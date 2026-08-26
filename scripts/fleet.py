#!/usr/bin/env python3
"""
proxy-fleet: Manage VPS proxy infrastructure.

Usage:
    python3 fleet.py init                              # Interactive setup
    python3 fleet.py status                            # Show all nodes
    python3 fleet.py deploy <host> [host...]           # Deploy to new machines
    python3 fleet.py deploy <host> --nat 10000-10009   # NAT machine with port range
    python3 fleet.py deploy <host> --name "Tokyo" --emoji "🇯🇵"
    python3 fleet.py remove <host>                     # Remove a node
    python3 fleet.py sync                              # Regenerate & upload subscription
"""

import base64
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import textwrap
import time
from getpass import getpass
from urllib.parse import quote, urlencode
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

SKILL_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = SKILL_DIR / "config.json"
EXAMPLE_CONFIG_PATH = SKILL_DIR / "config.example.json"
RULES_DIR = SKILL_DIR / "templates" / "rules"
SSH_STRICT_HOST_KEY_CHECKING = os.environ.get(
    "FLEET_STRICT_HOST_KEY_CHECKING", "accept-new"
)

# ── Helpers ──────────────────────────────────────────────────

def load_config():
    if not CONFIG_PATH.exists():
        print("Error: config.json not found. Run 'fleet.py init' first.")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)

def save_config(cfg):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{CONFIG_PATH.name}.", dir=str(CONFIG_PATH.parent)
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(temporary_name, CONFIG_PATH)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    print("  Config saved.")


def ssh_args(host, *remote_args):
    """Build SSH argv with host identity verification enabled by default."""
    return [
        "ssh",
        "-o", "ConnectTimeout=10",
        "-o", f"StrictHostKeyChecking={SSH_STRICT_HOST_KEY_CHECKING}",
        host,
        *remote_args,
    ]

def ssh(host, cmd, timeout=30, check=True):
    """Run a command on remote host via SSH."""
    r = subprocess.run(
        ssh_args(host, cmd),
        capture_output=True, text=True, timeout=timeout
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"[{host}] SSH failed: {r.stderr.strip()}")
    return r.stdout.strip()

def ssh_script(host, script_text, args="", timeout=60):
    """Pipe a Python script to the remote host via SSH stdin."""
    cmd = f"python3 - {args}" if args else "python3 -"
    r = subprocess.run(
        ssh_args(host, cmd),
        input=script_text, capture_output=True, text=True, timeout=timeout
    )
    if r.returncode != 0:
        raise RuntimeError(f"[{host}] Remote script failed: {r.stderr.strip()}")
    return r.stdout.strip()

def ssh_host_info(host):
    """Parse SSH config to get HostName for a host alias."""
    r = subprocess.run(["ssh", "-G", host], capture_output=True, text=True)
    info = {"hostname": host, "port": 22}
    for line in r.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            k, v = parts
            if k == "hostname":
                info["hostname"] = v
            elif k == "port":
                info["port"] = int(v)
    return info

def detect_xray_binary(host):
    """Detect the xray binary path on remote host (handles amd64/arm64)."""
    out = ssh(host, "ls /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -1", check=False)
    if out:
        return out.strip()
    # Fallback: check common names
    for name in ["xray-linux-amd64", "xray-linux-arm64", "xray"]:
        path = f"/usr/local/x-ui/bin/{name}"
        exists = ssh(host, f"test -f {path} && echo yes || echo no", check=False)
        if "yes" in exists:
            return path
    raise RuntimeError(f"[{host}] Cannot find xray binary in /usr/local/x-ui/bin/")

# ── Port Scanner ─────────────────────────────────────────────

def scan_ports(host):
    """Get set of TCP ports in use on remote host."""
    out = ssh(host, "ss -tlnp 2>/dev/null | awk 'NR>1{print $4}'", check=False)
    ports = set()
    for line in out.splitlines():
        m = re.search(r':(\d+)$', line)
        if m:
            ports.add(int(m.group(1)))
    return ports

def pick_port(used_ports, preferred_ports, nat_range=None):
    """Pick the best available port."""
    if nat_range:
        lo, hi = nat_range
        for p in range(lo, hi + 1):
            if p not in used_ports:
                return p
        raise RuntimeError(f"No available port in NAT range {lo}-{hi}")
    for p in preferred_ports:
        if p not in used_ports:
            return p
    raise RuntimeError(f"All preferred ports are in use: {preferred_ports}")

# ── Firewall ─────────────────────────────────────────────────

def configure_firewall(host, ports):
    """Detect firewall type and open ports."""
    has_ufw = "active" in ssh(host, "ufw status 2>/dev/null || echo inactive", check=False)
    if has_ufw:
        for p in ports:
            ssh(host, f"ufw allow {p}/tcp 2>/dev/null", check=False)
        ssh(host, "ufw reload 2>/dev/null", check=False)
        print(f"  [{host}] UFW: opened ports {ports}")
    else:
        policy = ssh(host, "iptables -L INPUT -n 2>/dev/null | head -1", check=False)
        if "DROP" in policy or "REJECT" in policy:
            for p in ports:
                ssh(host, f"iptables -A INPUT -p tcp --dport {p} -j ACCEPT 2>/dev/null", check=False)
            print(f"  [{host}] iptables: opened ports {ports}")
        else:
            print(f"  [{host}] No restrictive firewall detected, skipping")

# ── 3x-ui Install ───────────────────────────────────────────

def install_3xui(host, creds):
    """Install 3x-ui and set credentials."""
    installed = "x-ui" in ssh(host, "which x-ui 2>/dev/null || echo ''", check=False)
    if installed:
        print(f"  [{host}] 3x-ui already installed, skipping install")
    else:
        print(f"  [{host}] Installing 3x-ui (this may take 1-2 minutes)...")
        ssh(host,
            "echo 'y' | bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)",
            timeout=180, check=False)
        print(f"  [{host}] Install complete")

    # Always reset credentials to ensure consistency
    setting_command = shlex.join([
        "/usr/local/x-ui/x-ui", "setting",
        "-username", str(creds["username"]),
        "-password", str(creds["password"]),
        "-port", str(creds["panel_port"]),
        "-webBasePath", "/",
    ])
    ssh(host, setting_command)
    ssh(host, "systemctl restart x-ui")
    print(f"  [{host}] Credentials set (panel port {creds['panel_port']})")

# ── VLESS+Reality Inbound ────────────────────────────────────

REMOTE_INBOUND_SCRIPT = textwrap.dedent(r'''
import json, subprocess, sys, urllib.request, urllib.parse, http.cookiejar, secrets, glob, ssl

port = int(sys.argv[1])
remark = sys.argv[2]
panel_port = int(sys.argv[3])
username = sys.argv[4]
password = sys.argv[5]
sni = sys.argv[6]

# Auto-detect xray binary (amd64 or arm64)
candidates = glob.glob("/usr/local/x-ui/bin/xray-linux-*")
XRAY = candidates[0] if candidates else "/usr/local/x-ui/bin/xray-linux-amd64"

# Generate x25519 keys
# Xray v26+: "PrivateKey: ... / Password: ... / Hash32: ..."
# Xray older: "Private key: ... / Public key: ..."
keys_out = subprocess.check_output([XRAY, "x25519"]).decode()
kv = {}
for l in keys_out.strip().splitlines():
    if ": " in l:
        k, v = l.split(": ", 1)
        kv[k.strip()] = v.strip()

priv = kv.get("PrivateKey") or kv.get("Private key", "")
pub = (kv.get("Password") or kv.get("Password (PublicKey)")
       or kv.get("Public key", ""))

if not priv or not pub:
    print(json.dumps({"success": False, "error": "Failed to parse x25519 output"}))
    sys.exit(0)

uuid = subprocess.check_output([XRAY, "uuid"]).decode().strip()
sid = secrets.token_hex(4)

# Login — support legacy form login and CSRF-protected 3x-ui 3.x panels.
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
panel = None
opener = None
for proto in ["https", "http"]:
    cj = http.cookiejar.CookieJar()
    if proto == "https":
        candidate = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            urllib.request.HTTPSHandler(context=ctx),
        )
    else:
        candidate = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    base = f"{proto}://localhost:{panel_port}"
    try:
        token = ""
        try:
            csrf_resp = candidate.open(f"{base}/csrf-token", timeout=5)
            token = json.loads(csrf_resp.read()).get("obj", "")
        except Exception:
            pass
        payload = json.dumps({"username": username, "password": password}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["X-CSRF-Token"] = token
        login_req = urllib.request.Request(f"{base}/login", payload, headers)
        candidate.open(login_req, timeout=5)
        panel, opener = base, candidate
        break
    except Exception:
        try:
            legacy = urllib.parse.urlencode(
                {"username": username, "password": password}
            ).encode()
            candidate.open(f"{base}/login", legacy, timeout=5)
            panel, opener = base, candidate
            break
        except Exception:
            continue

if not panel or not opener:
    raise RuntimeError("Unable to log in to 3x-ui panel")

# Replace only the same managed inbound; never delete unrelated VLESS inbounds.
req = urllib.request.Request(f"{panel}/panel/api/inbounds/list")
resp = opener.open(req)
existing = json.loads(resp.read())
for ib in existing.get("obj", []):
    if ib.get("protocol") != "vless":
        continue
    if str(ib.get("port")) == str(port) and ib.get("remark") != remark:
        print(json.dumps({"success": False, "error": f"VLESS port {port} is already in use"}))
        sys.exit(0)
    if ib.get("remark") == remark:
        delete_headers = {}
        if token:
            delete_headers["X-CSRF-Token"] = token
        dreq = urllib.request.Request(
            f"{panel}/panel/api/inbounds/del/{ib['id']}",
            headers=delete_headers,
        )
        opener.open(dreq)

settings = json.dumps({
    "clients": [{"id": uuid, "flow": "xtls-rprx-vision", "email": f"vless-{port}",
                 "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": True,
                 "tgId": 0, "subId": "", "reset": 0}],
    "decryption": "none", "fallbacks": []
})
stream = json.dumps({
    "network": "tcp", "security": "reality", "externalProxy": [],
    "realitySettings": {
        "show": False, "xver": 0, "dest": f"{sni}:443",
        "serverNames": [sni], "privateKey": priv,
        "minClient": "", "maxClient": "", "maxTimediff": 0, "shortIds": [sid],
        "settings": {"publicKey": pub, "fingerprint": "chrome", "serverName": "", "spiderX": "/"}
    },
    "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}
})
sniffing = json.dumps({"enabled": True, "destOverride": ["http", "tls", "quic", "fakedns"],
                        "metadataOnly": False, "routeOnly": False})

body = json.dumps({
    "up": 0, "down": 0, "total": 0, "remark": remark, "enable": True, "expiryTime": 0,
    "listen": "", "port": port, "protocol": "vless",
    "settings": settings, "streamSettings": stream, "sniffing": sniffing
}).encode()

mutation_headers = {"Content-Type": "application/json"}
if token:
    mutation_headers["X-CSRF-Token"] = token
req = urllib.request.Request(f"{panel}/panel/api/inbounds/add", body, mutation_headers)
resp = opener.open(req)
result = json.loads(resp.read())

print(json.dumps({
    "success": result.get("success", False),
    "uuid": uuid, "public_key": pub, "short_id": sid, "port": port
}))
''')

def create_inbound(host, port, remark, cfg):
    """Create VLESS+Reality inbound on remote host. Returns node info dict."""
    creds = cfg["credentials"]
    defaults = cfg["defaults"]
    args = build_inbound_args(
        port=port,
        remark=remark,
        panel_port=creds["panel_port"],
        username=creds["username"],
        password=creds["password"],
        sni=defaults["sni"],
    )
    out = ssh_script(host, REMOTE_INBOUND_SCRIPT, args, timeout=30)
    result = json.loads(out)
    if not result.get("success"):
        raise RuntimeError(
            f"[{host}] Failed to create inbound: "
            f"{result.get('error') or result.get('msg') or 'unknown'}"
        )
    print(f"  [{host}] VLESS+Reality on port {port} — UUID: {result['uuid'][:8]}...")
    return result


def build_inbound_args(port, remark, panel_port, username, password, sni):
    """Build shell-safe argv for the remote inbound creation script."""
    return shlex.join([
        str(port),
        str(remark),
        str(panel_port),
        str(username),
        str(password),
        str(sni),
    ])

# ── Remote Query ─────────────────────────────────────────────

REMOTE_QUERY_SCRIPT = textwrap.dedent(r'''
import json, urllib.request, urllib.parse, http.cookiejar, subprocess, sys, glob, ssl

panel_port = int(sys.argv[1])
username = sys.argv[2]
password = sys.argv[3]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Detect protocol and support both legacy and CSRF-protected 3x-ui login flows.
panel = None
opener = None
for proto in ["https", "http"]:
    cj = http.cookiejar.CookieJar()
    if proto == "https":
        candidate = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            urllib.request.HTTPSHandler(context=ctx),
        )
    else:
        candidate = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    base = f"{proto}://localhost:{panel_port}"
    try:
        token = ""
        try:
            csrf_resp = candidate.open(f"{base}/csrf-token", timeout=5)
            token = json.loads(csrf_resp.read()).get("obj", "")
        except Exception:
            pass
        payload = json.dumps({"username": username, "password": password}).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            headers["X-CSRF-Token"] = token
        candidate.open(urllib.request.Request(f"{base}/login", payload, headers), timeout=5)
        panel, opener = base, candidate
        break
    except Exception:
        try:
            legacy = urllib.parse.urlencode(
                {"username": username, "password": password}
            ).encode()
            candidate.open(f"{base}/login", legacy, timeout=5)
            panel, opener = base, candidate
            break
        except Exception:
            continue

if not panel:
    print(json.dumps({"inbounds": []}))
    sys.exit(0)

inbounds = []
xver = "?"

def json_object(value):
    """Normalize legacy JSON strings and newer 3x-ui object fields."""
    if isinstance(value, str):
        return json.loads(value or "{}")
    return value or {}

try:
    resp = opener.open(f"{panel}/panel/api/inbounds/list")
    data = json.loads(resp.read())

    for ib in data.get("obj", []):
        stream = json_object(ib.get("streamSettings", {}))
        settings = json_object(ib.get("settings", {}))
        reality = stream.get("realitySettings", {})
        clients = settings.get("clients", [])
        inbounds.append({
            "id": ib["id"], "protocol": ib["protocol"], "port": ib["port"],
            "remark": ib.get("remark", ""), "enable": ib.get("enable", False),
            "up": ib.get("up", 0), "down": ib.get("down", 0),
            "uuid": clients[0]["id"] if clients else "",
            "public_key": reality.get("settings", {}).get("publicKey", ""),
            "private_key": reality.get("privateKey", ""),
            "short_id": (reality.get("shortIds", [""]))[0] if reality.get("shortIds") else "",
            "sni": (reality.get("serverNames", [""]))[0] if reality.get("serverNames") else "",
        })

    # Detect xray binary and version (native install + Docker)
    xray_bin = None
    for candidate in glob.glob("/usr/local/x-ui/bin/xray-linux-*"):
        xray_bin = candidate
        break
    if not xray_bin:
        # Try Docker 3x-ui container
        try:
            r = subprocess.run(["docker", "exec", "3x-ui", "which", "xray"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                xray_bin = f"docker exec 3x-ui {r.stdout.strip()}"
        except Exception:
            pass
    if xray_bin and "docker exec" not in str(xray_bin):
        xver = subprocess.check_output(
            [xray_bin, "version"], stderr=subprocess.STDOUT
        ).decode().split()[1]
        # Derive public key from private key if missing (Docker 3x-ui)
        for ib in inbounds:
            if not ib["public_key"] and ib["private_key"]:
                try:
                    out = subprocess.check_output(
                        [xray_bin, "x25519", "-i", ib["private_key"]],
                        stderr=subprocess.STDOUT
                    ).decode()
                    for line in out.splitlines():
                        if "PublicKey" in line:
                            ib["public_key"] = line.split(":", 1)[1].strip()
                            break
                except Exception:
                    pass
except Exception as e:
    pass

for ib in inbounds:
    ib.pop("private_key", None)

print(json.dumps({"inbounds": inbounds, "xray_version": xver}))
''')

def query_node(host, cfg):
    """Query a node's 3x-ui API with legacy/CSRF login compatibility."""
    creds = cfg["credentials"]
    panel_port = creds["panel_port"]
    # Check for per-node panel_port override (e.g. Docker install)
    for n in cfg.get("nodes", []):
        if n["ssh_host"] == host and "panel_port" in n:
            panel_port = n["panel_port"]
            break

    args = shlex.join([
        str(panel_port),
        str(creds["username"]),
        str(creds["password"]),
    ])
    try:
        out = ssh_script(host, REMOTE_QUERY_SCRIPT, args, timeout=30)
        data = json.loads(out)
        return data if isinstance(data, dict) else {"inbounds": []}
    except json.JSONDecodeError:
        return {"error": "invalid JSON response", "inbounds": []}
    except Exception as e:
        return {"error": str(e), "inbounds": []}


def format_query_result(host, node_details):
    """Render query failures explicitly instead of treating them as empty nodes."""
    if node_details.get("error"):
        return f"  [{host}] ❌ Query failed: {node_details['error']}"
    return f"  [{host}] {len(node_details.get('inbounds', []))} inbound(s)"


def _derive_public_key(host, private_key):
    """Derive X25519 public key from private key using remote xray."""
    # Try native xray first
    try:
        out = ssh(host,
            f'for b in /usr/local/x-ui/bin/xray-linux-*; do '
            f'  [ -f "$b" ] && out=$("$b" x25519 -i "{private_key}" 2>/dev/null) && '
            f'  echo "$out" && break; '
            f'done',
            timeout=10, check=False)
        if out:
            for line in out.splitlines():
                if "PublicKey" in line:
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    # Try Docker 3x-ui
    try:
        out = ssh(host,
            f'docker exec 3x-ui sh -c \'xray x25519 -i "{private_key}"\' 2>/dev/null || '
            f'docker exec 3x-ui sh -c \'for b in /usr/local/x-ui/bin/xray-linux-*; do [ -f "$b" ] && "$b" x25519 -i "{private_key}"; break; done\' 2>/dev/null',
            timeout=10, check=False)
        if out:
            for line in out.splitlines():
                if "PublicKey" in line:
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""

# ── Verify ───────────────────────────────────────────────────

def verify_port(server, port, timeout=5):
    """Check if a port is reachable from local machine."""
    r = subprocess.run(
        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
         "--connect-timeout", str(timeout), f"https://{server}:{port}"],
        capture_output=True, text=True
    )
    # Reality returns 400 to non-VLESS clients — that means it's alive
    return r.stdout.strip() in ("400", "200")

# ── Subscription Generator ───────────────────────────────────

def load_rules():
    """Load inline rules and compose the whitelist-mode provider chain."""

    def load_inline(name):
        lines = []
        path = RULES_DIR / f"{name}.yaml"
        if path.exists():
            for line in path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
        return lines

    rules = load_inline("ai")
    rules.extend([
        "- RULE-SET,applications,DIRECT",
        "- RULE-SET,reject,REJECT",
    ])
    rules.extend(load_inline("direct"))
    rules.extend([
        "- RULE-SET,telegramcidr,🚀 Proxy,no-resolve",
        "- RULE-SET,private,DIRECT",
        "- RULE-SET,apple,DIRECT",
        "- RULE-SET,icloud,DIRECT",
        "- RULE-SET,direct,DIRECT",
        "- RULE-SET,cncidr,DIRECT,no-resolve",
        "- RULE-SET,lancidr,DIRECT,no-resolve",
        "- GEOIP,CN,DIRECT",
    ])
    rules.append("- MATCH,🐟 Final")
    return rules

def generate_subscription(cfg, node_details):
    """Generate complete mihomo YAML config."""
    nodes = cfg["nodes"]
    defaults = cfg["defaults"]
    dns_cfg = defaults.get("dns", {})

    # DNS servers (configurable, with sensible defaults)
    domestic_ns = dns_cfg.get("domestic", ["223.5.5.5", "119.29.29.29"])
    domestic_doh = dns_cfg.get("domestic_doh", ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"])
    foreign_dns = dns_cfg.get("foreign", ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"])

    # Build proxy list
    proxies = []
    proxy_names = []
    us_names = []

    for node in nodes:
        nd = node_details.get(node["ssh_host"], {})
        inbounds = nd.get("inbounds", [])
        vless_ib = next((ib for ib in inbounds if ib["protocol"] == "vless"), None)
        if not vless_ib:
            continue

        full_name = f"{node['emoji']} {node['name']}"
        proxy_names.append(full_name)
        if "🇺🇸" in node.get("emoji", ""):
            us_names.append(full_name)

        proxies.append({
            "name": full_name,
            "type": "vless",
            "server": node["server"],
            "port": node["port"],
            "uuid": vless_ib["uuid"],
            "network": "tcp",
            "tls": True,
            "udp": True,
            "flow": "xtls-rprx-vision",
            "servername": vless_ib.get("sni") or defaults["sni"],
            "reality-opts": {
                "public-key": vless_ib["public_key"],
                "short-id": vless_ib["short_id"],
            },
            "client-fingerprint": defaults["fingerprint"],
        })

    if not proxies:
        print("  Warning: no active VLESS inbounds found on any node")
        return ""

    # AI group: US nodes first, then others
    ai_order = us_names + [n for n in proxy_names if n not in us_names]
    # Proxy group: HK/JP first for lower latency
    proxy_order = [n for n in proxy_names if "🇭🇰" in n or "🇯🇵" in n] + \
                  [n for n in proxy_names if "🇭🇰" not in n and "🇯🇵" not in n]

    rules = load_rules()

    lines = [
        "############################################",
        "# Mihomo (Clash Meta) Subscription Config",
        f"# Nodes: {len(proxies)} | Generated by proxy-fleet",
        "############################################",
        "",
        "mixed-port: 7890",
        "allow-lan: false",
        "mode: rule",
        "log-level: info",
        "unified-delay: true",
        "find-process-mode: strict",
        "global-client-fingerprint: chrome",
        "",
        "dns:",
        "  enable: true",
        "  listen: :1053",
        "  ipv6: false",
        "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16",
        "  fake-ip-filter:",
        '    - "*.lan"',
        '    - "*.local"',
        '    - "*.localhost"',
        '    - "+.msftconnecttest.com"',
        '    - "+.msftncsi.com"',
        "  default-nameserver:",
    ]
    for ns in domestic_ns:
        lines.append(f"    - {ns}")
    lines.append("  nameserver:")
    for ns in domestic_doh:
        lines.append(f"    - {ns}")
    lines.append("  fallback:")
    for ns in foreign_dns:
        lines.append(f"    - {ns}")
    lines += [
        "  fallback-filter:",
        "    geoip: true",
        "    geoip-code: CN",
        "",
        "proxies:",
    ]

    for p in proxies:
        lines.append(f'  - name: "{p["name"]}"')
        lines.append(f'    type: {p["type"]}')
        lines.append(f'    server: {p["server"]}')
        lines.append(f'    port: {p["port"]}')
        lines.append(f'    uuid: {p["uuid"]}')
        lines.append(f'    network: {p["network"]}')
        lines.append(f'    tls: {str(p["tls"]).lower()}')
        lines.append(f'    udp: {str(p["udp"]).lower()}')
        lines.append(f'    flow: {p["flow"]}')
        lines.append(f'    servername: {p["servername"]}')
        lines.append("    reality-opts:")
        lines.append(f'      public-key: {p["reality-opts"]["public-key"]}')
        lines.append(f'      short-id: {p["reality-opts"]["short-id"]}')
        lines.append(f'    client-fingerprint: {p["client-fingerprint"]}')
        lines.append("")

    lines.append("proxy-groups:")
    lines.append('  - name: "🤖 AI Services"')
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in ai_order:
        lines.append(f'      - "{n}"')
    lines.append("")

    lines.append('  - name: "🚀 Proxy"')
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in proxy_order:
        lines.append(f'      - "{n}"')
    lines.append("      - DIRECT")
    lines.append("")

    lines.append('  - name: "🐟 Final"')
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append('      - "🚀 Proxy"')
    lines.append("      - DIRECT")
    lines.append("")

    lines.append("rule-providers:")
    providers = [
        ("reject", "domain", "reject.txt"),
        ("private", "domain", "private.txt"),
        ("apple", "domain", "apple.txt"),
        ("icloud", "domain", "icloud.txt"),
        ("direct", "domain", "direct.txt"),
        ("applications", "classical", "applications.txt"),
        ("cncidr", "ipcidr", "cncidr.txt"),
        ("lancidr", "ipcidr", "lancidr.txt"),
        ("telegramcidr", "ipcidr", "telegramcidr.txt"),
    ]
    provider_base = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release"
    for name, behavior, filename in providers:
        lines.append(f"  {name}:")
        lines.append("    type: http")
        lines.append(f"    behavior: {behavior}")
        lines.append(f'    url: "{provider_base}/{filename}"')
        lines.append(f"    path: ./ruleset/{name}.yaml")
        lines.append("    interval: 86400")
    lines.append("")

    lines.append("rules:")
    for r in rules:
        lines.append(f"  {r}")

    return "\n".join(lines) + "\n"


def generate_vless_subscription(cfg, node_details):
    """Generate the base64 VLESS URI list used by Loon/V2rayN clients."""
    defaults = cfg["defaults"]
    lines = []
    for node in cfg["nodes"]:
        nd = node_details.get(node["ssh_host"], {})
        vless_ib = next(
            (ib for ib in nd.get("inbounds", []) if ib["protocol"] == "vless"),
            None,
        )
        if not vless_ib:
            continue
        name = f"{node['emoji']} {node['name']}"
        params = urlencode({
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "security": "reality",
            "sni": vless_ib.get("sni") or defaults["sni"],
            "fp": defaults["fingerprint"],
            "pbk": vless_ib["public_key"],
            "sid": vless_ib["short_id"],
            "type": "tcp",
        })
        lines.append(
            f"vless://{vless_ib['uuid']}@{node['server']}:{node['port']}"
            f"?{params}#{quote(name)}"
        )
    return base64.b64encode("\n".join(lines).encode()).decode()


def subscription_url(cfg, filename):
    """Return the token-protected public URL for a subscription file."""
    sub = cfg["subscription"]
    return f"https://{sub['domain']}{sub['url_path'].rstrip('/')}/{filename}"


def upload_subscription_file(sub, filename, content):
    """Upload one subscription artifact without exposing its content in logs."""
    remote_path = f"{sub['file_path'].rstrip('/')}/{filename}"
    command = f"mkdir -p {shlex.quote(sub['file_path'])} && cat > {shlex.quote(remote_path)}"
    return subprocess.run(
        ssh_args(sub["ssh_host"], command),
        input=content,
        capture_output=True,
        text=True,
        timeout=30,
    )

# ── Commands ─────────────────────────────────────────────────

def cmd_init():
    """Interactive setup to create config.json."""
    if CONFIG_PATH.exists():
        ans = input("config.json already exists. Overwrite? [y/N] ").strip().lower()
        if ans != "y":
            print("Aborted.")
            return

    print("\n=== proxy-fleet init ===\n")

    # Credentials
    username = input("Panel username [admin]: ").strip() or "admin"
    password = getpass("Panel password (leave empty to auto-generate): ").strip()
    if not password:
        password = secrets.token_urlsafe(16)
        print(f"  Generated password: {password}")
    panel_port = input("Panel port [9453]: ").strip() or "9453"

    # Subscription hosting
    print("\n--- Subscription hosting ---")
    sub_host = input("SSH host for subscription hosting: ").strip()
    domain = input("Subscription domain (e.g. sub.example.com): ").strip()
    url_path = secrets.token_hex(8)
    print(f"  Generated URL path: {url_path}")
    file_path = f"/var/www/sub/{url_path}"

    # DNS
    print("\n--- DNS config ---")
    dns_preset = input("DNS preset - [1] China, [2] Global [1]: ").strip() or "1"
    if dns_preset == "2":
        dns_cfg = {
            "domestic": ["8.8.8.8", "1.1.1.1"],
            "domestic_doh": ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"],
            "foreign": ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"]
        }
    else:
        dns_cfg = {
            "domestic": ["223.5.5.5", "119.29.29.29"],
            "domestic_doh": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
            "foreign": ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"]
        }

    cfg = {
        "credentials": {
            "username": username,
            "password": password,
            "panel_port": int(panel_port)
        },
        "subscription": {
            "ssh_host": sub_host,
            "domain": domain,
            "file_path": file_path,
            "url_path": url_path,
            "cert_path": "/etc/nginx/ssl/cert.crt",
            "key_path": "/etc/nginx/ssl/cert.key"
        },
        "defaults": {
            "protocol": "vless",
            "security": "reality",
            "sni": "www.microsoft.com",
            "fingerprint": "chrome",
            "preferred_ports": [443, 2083, 8443, 2053, 2087, 2096],
            "dns": dns_cfg
        },
        "nodes": []
    }

    save_config(cfg)
    print("\n✅ Config created. Next steps:")
    print("  1. Deploy nodes:  python3 scripts/fleet.py deploy <ssh-host>")
    print(f"  2. Set up nginx on {sub_host} with your SSL cert")
    print(f"  3. Point DNS: {domain} → your hosting server IP")

def cmd_status():
    cfg = load_config()
    nodes = cfg["nodes"]

    if not nodes:
        print("\nNo nodes configured. Run 'fleet.py deploy <host>' to add one.")
        return

    print(f"\n{'Node':<20} {'Server':<20} {'Port':>6}  {'Status':<16} {'Traffic':>12}")
    print("─" * 78)

    def check(node):
        host = node["ssh_host"]
        try:
            nd = query_node(host, cfg)
            vless = next((ib for ib in nd.get("inbounds", []) if ib["protocol"] == "vless"), None)
            reachable = verify_port(node["server"], node["port"])
            up = vless.get("up", 0) if vless else 0
            down = vless.get("down", 0) if vless else 0
            traffic = f"↑{up // 1048576}M ↓{down // 1048576}M"
            status = "✅ OK" if reachable else "⚠️  Unreachable"
            return node, status, traffic
        except Exception as e:
            return node, f"❌ {str(e)[:20]}", "—"

    with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        futures = [pool.submit(check, n) for n in nodes]
        for f in as_completed(futures):
            node, status, traffic = f.result()
            name = f"{node['emoji']} {node['name']}"
            print(f"{name:<20} {node['server']:<20} {node['port']:>6}  {status:<16} {traffic:>12}")

    sub = cfg["subscription"]
    print(f"\n📋 Clash/Mihomo: {subscription_url(cfg, 'config.yaml')}")
    print(f"   Loon/V2rayN: {subscription_url(cfg, 'vless.txt')}")
    print(f"   Hosted on: {sub['ssh_host']} ({sub['file_path']})\n")

def cmd_deploy(hosts, nat_range=None, name_override=None, emoji_override=None):
    cfg = load_config()
    creds = cfg["credentials"]
    defaults = cfg["defaults"]

    for host in hosts:
        print(f"\n{'='*50}")
        print(f"Deploying to: {host}")
        print(f"{'='*50}")

        # 1. Check connectivity
        try:
            arch = ssh(host, "uname -m", timeout=10)
            print(f"  [{host}] Connected ({arch})")
        except Exception as e:
            print(f"  [{host}] ❌ Cannot connect: {e}")
            continue

        # 2. Scan ports
        used = scan_ports(host)
        print(f"  [{host}] Ports in use: {sorted(used)[:15]}{'...' if len(used) > 15 else ''}")

        # 3. Pick port
        try:
            port = pick_port(used, defaults["preferred_ports"], nat_range)
        except RuntimeError as e:
            print(f"  [{host}] ❌ {e}")
            continue
        print(f"  [{host}] Selected port: {port}")

        # 4. Install 3x-ui
        install_3xui(host, creds)

        # 5. Wait for x-ui to start
        time.sleep(2)

        # 6. Create inbound
        host_info = ssh_host_info(host)
        server = host_info["hostname"]
        remark = name_override or host.replace(".", "-").replace(" ", "-")
        try:
            create_inbound(host, port, remark, cfg)
        except Exception as e:
            print(f"  [{host}] ❌ Inbound creation failed: {e}")
            continue

        # 7. Firewall
        configure_firewall(host, [port, creds["panel_port"]])

        # 8. Verify
        reachable = verify_port(server, port)
        print(f"  [{host}] Connectivity: {'✅ OK' if reachable else '⚠️  Not reachable (may need time or external firewall)'}")

        # 9. Add to config
        emoji = emoji_override or "🌐"
        already = any(n["ssh_host"] == host for n in cfg["nodes"])
        if not already:
            cfg["nodes"].append({
                "name": remark,
                "emoji": emoji,
                "ssh_host": host,
                "server": server,
                "port": port,
                "nat_ports": list(nat_range) if nat_range else None,
            })
            save_config(cfg)
            print(f"  [{host}] Added to fleet config")
        else:
            for n in cfg["nodes"]:
                if n["ssh_host"] == host:
                    n["port"] = port
                    if name_override:
                        n["name"] = name_override
                    if emoji_override:
                        n["emoji"] = emoji_override
            save_config(cfg)
            print(f"  [{host}] Updated in fleet config")

    # 10. Sync subscription
    print(f"\n{'='*50}")
    print("Syncing subscription...")
    cmd_sync()

def cmd_remove(host):
    cfg = load_config()
    found = any(n["ssh_host"] == host for n in cfg["nodes"])
    if not found:
        print(f"Node '{host}' not found in config.")
        return

    cfg["nodes"] = [n for n in cfg["nodes"] if n["ssh_host"] != host]
    save_config(cfg)
    print(f"Removed {host} from fleet config")
    print(f"Note: 3x-ui is still installed on {host}. To uninstall:")
    print(f"  ssh {host} 'x-ui uninstall'")

    cmd_sync()

def cmd_sync():
    cfg = load_config()
    nodes = cfg["nodes"]

    if not nodes:
        print("No nodes to sync.")
        return

    print("Querying all nodes (sequential, with delays to avoid rate limiting)...")
    node_details = {}
    failures = []
    for i, node in enumerate(nodes):
        host = node["ssh_host"]
        if i > 0:
            time.sleep(20)  # Oracle Cloud SSHD rate limiting avoidance
        try:
            nd = query_node(host, cfg)
            if not isinstance(nd, dict):
                nd = {"error": "unexpected response", "inbounds": []}
            node_details[host] = nd
            print(format_query_result(host, nd))
            if nd.get("error"):
                failures.append(host)
        except Exception as e:
            print(f"  [{host}] ❌ Query failed: {e}")
            failures.append(host)

    if failures:
        print(
            "❌ Subscription sync aborted; existing production artifacts were kept. "
            f"Failed nodes: {', '.join(failures)}"
        )
        return False

    yaml_content = generate_subscription(cfg, node_details)
    vless_content = generate_vless_subscription(cfg, node_details)
    if not yaml_content:
        print("❌ No subscription content generated.")
        return False

    proxy_count = yaml_content.count("type: vless")
    print(f"\nGenerated subscription with {proxy_count} nodes")

    # Upload
    sub = cfg["subscription"]
    yaml_result = upload_subscription_file(sub, "config.yaml", yaml_content)
    if yaml_result.returncode != 0:
        print(f"❌ config.yaml upload failed: {yaml_result.stderr}")
        return False
    vless_result = upload_subscription_file(sub, "vless.txt", vless_content)
    if vless_result.returncode != 0:
        print(f"❌ vless.txt upload failed: {vless_result.stderr}")
        return False
    print(f"✅ Uploaded config.yaml and vless.txt to {sub['ssh_host']}:{sub['file_path']}")
    print(f"📋 Clash/Mihomo: {subscription_url(cfg, 'config.yaml')}")
    print(f"   Loon/V2rayN: {subscription_url(cfg, 'vless.txt')}")
    return True

# ── Main ─────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "init":
        cmd_init()
    elif cmd == "status":
        cmd_status()
    elif cmd == "deploy":
        if len(sys.argv) < 3:
            print("Usage: fleet.py deploy <host> [host...] [--nat START-END] [--name NAME] [--emoji EMOJI]")
            sys.exit(1)
        hosts = []
        nat_range = None
        name_override = None
        emoji_override = None
        i = 2
        while i < len(sys.argv):
            if sys.argv[i] == "--nat" and i + 1 < len(sys.argv):
                lo, hi = sys.argv[i + 1].split("-")
                nat_range = (int(lo), int(hi))
                i += 2
            elif sys.argv[i] == "--name" and i + 1 < len(sys.argv):
                name_override = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == "--emoji" and i + 1 < len(sys.argv):
                emoji_override = sys.argv[i + 1]
                i += 2
            else:
                hosts.append(sys.argv[i])
                i += 1
        cmd_deploy(hosts, nat_range, name_override, emoji_override)
    elif cmd == "remove":
        if len(sys.argv) < 3:
            print("Usage: fleet.py remove <host>")
            sys.exit(1)
        cmd_remove(sys.argv[2])
    elif cmd == "sync":
        cmd_sync()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)

if __name__ == "__main__":
    main()

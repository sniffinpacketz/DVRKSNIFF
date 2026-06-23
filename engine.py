# DVRKSNIFF Engine — Packet capture core
# Credited to @botnet1337 on IG

import threading
import time
import random
import socket
import subprocess
import ipaddress
import re
from datetime import datetime
from collections import deque

try:
    import pydivert
    WINDIVERT_AVAILABLE = True
except Exception:
    WINDIVERT_AVAILABLE = False


# ── Network Adapter Enumeration ────────────────────────────────────────────────

def get_adapters():
    """
    Returns list of dicts: {name, ip, friendly_name}
    Uses multiple methods to get REAL Windows adapters with proper names.
    Filters out loopback, tunnel, VPN virtual, and inactive adapters.
    """
    adapters  = []
    seen_ips  = set()

    # ── Method 1: wmic (most reliable on Windows for real names) ──────────────
    try:
        result = subprocess.run(
            ["wmic", "nic", "where", "NetEnabled=True",
             "get", "Name,NetConnectionID,MACAddress", "/format:csv"],
            capture_output=True, text=True, timeout=6, creationflags=0x08000000
        )
        # Build map of adapter name → friendly connection ID
        nic_map = {}
        for line in result.stdout.splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 4 and parts[1]:
                nic_map[parts[1]] = parts[2] if parts[2] else parts[1]
    except Exception:
        nic_map = {}

    # ── Method 2: ipconfig /all — gets IPs + adapter names ───────────────────
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True, text=True, timeout=6, creationflags=0x08000000
        )
        lines          = result.stdout.splitlines()
        current_name   = ""
        current_type   = ""
        current_mac    = ""
        current_ips    = []
        connected      = True

        def flush_adapter():
            nonlocal current_name, current_type, current_mac, current_ips, connected
            if current_ips and connected and current_name:
                # Skip loopback, Teredo, isatap, tunnel adapters
                skip_patterns = ["loopback","teredo","isatap","6to4","tunnel",
                                 "bluetooth","vmware","virtualbox","hyper-v",
                                 "pseudo","npcap","miniport"]
                name_lower = current_name.lower()
                if any(p in name_lower for p in skip_patterns):
                    return
                for ip in current_ips:
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        friendly = f"{current_name} — {ip}"
                        adapters.append({
                            "ip":            ip,
                            "name":          current_name,
                            "friendly_name": friendly,
                            "mac":           current_mac,
                        })
            current_ips = []
            connected   = True

        for line in lines:
            stripped = line.strip()

            # New adapter block starts with non-indented line ending with ":"
            if line and not line.startswith(" ") and line.rstrip().endswith(":"):
                flush_adapter()
                # Strip "adapter " prefix and colon
                raw = line.strip().rstrip(":")
                raw = re.sub(r'^(Ethernet adapter|Wireless LAN adapter|'
                             r'Unknown adapter|PPP adapter)\s*', '', raw, flags=re.I)
                current_name = raw.strip()
                current_mac  = ""
                current_type = ""
                continue

            # Detect disconnected adapters
            if "Media disconnected" in stripped or "Media State" in stripped and "Disconnected" in stripped:
                connected = False

            # MAC address
            if re.search(r"Physical Address", stripped, re.I):
                m = re.search(r"([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}"
                              r"[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})", stripped)
                if m:
                    current_mac = m.group(1)

            # IPv4 address
            if re.search(r"IPv4 Address|IP Address", stripped, re.I):
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", stripped)
                if m:
                    ip = m.group(1).strip()
                    if not ip.startswith("127.") and ip not in ("0.0.0.0",):
                        current_ips.append(ip)

        flush_adapter()

    except Exception:
        pass

    # ── Method 3: socket fallback if nothing found ─────────────────────────
    if not adapters:
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ":" in ip or ip.startswith("127.") or ip in seen_ips:
                    continue
                seen_ips.add(ip)
                adapters.append({"ip": ip, "name": ip,
                                 "friendly_name": f"Network — {ip}", "mac": ""})
        except Exception:
            pass

    # ── Fallback: capture all ──────────────────────────────────────────────
    if not adapters:
        adapters.append({
            "ip": "0.0.0.0", "name": "all",
            "friendly_name": "All Interfaces", "mac": ""
        })

    return adapters


def get_local_ips():
    """Return set of all local IPs to filter out of peer display."""
    ips = {"127.0.0.1", "0.0.0.0", "::1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass
    for a in get_adapters():
        ips.add(a["ip"])
    return ips


# ── Noise IP filter ────────────────────────────────────────────────────────────

# CDN / infrastructure ranges to skip from peer table (they're not real peers)
_NOISE_PREFIXES = (
    "224.", "239.", "255.", "169.254.",   # multicast, APIPA, broadcast
    "100.64.", "192.0.0.", "192.0.2.",    # shared/doc ranges
    "198.51.", "203.0.",                  # doc ranges
)

_NOISE_EXACT = {
    "8.8.8.8", "8.8.4.4",               # Google DNS
    "1.1.1.1", "1.0.0.1",               # Cloudflare DNS
    "9.9.9.9",                           # Quad9 DNS
    "208.67.222.222", "208.67.220.220",  # OpenDNS
}

def _is_noise_ip(ip: str) -> bool:
    """Returns True for IPs that should be filtered from the peer table."""
    if ip in _NOISE_EXACT:
        return True
    for prefix in _NOISE_PREFIXES:
        if ip.startswith(prefix):
            return True
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a.is_multicast or a.is_unspecified or a.is_link_local
    except Exception:
        return True


# ── Sniffer Engine ─────────────────────────────────────────────────────────────

class SnifferEngine:
    """
    Core packet capture engine — optimised for low overhead.
    Real mode  : WinDivert intercepts packets kernel-level.
    Simulation : Synthetic events for demo / non-Windows.
    """

    # How many packets to buffer before emitting to UI — reduces GUI callbacks
    _BATCH_SIZE = 8

    def __init__(self, on_packet=None, on_status=None):
        self.on_packet   = on_packet
        self.on_status   = on_status
        self._thread     = None
        self._running    = False
        self._filter     = "true"
        self._adapter_ip = None
        self.simulation  = not WINDIVERT_AVAILABLE
        self._local_ips  = get_local_ips()
        self._peer_ips   = set()
        self._seen_ips   = set()
        self._batch_buf  = deque()
        self._batch_lock = threading.Lock()

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, windivert_filter="true", adapter_ip=None):
        if self._running:
            return
        self._filter     = windivert_filter or "true"
        self._adapter_ip = adapter_ip
        self._running    = True
        self._local_ips  = get_local_ips()  # refresh
        self._peer_ips.clear()
        self._seen_ips.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def is_running(self):
        return self._running

    def get_peers(self):
        return set(self._peer_ips)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _run(self):
        mode = "SIMULATION" if self.simulation else "LIVE"
        self._emit_status(f"● STARTING [{mode}]")
        if self.simulation:
            self._emit_status("⚠  SIMULATION MODE — WinDivert not available on this OS")
            self._run_simulation()
        else:
            label = f" on {self._adapter_ip}" if self._adapter_ip else ""
            self._emit_status(f"● LIVE CAPTURE{label} — WinDivert active")
            self._run_live()

    def _build_live_filter(self):
        base = self._filter or "true"
        if self._adapter_ip and self._adapter_ip not in ("0.0.0.0", "all", ""):
            ip_clause = (f"(ip.SrcAddr == {self._adapter_ip} or "
                         f"ip.DstAddr == {self._adapter_ip})")
            return ip_clause if base == "true" else f"({base}) and {ip_clause}"
        return base

    def _run_live(self):
        try:
            live_filter = self._build_live_filter()
            self._emit_status(f"● LIVE — filter: {live_filter[:80]}")
            with pydivert.WinDivert(live_filter) as w:
                for pkt in w:
                    if not self._running:
                        break
                    try:
                        src   = pkt.src_addr
                        dst   = pkt.dst_addr
                        proto = "TCP" if pkt.tcp else "UDP" if pkt.udp else "ICMP"
                        sport = getattr(pkt, "src_port", 0) or 0
                        dport = getattr(pkt, "dst_port", 0) or 0
                        size  = len(bytes(pkt.raw)) if pkt.raw else 0
                        direction = "IN" if pkt.is_inbound else "OUT"
                        ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]

                        # Re-inject immediately — minimise latency on real traffic
                        w.send(pkt)

                        # Determine remote peer IP
                        remote_ip = src if direction == "IN" else dst

                        # Skip noise
                        if _is_noise_ip(remote_ip) or remote_ip in self._local_ips:
                            continue

                        is_new = remote_ip not in self._seen_ips
                        self._seen_ips.add(remote_ip)
                        self._peer_ips.add(remote_ip)

                        packet = {
                            "ts": ts, "src": src, "dst": dst,
                            "sport": sport, "dport": dport,
                            "proto": proto, "size": size,
                            "direction": direction,
                            "new": is_new,
                            "is_peer": True,
                            "peer_ip": remote_ip,
                        }
                        self._emit_packet(packet)
                    except Exception:
                        pass
        except Exception as e:
            self._emit_status(f"[Engine Error] {e}")
            self._running = False

    def _run_simulation(self):
        """Synthetic packet generator — only real-looking public IPs, no noise."""
        public_pool = [
            f"{r}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            for r in [5, 31, 46, 54, 77, 82, 104, 151, 185, 199, 204, 216]
        ]
        protos    = ["UDP", "UDP", "UDP", "TCP", "TCP"]
        game_ports = [6672, 3074, 7777, 50000, 3478, 27015, 37015, 443, 8801]

        while self._running:
            remote    = random.choice(public_pool)
            local_ip  = "192.168.1.2"
            direction = random.choice(["IN", "IN", "OUT"])
            src = remote if direction == "IN" else local_ip
            dst = local_ip if direction == "IN" else remote
            proto = random.choice(protos)
            sport = random.randint(1024, 65535)
            dport = random.choice(game_ports)
            size  = random.randint(64, 1400)
            ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            is_new = remote not in self._seen_ips
            self._seen_ips.add(remote)
            self._peer_ips.add(remote)

            packet = {
                "ts": ts, "src": src, "dst": dst,
                "sport": sport, "dport": dport,
                "proto": proto, "size": size,
                "direction": direction,
                "new": is_new,
                "is_peer": True,
                "peer_ip": remote,
            }
            self._emit_packet(packet)
            # Slower simulation — 5 packets/sec feels realistic
            time.sleep(0.2)

    def _emit_packet(self, p):
        if self.on_packet:
            self.on_packet(p)

    def _emit_status(self, s):
        if self.on_status:
            self.on_status(s)


# ── Utilities ──────────────────────────────────────────────────────────────────

def icmp_ping(host, count=4):
    """ICMP ping — returns list of result strings."""
    results = []
    try:
        param = "-n" if __import__("sys").platform == "win32" else "-c"
        proc = subprocess.run(
            ["ping", param, str(count), host],
            capture_output=True, text=True, timeout=15
        )
        output = proc.stdout or proc.stderr or "No output"
        results = [l for l in output.splitlines() if l.strip()]
    except Exception as e:
        results = [f"Ping error: {e}"]
    return results


def scan_ports(host, ports, timeout=0.5):
    """TCP port scan — returns list of (port, state) tuples."""
    results = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((host, port))
            s.close()
            results.append((port, "OPEN" if r == 0 else "CLOSED"))
        except Exception:
            results.append((port, "ERROR"))
    return results


def geoip_lookup(ip):
    """Free IP geolocation via ip-api.com."""
    import urllib.request
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,query"
        with urllib.request.urlopen(url, timeout=5) as r:
            import json
            return json.loads(r.read().decode())
    except Exception as e:
        return {"status": "fail", "message": str(e)}


def ssh_run(host, user, password, port, command, key_path=""):
    """Run a single SSH command — returns (stdout, stderr, error_str)."""
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(hostname=host, port=int(port), username=user, timeout=10)
        if key_path and key_path.strip():
            kwargs["key_filename"] = key_path.strip()
        elif password:
            kwargs["password"] = password
        client.connect(**kwargs)
        _, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        client.close()
        return out, err, ""
    except ImportError:
        return "", "", "paramiko not installed. Run: pip install paramiko"
    except Exception as e:
        return "", "", str(e)

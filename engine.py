# DVRKSNIFF Engine — Packet capture core
# Credited to @botnet1337 on IG

import threading
import time
import random
import socket
import subprocess
import ipaddress
from datetime import datetime

try:
    import pydivert
    WINDIVERT_AVAILABLE = True
except Exception:
    WINDIVERT_AVAILABLE = False


# ── Network Adapter Enumeration ────────────────────────────────────────────────

def get_adapters():
    """
    Returns list of dicts: {name, ip, friendly_name}
    Works on Windows via socket + getaddrinfo, fallback via ipconfig parsing.
    """
    adapters = []
    seen = set()

    # Primary method: socket hostname resolution
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            if ip not in seen and not ip.startswith("127.") and ":" not in ip:
                seen.add(ip)
                adapters.append({"ip": ip, "name": ip, "friendly_name": f"Local ({ip})"})
    except Exception:
        pass

    # Windows: parse ipconfig for friendly adapter names
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.splitlines()
        current_adapter = "Unknown"
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith(" ") and ":" in stripped:
                current_adapter = stripped.rstrip(":")
            elif "IPv4 Address" in stripped or "IP Address" in stripped:
                ip = stripped.split(":")[-1].strip().rstrip("(Preferred)").strip()
                if ip and not ip.startswith("127.") and ":" not in ip:
                    if ip not in seen:
                        seen.add(ip)
                        adapters.append({
                            "ip": ip,
                            "name": ip,
                            "friendly_name": f"{current_adapter} — {ip}",
                        })
                    else:
                        # Update friendly name for existing entry
                        for a in adapters:
                            if a["ip"] == ip:
                                a["friendly_name"] = f"{current_adapter} — {ip}"
    except Exception:
        pass

    # Linux/Mac: use netifaces if available
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                ip = addr.get("addr", "")
                if ip and not ip.startswith("127.") and ip not in seen:
                    seen.add(ip)
                    adapters.append({
                        "ip": ip,
                        "name": iface,
                        "friendly_name": f"{iface} — {ip}",
                    })
    except ImportError:
        pass

    if not adapters:
        adapters.append({"ip": "0.0.0.0", "name": "all", "friendly_name": "All Interfaces"})

    return adapters


def get_local_ips():
    """Return set of all local IPs to filter them out of peer detection."""
    ips = set(["127.0.0.1", "0.0.0.0"])
    for a in get_adapters():
        ips.add(a["ip"])
    return ips


# ── Sniffer Engine ─────────────────────────────────────────────────────────────

class SnifferEngine:
    """
    Core packet capture engine.
    Real mode  : WinDivert intercepts live packets kernel-level.
    Simulation : Generates synthetic events for demo/non-Windows.
    """

    def __init__(self, on_packet=None, on_status=None):
        self.on_packet  = on_packet   # callback(packet_dict)
        self.on_status  = on_status   # callback(str)
        self._thread    = None
        self._running   = False
        self._filter    = "true"
        self._adapter_ip = None       # bound adapter IP (None = all)
        self.simulation = not WINDIVERT_AVAILABLE
        self._seen_ips  = set()
        self._local_ips = get_local_ips()
        self._peer_ips  = set()       # confirmed P2P peers (not local, not CDN)

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, windivert_filter="true", adapter_ip=None):
        if self._running:
            return
        self._filter     = windivert_filter
        self._adapter_ip = adapter_ip
        self._running    = True
        self._seen_ips.clear()
        self._peer_ips.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def is_running(self):
        return self._running

    def get_peers(self):
        """Return set of confirmed peer IPs (non-local, non-loopback)."""
        return set(self._peer_ips)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _run(self):
        mode = "SIMULATION" if self.simulation else "LIVE"
        self._emit_status(f"● STARTING [{mode}]")
        if self.simulation:
            self._emit_status("⚠  SIMULATION MODE — WinDivert not available on this OS")
            self._run_simulation()
        else:
            adapter_str = f" on {self._adapter_ip}" if self._adapter_ip else ""
            self._emit_status(f"● LIVE CAPTURE{adapter_str} — WinDivert active")
            self._run_live()

    def _build_live_filter(self):
        """
        Combine user filter with adapter binding.
        WinDivert filter syntax: combine with 'and'.
        If adapter IP specified, restrict to that interface.
        """
        base = self._filter or "true"
        if self._adapter_ip and self._adapter_ip not in ("0.0.0.0", "all"):
            ip_clause = f"(ip.SrcAddr == {self._adapter_ip} or ip.DstAddr == {self._adapter_ip})"
            if base == "true":
                return ip_clause
            return f"({base}) and {ip_clause}"
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

                        # Determine if this is a real peer (not local/loopback/multicast)
                        is_peer = self._is_real_peer(src, dst, direction)
                        peer_ip = src if direction == "IN" else dst

                        if is_peer:
                            self._peer_ips.add(peer_ip)

                        packet = {
                            "ts":        ts,
                            "src":       src,
                            "dst":       dst,
                            "sport":     sport,
                            "dport":     dport,
                            "proto":     proto,
                            "size":      size,
                            "direction": direction,
                            "new":       peer_ip not in self._seen_ips,
                            "is_peer":   is_peer,
                            "peer_ip":   peer_ip if is_peer else None,
                        }
                        self._seen_ips.add(src)
                        self._seen_ips.add(dst)
                        w.send(pkt)  # re-inject — sniff only, never block
                        self._emit_packet(packet)
                    except Exception:
                        pass
        except Exception as e:
            self._emit_status(f"[Engine Error] {e}")
            self._running = False

    def _is_real_peer(self, src, dst, direction):
        """
        True if the remote IP is a real P2P peer:
        - Not local/loopback
        - Not multicast/broadcast
        - Not private RFC1918 (unless LAN gaming — can toggle)
        """
        remote = src if direction == "IN" else dst
        try:
            a = ipaddress.ip_address(remote)
            if a.is_loopback or a.is_multicast or a.is_unspecified:
                return False
            if remote in self._local_ips:
                return False
            return True
        except Exception:
            return False

    def _run_simulation(self):
        """Synthetic packet generator for demo mode."""
        public_pool = [
            f"{r}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            for r in [5, 31, 46, 54, 77, 82, 104, 151, 185, 192, 199, 204, 216]
        ]
        private_pool = [f"192.168.1.{i}" for i in range(2, 15)]
        protos    = ["UDP", "UDP", "UDP", "TCP"]
        game_ports = [6672, 3074, 7777, 50000, 3478, 27015, 37015, 443]

        while self._running:
            is_public = random.random() > 0.3
            remote = random.choice(public_pool if is_public else private_pool)
            local  = "192.168.1.2"
            direction = random.choice(["IN", "OUT"])
            src = remote if direction == "IN" else local
            dst = local  if direction == "IN" else remote
            proto = random.choice(protos)
            sport = random.randint(1024, 65535)
            dport = random.choice(game_ports)
            size  = random.randint(64, 1400)
            ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            is_peer = is_public

            if is_peer:
                self._peer_ips.add(remote)

            packet = {
                "ts": ts, "src": src, "dst": dst,
                "sport": sport, "dport": dport,
                "proto": proto, "size": size,
                "direction": direction,
                "new": remote not in self._seen_ips,
                "is_peer": is_peer,
                "peer_ip": remote if is_peer else None,
            }
            self._seen_ips.add(remote)
            self._emit_packet(packet)
            time.sleep(random.uniform(0.04, 0.25))

    def _emit_packet(self, pkt):
        if self.on_packet:
            self.on_packet(pkt)

    def _emit_status(self, msg):
        if self.on_status:
            self.on_status(msg)


# ── ICMP Pinger ────────────────────────────────────────────────────────────────

def icmp_ping(host, count=4, timeout_ms=2000):
    """
    Cross-platform ICMP ping using system ping binary.
    Returns list of {line, success, rtt_ms}.
    """
    import platform
    import re

    results = []
    is_win  = platform.system().lower() == "windows"

    try:
        if is_win:
            cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), host]

        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=count * (timeout_ms / 1000 + 2)
        )
        output = proc.stdout + proc.stderr
        lines  = output.splitlines()

        rtt_pattern = re.compile(r"time[=<](\d+\.?\d*)\s*ms", re.IGNORECASE)

        for line in lines:
            if not line.strip():
                continue
            m = rtt_pattern.search(line)
            rtt = float(m.group(1)) if m else None
            success = rtt is not None
            if not success:
                ll = line.lower()
                if any(x in ll for x in ["request timed out", "unreachable",
                                          "100% loss", "100% packet loss",
                                          "could not find host", "failure"]):
                    success = False
                elif any(x in ll for x in ["reply from", "bytes from", "icmp"]):
                    success = True
                else:
                    continue  # skip noise lines

            results.append({"line": line.strip(), "success": success, "rtt_ms": rtt})

        # Fallback: return all non-empty lines if nothing parsed
        if not results:
            for line in lines:
                if line.strip():
                    results.append({"line": line.strip(), "success": True, "rtt_ms": None})

    except subprocess.TimeoutExpired:
        results.append({"line": "Ping timed out", "success": False, "rtt_ms": None})
    except FileNotFoundError:
        results.append({"line": "ping binary not found", "success": False, "rtt_ms": None})
    except Exception as e:
        results.append({"line": f"Error: {e}", "success": False, "rtt_ms": None})

    return results


# ── Port Scanner ───────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1080: "SOCKS",
    3306: "MySQL", 3389: "RDP", 3478: "STUN/TURN",
    3074: "COD/Xbox Live", 5900: "VNC", 6379: "Redis",
    6672: "GTA/RDR2", 7777: "Game Server",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27015: "Steam/SRCDS", 27017: "MongoDB",
    37015: "Apex Legends", 50000: "Discord Voice",
}

def scan_ports(host, ports=None, timeout=0.5, on_progress=None):
    """TCP connect scan. Returns list of {port, service, open, banner}."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    # Resolve hostname once
    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror as e:
        return [{"port": 0, "service": "DNS", "open": False, "banner": f"Cannot resolve {host}: {e}"}]

    results = []
    for i, port in enumerate(ports):
        if on_progress:
            on_progress(i + 1, len(ports), port)
        banner = ""
        open_  = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            code = s.connect_ex((resolved, port))
            open_ = (code == 0)
            if open_:
                try:
                    s.settimeout(0.5)
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    raw = s.recv(256)
                    banner = raw.decode(errors="replace").split("\r\n")[0][:80]
                except Exception:
                    pass
            s.close()
        except Exception:
            pass
        results.append({
            "port":    port,
            "service": COMMON_PORTS.get(port, "Unknown"),
            "open":    open_,
            "banner":  banner,
        })
    return results


# ── GeoIP Lookup ───────────────────────────────────────────────────────────────

def geoip_lookup(ip):
    """
    Free IP geolocation using multiple providers with fallback.
    Primary: ip-api.com  (80 req/min free, no key)
    Fallback: ipinfo.io
    """
    import urllib.request
    import urllib.error
    import json

    # Validate IP first
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        # Try resolving hostname
        try:
            ip = socket.gethostbyname(ip)
        except Exception:
            return {"error": f"Invalid IP or unresolvable hostname: {ip}"}

    # Primary: ip-api.com
    try:
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,mobile,proxy,hosting"
        url = f"http://ip-api.com/json/{ip}?fields={fields}"
        req = urllib.request.Request(url, headers={"User-Agent": "DVRKSNIFF/2.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            return data
        # ip-api returned fail (private IP, etc.)
        return {"error": data.get("message", "IP lookup failed — may be private/reserved")}
    except urllib.error.URLError as e:
        pass  # Fall through to backup
    except Exception as e:
        pass

    # Fallback: ipinfo.io (no key needed for basic)
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "DVRKSNIFF/2.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
        if "bogon" in data:
            return {"error": "Private/reserved IP address — no geo data available"}
        # Normalize to ip-api format
        lat, lon = "0", "0"
        if "loc" in data:
            parts = data["loc"].split(",")
            lat, lon = parts[0], parts[1]
        return {
            "status":      "success",
            "query":       data.get("ip", ip),
            "country":     data.get("country", ""),
            "countryCode": data.get("country", ""),
            "regionName":  data.get("region", ""),
            "city":        data.get("city", ""),
            "zip":         data.get("postal", ""),
            "lat":         lat,
            "lon":         lon,
            "timezone":    data.get("timezone", ""),
            "isp":         data.get("org", ""),
            "org":         data.get("org", ""),
            "as":          data.get("org", ""),
        }
    except Exception as e:
        return {"error": f"All GeoIP providers failed: {e}"}


# ── SSH Client ─────────────────────────────────────────────────────────────────

def ssh_run(host, user, password, port, command, key_path=None, timeout=15):
    """
    Run a command over SSH. Returns (stdout_str, stderr_str, error_str).
    Uses paramiko. Falls back to system ssh if paramiko not available.
    """
    # Try paramiko first
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = dict(
            hostname=host,
            port=int(port),
            username=user,
            timeout=timeout,
            allow_agent=True,
            look_for_keys=True,
        )
        if key_path and key_path.strip():
            connect_kwargs["key_filename"] = key_path.strip()
        elif password:
            connect_kwargs["password"] = password
            connect_kwargs["look_for_keys"] = False
            connect_kwargs["allow_agent"] = False

        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        client.close()
        return out, err, None

    except ImportError:
        # paramiko not installed — use system ssh (Windows 10+ has it)
        pass
    except Exception as e:
        return "", "", str(e)

    # System ssh fallback
    try:
        ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
                   "-o", f"ConnectTimeout={timeout}",
                   "-p", str(port)]
        if key_path and key_path.strip():
            ssh_cmd += ["-i", key_path.strip()]
        ssh_cmd += [f"{user}@{host}", command]

        proc = subprocess.run(
            ssh_cmd, capture_output=True, text=True, timeout=timeout + 5,
            input=(password + "\n") if password else None
        )
        return proc.stdout, proc.stderr, None
    except FileNotFoundError:
        return "", "", "SSH not available. Install paramiko: pip install paramiko"
    except Exception as e:
        return "", "", str(e)

# DVRKSNIFF Engine — Packet capture core
# Credited to @botnet1337 on IG

import threading
import time
import random
import socket
import struct
import subprocess
from datetime import datetime

try:
    import pydivert
    WINDIVERT_AVAILABLE = True
except Exception:
    WINDIVERT_AVAILABLE = False


class SnifferEngine:
    """
    Core packet capture engine.
    Real mode: uses WinDivert to intercept live packets.
    Simulation mode: generates synthetic events for demo/non-Windows.
    """

    def __init__(self, on_packet=None, on_status=None):
        self.on_packet = on_packet   # callback(packet_dict)
        self.on_status = on_status   # callback(str)
        self._thread = None
        self._running = False
        self._filter = "true"
        self.simulation = not WINDIVERT_AVAILABLE
        self._seen_ips = set()

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, windivert_filter="true"):
        if self._running:
            return
        self._filter = windivert_filter
        self._running = True
        self._seen_ips.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def is_running(self):
        return self._running

    # ── Internal ───────────────────────────────────────────────────────────────

    def _run(self):
        if self.simulation:
            self._emit_status("⚠  SIMULATION MODE — WinDivert not available")
            self._run_simulation()
        else:
            self._emit_status("● LIVE CAPTURE — WinDivert active")
            self._run_live()

    def _run_live(self):
        try:
            with pydivert.WinDivert(self._filter) as w:
                for pkt in w:
                    if not self._running:
                        break
                    try:
                        src = pkt.src_addr
                        dst = pkt.dst_addr
                        proto = "TCP" if pkt.tcp else "UDP" if pkt.udp else "OTHER"
                        sport = pkt.src_port or 0
                        dport = pkt.dst_port or 0
                        size = len(pkt.raw) if pkt.raw else 0
                        direction = "IN" if pkt.is_inbound else "OUT"
                        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

                        packet = {
                            "ts": ts,
                            "src": src,
                            "dst": dst,
                            "sport": sport,
                            "dport": dport,
                            "proto": proto,
                            "size": size,
                            "direction": direction,
                            "new": src not in self._seen_ips and dst not in self._seen_ips,
                        }
                        self._seen_ips.add(src)
                        self._seen_ips.add(dst)
                        w.send(pkt)  # re-inject — we're sniffing, not blocking
                        self._emit_packet(packet)
                    except Exception:
                        pass
        except Exception as e:
            self._emit_status(f"Engine error: {e}")
            self._running = False

    def _run_simulation(self):
        pool = [
            "192.168.1." + str(i) for i in range(2, 20)
        ] + [
            f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(10)
        ] + [
            f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(20)
        ]
        protos = ["UDP", "TCP", "UDP", "UDP", "TCP"]
        directions = ["IN", "OUT"]

        while self._running:
            src = random.choice(pool)
            dst = random.choice(pool)
            proto = random.choice(protos)
            sport = random.randint(1024, 65535)
            dport = random.choice([6672, 3074, 50000, 443, 80, 27015, 7777, 3478])
            size = random.randint(64, 1400)
            direction = random.choice(directions)
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            packet = {
                "ts": ts,
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "size": size,
                "direction": direction,
                "new": src not in self._seen_ips,
            }
            self._seen_ips.add(src)
            self._emit_packet(packet)
            time.sleep(random.uniform(0.05, 0.3))

    def _emit_packet(self, pkt):
        if self.on_packet:
            self.on_packet(pkt)

    def _emit_status(self, msg):
        if self.on_status:
            self.on_status(msg)


# ── ICMP Pinger ────────────────────────────────────────────────────────────────

def icmp_ping(host, count=4, timeout=1000):
    """
    Sends ICMP echo requests and returns list of result dicts.
    Uses system ping command (works on both Windows and Linux).
    """
    results = []
    try:
        import platform
        is_win = platform.system().lower() == "windows"
        flag_c = "-n" if is_win else "-c"
        flag_w = f"-w {timeout}" if is_win else f"-W {timeout // 1000 or 1}"
        cmd = ["ping", flag_c, str(count), flag_w, host]

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = proc.communicate(timeout=30)

        lines = stdout.splitlines()
        for line in lines:
            ll = line.lower()
            if "time=" in ll or "time<" in ll:
                results.append({"line": line.strip(), "success": True})
            elif "request timed out" in ll or "100% packet loss" in ll or "unreachable" in ll:
                results.append({"line": line.strip(), "success": False})

        if not results:
            for line in lines:
                if line.strip():
                    results.append({"line": line.strip(), "success": True})

    except Exception as e:
        results.append({"line": f"Error: {e}", "success": False})

    return results


# ── Port Scanner ───────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 6379: "Redis", 6672: "GTA/RDR2",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27015: "Steam/SRCDS",
    3074: "COD/Xbox Live", 7777: "Fortnite/Gameserver",
    50000: "Discord Voice", 3478: "STUN/WhatsApp",
}

def scan_ports(host, ports=None, timeout=0.5, on_progress=None):
    """
    TCP port scan. Returns list of {port, service, open, banner}.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    results = []
    total = len(ports)

    for i, port in enumerate(ports):
        if on_progress:
            on_progress(i + 1, total, port)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            code = s.connect_ex((host, port))
            banner = ""
            if code == 0:
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode(errors="replace").split("\r\n")[0]
                except Exception:
                    pass
            s.close()
            results.append({
                "port": port,
                "service": COMMON_PORTS.get(port, "Unknown"),
                "open": code == 0,
                "banner": banner,
            })
        except Exception as e:
            results.append({"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "open": False, "banner": ""})

    return results


# ── GeoIP Lookup ───────────────────────────────────────────────────────────────

def geoip_lookup(ip):
    """
    Free IP geolocation via ip-api.com (no key needed).
    Returns dict with country, city, ISP, lat/lon, etc.
    """
    import urllib.request
    import json
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        req = urllib.request.Request(url, headers={"User-Agent": "DVRKSNIFF/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            return data
        return {"error": data.get("message", "lookup failed")}
    except Exception as e:
        return {"error": str(e)}

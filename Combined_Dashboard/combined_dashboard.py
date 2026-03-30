#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   CodeAlpha Cybersecurity Internship                         ║
║   Combined Dashboard — Task 1 + Task 4                       ║
║   Network Packet Analyzer v2.0 + Suricata IDS                ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, time, signal, argparse, threading, collections, json, os
from datetime import datetime

# ── Scapy ────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        ARP, Raw, Ether, get_if_list
    )
    SCAPY = True
except ImportError:
    SCAPY = False

import curses
import socket
import struct

# ════════════════════════════════════════════════════════════
#  Suricata log paths
# ════════════════════════════════════════════════════════════
IDS_LOG_PATHS = [
    "/root/CodeAlpha_ProjectName/Task4_IDS/eve.json",
    "/var/log/suricata/eve.json",
]

def find_ids_log():
    for p in IDS_LOG_PATHS:
        if os.path.exists(p):
            return p
    return None

# ════════════════════════════════════════════════════════════
#  Shared state
# ════════════════════════════════════════════════════════════
lock = threading.Lock()

MAX_LOG  = 200
pkt_log  = collections.deque(maxlen=MAX_LOG)

SPARK_LEN = 60
rate_ring = collections.deque([0]*SPARK_LEN, maxlen=SPARK_LEN)
_rate_tmp = [0]

proto_counts = collections.defaultdict(int)
src_counts   = collections.defaultdict(int)
dst_counts   = collections.defaultdict(int)
port_counts  = collections.defaultdict(int)
total_pkts   = [0]
total_bytes  = [0]
start_ts     = [time.time()]

MAX_DEEP = 100
deep_log = collections.deque(maxlen=MAX_DEEP)

# ── Alert log (Task 1 live + Task 4 Suricata) ──
MAX_ALERTS = 100
alert_log  = collections.deque(maxlen=MAX_ALERTS)

# IDS summary counters
ids_total    = [0]
ids_by_sig   = collections.defaultdict(int)
ids_by_src   = collections.defaultdict(int)
ids_by_proto = collections.defaultdict(int)

# Port-scan detection
syn_tracker    = collections.defaultdict(list)
SCAN_THRESHOLD = 15

# ════════════════════════════════════════════════════════════
#  Colour palette
# ════════════════════════════════════════════════════════════
C_HEADER = 1
C_TCP    = 2
C_UDP    = 3
C_ICMP   = 4
C_DNS    = 5
C_HTTP   = 6
C_ARP    = 7
C_OTHER  = 8
C_DIM    = 9
C_ALERT  = 10
C_DEEP   = 11
C_TITLE  = 12
C_GRAPH  = 13
C_BORDER = 14
C_IDS    = 15   # bright red for Suricata alerts

PROTO_COLOUR = {
    "TCP": C_TCP, "UDP": C_UDP, "ICMP": C_ICMP,
    "DNS": C_DNS, "HTTP": C_HTTP, "HTTPS": C_HTTP,
    "ARP": C_ARP, "TLS": C_HTTP,
}

WELL_KNOWN = {
    20:"FTP-data",21:"FTP",22:"SSH",23:"Telnet",
    25:"SMTP",53:"DNS",67:"DHCP",80:"HTTP",
    110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    3306:"MySQL",5432:"PG",6379:"Redis",
    8080:"HTTP-alt",8443:"HTTPS-alt",
    4444:"Metasploit",1337:"Leet",6667:"IRC",
}

# ════════════════════════════════════════════════════════════
#  Task 4: Suricata log reader thread
# ════════════════════════════════════════════════════════════
def suricata_reader_thread():
    log_file = find_ids_log()
    if not log_file:
        with lock:
            alert_log.appendleft(
                "[IDS] No Suricata log found — start Suricata first"
            )
        return

    seen = 0
    while True:
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            for line in lines[seen:]:
                try:
                    ev = json.loads(line.strip())
                    if ev.get('event_type') == 'alert':
                        ts  = ev.get('timestamp','')[:19].replace('T',' ')
                        sig = ev['alert']['signature']
                        src = ev.get('src_ip','?')
                        dst = ev.get('dest_ip','?')
                        sev = ev['alert'].get('severity', 3)
                        sev_label = {1:"HIGH",2:"MED",3:"LOW"}.get(sev,"?")
                        with lock:
                            alert_log.appendleft(
                                f"[SURICATA][{sev_label}] {ts}  "
                                f"{src} -> {dst}  |  {sig}"
                            )
                            ids_total[0] += 1
                            ids_by_sig[sig] += 1
                            ids_by_src[src] += 1
                            ids_by_proto[ev.get('proto','?')] += 1
                except Exception:
                    pass
            seen = len(lines)
        except Exception:
            pass
        time.sleep(2)

# ════════════════════════════════════════════════════════════
#  Task 1: Protocol deep-dive parsers (from your original v2)
# ════════════════════════════════════════════════════════════
def parse_http(raw, src, dst):
    try:
        text  = raw.decode("utf-8", errors="replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    first = lines[0]
    for method in ("GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","CONNECT"):
        if first.startswith(method + " "):
            parts = first.split(" ", 2)
            path  = parts[1] if len(parts) > 1 else "?"
            host  = next((l.split(":",1)[1].strip() for l in lines
                          if l.lower().startswith("host:")), "")
            ua    = next((l.split(":",1)[1].strip()[:40] for l in lines
                          if l.lower().startswith("user-agent:")), "")
            return (f"HTTP  {method} {path}  "
                    f"{'Host:'+host if host else ''}  "
                    f"{'UA:'+ua if ua else ''}").strip()
    if first.startswith("HTTP/"):
        code = first.split(" ")[1] if len(first.split(" ")) > 1 else "?"
        ct   = next((l.split(":",1)[1].strip()[:30] for l in lines
                     if l.lower().startswith("content-type:")), "")
        return f"HTTP  Response {code}  {ct}"
    return None

def parse_dns_pkt(pkt):
    if DNS not in pkt:
        return None
    dns = pkt[DNS]
    if dns.qr == 0 and dns.qd:
        try:
            name = dns.qd.qname.decode("utf-8","replace").rstrip(".")
        except Exception:
            name = str(dns.qd.qname)
        qt = {1:"A",2:"NS",5:"CNAME",15:"MX",
              16:"TXT",28:"AAAA"}.get(dns.qd.qtype,"?")
        return f"DNS   QUERY  {name}  [{qt}]"
    elif dns.qr == 1 and dns.an:
        try:
            name = dns.qd.qname.decode("utf-8","replace").rstrip(".") if dns.qd else "?"
        except Exception:
            name = "?"
        answers = []
        an = dns.an
        while an:
            try:
                answers.append(str(an.rdata))
            except Exception:
                pass
            an = (an.payload
                  if hasattr(an,"payload")
                  and isinstance(an.payload, type(dns.an))
                  else None)
            if an and not hasattr(an,"rdata"):
                break
        return f"DNS   REPLY  {name}  -> {', '.join(answers[:3])}"
    return None

def parse_tls(raw):
    if len(raw) < 6:
        return None
    rec_type = raw[0]
    if rec_type not in (20,21,22,23):
        return None
    major, minor = raw[1], raw[2]
    ver_map = {(3,1):"TLS 1.0",(3,3):"TLS 1.2",(3,4):"TLS 1.3"}
    ver = ver_map.get((major,minor), f"TLS {major}.{minor}")
    if rec_type == 22 and len(raw) > 6:
        hs_type = raw[5]
        hs_map  = {1:"ClientHello",2:"ServerHello",
                   11:"Certificate",14:"ServerHelloDone",
                   16:"ClientKeyExchange",20:"Finished"}
        return f"TLS   {ver} {hs_map.get(hs_type,f'type={hs_type}')}"
    type_map = {20:"ChangeCipherSpec",21:"Alert",
                22:"Handshake",23:"AppData"}
    return f"TLS   {ver} {type_map.get(rec_type,'?')}"

def parse_smtp(raw):
    try:
        text = raw.decode("utf-8","replace").strip()
    except Exception:
        return None
    for kw in ("EHLO","HELO","MAIL FROM","RCPT TO","DATA","QUIT","AUTH"):
        if text.upper().startswith(kw):
            return f"SMTP  {text[:80]}"
    if len(text) >= 3 and text[:3].isdigit():
        return f"SMTP  Response {text[:60]}"
    return None

def parse_ftp(raw):
    try:
        text = raw.decode("utf-8","replace").strip()
    except Exception:
        return None
    for kw in ("USER","PASS","LIST","RETR","STOR","QUIT","PORT","PASV","TYPE"):
        if text.upper().startswith(kw):
            return f"FTP   {text[:80]}"
    if len(text) >= 3 and text[:3].isdigit():
        return f"FTP   Response {text[:60]}"
    return None

# ════════════════════════════════════════════════════════════
#  Task 1: Port-scan detection
# ════════════════════════════════════════════════════════════
def check_portscan(src_ip, flags):
    SYN = 0x02; ACK = 0x10
    if (flags & SYN) and not (flags & ACK):
        now = time.time()
        with lock:
            lst = syn_tracker[src_ip]
            lst.append(now)
            syn_tracker[src_ip] = [t for t in lst if now - t < 10]
            count = len(syn_tracker[src_ip])
        if count == SCAN_THRESHOLD:
            ts = datetime.now().strftime("%H:%M:%S")
            with lock:
                alert_log.appendleft(
                    f"[LIVE][HIGH] {ts}  "
                    f"PORT SCAN from {src_ip}  "
                    f"({count} SYNs in 10s)"
                )

# ════════════════════════════════════════════════════════════
#  Task 1: Packet callback
# ════════════════════════════════════════════════════════════
def on_packet(pkt):
    ts    = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    size  = len(pkt)
    proto = "OTHER"
    src   = dst = "?"
    info  = ""
    deep  = None

    if ARP in pkt:
        a = pkt[ARP]
        proto = "ARP"
        src, dst = a.psrc, a.pdst
        info = "REQUEST" if a.op == 1 else "REPLY"

    elif IP in pkt:
        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst

        if TCP in pkt:
            tcp   = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            flags = tcp.flags
            flag_str = str(flags)
            svc   = WELL_KNOWN.get(dport) or WELL_KNOWN.get(sport,"")
            proto = (svc if svc in
                     ("HTTP","HTTPS","FTP","SSH","SMTP") else "TCP")
            src   = f"{src_ip}:{sport}"
            dst   = f"{dst_ip}:{dport}"
            info  = (f"Flags={flag_str}  Seq={tcp.seq}  "
                     f"Win={tcp.window}  "
                     f"Sport={WELL_KNOWN.get(sport,sport)}  "
                     f"Dport={WELL_KNOWN.get(dport,dport)}")
            check_portscan(src_ip, int(flags))
            with lock:
                port_counts[dport] += 1
            if Raw in pkt:
                raw = bytes(pkt[Raw])
                if dport == 80 or sport == 80:
                    deep = parse_http(raw, src, dst)
                elif dport == 443 or sport == 443:
                    deep = parse_tls(raw)
                elif dport == 21 or sport == 21:
                    deep = parse_ftp(raw)
                elif dport == 25 or sport == 25:
                    deep = parse_smtp(raw)
                if not deep:
                    deep = parse_tls(raw)

        elif UDP in pkt:
            udp   = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            proto = "DNS" if (dport==53 or sport==53) else "UDP"
            src   = f"{src_ip}:{sport}"
            dst   = f"{dst_ip}:{dport}"
            info  = (f"Len={udp.len}  "
                     f"Sport={WELL_KNOWN.get(sport,sport)}  "
                     f"Dport={WELL_KNOWN.get(dport,dport)}")
            with lock:
                port_counts[dport] += 1
            deep = parse_dns_pkt(pkt)

        elif ICMP in pkt:
            ic    = pkt[ICMP]
            proto = "ICMP"
            src, dst = src_ip, dst_ip
            t_map = {0:"Echo Reply",3:"Unreachable",
                     8:"Echo Request",11:"Time Exceeded"}
            info  = (f"Type={ic.type}"
                     f"({t_map.get(ic.type,'?')}) Code={ic.code}")
        else:
            proto = f"IP/{ip.proto}"
            src, dst = src_ip, dst_ip

    elif IPv6 in pkt:
        ip6   = pkt[IPv6]
        proto = "IPv6"
        src, dst = ip6.src, ip6.dst
        info  = f"NH={ip6.nh}"
    else:
        return

    with lock:
        proto_counts[proto] += 1
        src_counts[src.split(":")[0]]  += 1
        dst_counts[dst.split(":")[0]]  += 1
        total_pkts[0]  += 1
        total_bytes[0] += size
        _rate_tmp[0]   += 1
        pkt_log.appendleft({
            "ts":ts,"proto":proto,
            "src":src,"dst":dst,
            "info":info,"size":size,
        })
        if deep:
            deep_log.appendleft(f"[{ts}] {deep}")

# ════════════════════════════════════════════════════════════
#  Rate ticker
# ════════════════════════════════════════════════════════════
def rate_ticker():
    while True:
        time.sleep(1)
        with lock:
            rate_ring.append(_rate_tmp[0])
            _rate_tmp[0] = 0

# ════════════════════════════════════════════════════════════
#  Curses helpers
# ════════════════════════════════════════════════════════════
def init_colours():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_HEADER, curses.COLOR_CYAN,    -1)
    curses.init_pair(C_TCP,    curses.COLOR_GREEN,   -1)
    curses.init_pair(C_UDP,    curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_ICMP,   curses.COLOR_MAGENTA, -1)
    curses.init_pair(C_DNS,    curses.COLOR_CYAN,    -1)
    curses.init_pair(C_HTTP,   curses.COLOR_RED,     -1)
    curses.init_pair(C_ARP,    curses.COLOR_BLUE,    -1)
    curses.init_pair(C_OTHER,  curses.COLOR_WHITE,   -1)
    curses.init_pair(C_DIM,    8,                    -1)
    curses.init_pair(C_ALERT,  curses.COLOR_RED,     -1)
    curses.init_pair(C_DEEP,   curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_TITLE,  curses.COLOR_WHITE,   -1)
    curses.init_pair(C_GRAPH,  curses.COLOR_GREEN,   -1)
    curses.init_pair(C_BORDER, curses.COLOR_CYAN,    -1)
    curses.init_pair(C_IDS,    curses.COLOR_RED,     -1)

def safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0:
        return
    max_len = w - x - 1
    if max_len <= 0:
        return
    try:
        win.addstr(y, x, text[:max_len], attr)
    except curses.error:
        pass

SPARK_CHARS = " ▁▂▃▄▅▆▇█"

def sparkline(values, width):
    data = list(values)[-width:]
    if not data:
        return " " * width
    mx = max(data) or 1
    return "".join(
        SPARK_CHARS[int((v/mx)*(len(SPARK_CHARS)-1))]
        for v in data
    ).ljust(width)

def bar_chart(counts, width, n=8):
    top = sorted(counts.items(), key=lambda x: -x[1])[:n]
    if not top:
        return []
    mx    = top[0][1] or 1
    bar_w = max(1, width - 20)
    rows  = []
    for label, cnt in top:
        filled = max(1, int((cnt/mx)*bar_w))
        bar    = "█"*filled + "░"*(bar_w-filled)
        rows.append((str(label)[:14], bar, cnt))
    return rows

# ════════════════════════════════════════════════════════════
#  Dashboard — 5 tabs
# ════════════════════════════════════════════════════════════
TAB_NAMES   = ["Packets","Deep-Dive","Graphs","Alerts","IDS-Dashboard"]
current_tab = [0]

def draw_dashboard(stdscr, args):
    curses.curs_set(0)
    stdscr.nodelay(True)
    init_colours()

    while True:
        try:
            key = stdscr.getch()
        except Exception:
            key = -1

        if key == ord('q'):
            break
        elif key == curses.KEY_RIGHT or key == ord('\t'):
            current_tab[0] = (current_tab[0]+1) % len(TAB_NAMES)
        elif key == curses.KEY_LEFT:
            current_tab[0] = (current_tab[0]-1) % len(TAB_NAMES)
        elif key in (ord('1'),ord('2'),ord('3'),ord('4'),ord('5')):
            current_tab[0] = int(chr(key))-1

        H, W = stdscr.getmaxyx()
        stdscr.erase()

        # ── Header ─────────────────────────────────────
        elapsed = time.time() - start_ts[0]
        ids_log_ok = "YES" if find_ids_log() else "NO"
        hdr = (f"  CodeAlpha T1+T4  "
               f"Pkts:{total_pkts[0]:>6}  "
               f"Bytes:{total_bytes[0]:>8,}  "
               f"Rate:{rate_ring[-1]:>3}/s  "
               f"Up:{int(elapsed//60):02d}:{int(elapsed%60):02d}  "
               f"IDS-Alerts:{ids_total[0]}  "
               f"Suricata:{ids_log_ok}  ")
        safe_addstr(stdscr, 0, 0, hdr.ljust(W),
                    curses.color_pair(C_HEADER)|curses.A_BOLD)

        # ── Tab bar ─────────────────────────────────────
        tx = 1
        for i, name in enumerate(TAB_NAMES):
            label = f" {i+1}:{name} "
            if i == current_tab[0]:
                safe_addstr(stdscr, 1, tx, label,
                            curses.color_pair(C_TITLE)|curses.A_REVERSE|curses.A_BOLD)
            else:
                safe_addstr(stdscr, 1, tx, label,
                            curses.color_pair(C_DIM))
            tx += len(label)+1

        nav = "  </> Tab:switch  q:quit"
        safe_addstr(stdscr, 1, W-len(nav)-1, nav,
                    curses.color_pair(C_DIM))
        safe_addstr(stdscr, 2, 0, "─"*W,
                    curses.color_pair(C_BORDER))

        tab = current_tab[0]

        # ════════════════════════════════════════════════
        #  TAB 0 — Packets (your original v2 tab)
        # ════════════════════════════════════════════════
        if tab == 0:
            body_h = H - 4
            log_w  = W - 22
            safe_addstr(stdscr, 3, 0,
                        f" {'TIME':<12} {'PROTO':<7} {'SRC':<22} {'DST':<22} {'SIZE':>5}  INFO",
                        curses.color_pair(C_DIM)|curses.A_BOLD)
            safe_addstr(stdscr, 4, 0, "─"*log_w,
                        curses.color_pair(C_BORDER))
            with lock:
                snapshot = list(pkt_log)
            for i, e in enumerate(snapshot[:body_h-4]):
                row = 5+i
                if row >= H-1:
                    break
                pc    = PROTO_COLOUR.get(e["proto"], C_OTHER)
                ts_s  = e["ts"][:12].ljust(12)
                pr_s  = e["proto"][:6].ljust(7)
                src_s = e["src"][:21].ljust(22)
                dst_s = e["dst"][:21].ljust(22)
                sz_s  = str(e["size"]).rjust(5)
                info_s= e["info"][:log_w-72]
                safe_addstr(stdscr, row, 0,
                            f" {ts_s} ", curses.color_pair(C_DIM))
                safe_addstr(stdscr, row, 14, pr_s,
                            curses.color_pair(pc)|curses.A_BOLD)
                safe_addstr(stdscr, row, 21, src_s,
                            curses.color_pair(C_DNS))
                safe_addstr(stdscr, row, 44, dst_s,
                            curses.color_pair(C_DEEP))
                safe_addstr(stdscr, row, 67, sz_s,
                            curses.color_pair(C_DIM))
                safe_addstr(stdscr, row, 73, info_s,
                            curses.color_pair(C_DIM))
            # Right: protocol counts
            px = log_w+1
            safe_addstr(stdscr, 3, px, " PROTOCOL COUNTS",
                        curses.color_pair(C_HEADER)|curses.A_BOLD)
            safe_addstr(stdscr, 4, px, "─"*(W-px-1),
                        curses.color_pair(C_BORDER))
            with lock:
                pc_snap = dict(proto_counts)
            for i,(pr,cnt) in enumerate(
                    sorted(pc_snap.items(), key=lambda x:-x[1])[:body_h-4]):
                row = 5+i
                if row >= H-1: break
                col = PROTO_COLOUR.get(pr, C_OTHER)
                safe_addstr(stdscr, row, px,
                            f" {pr:<8} {cnt:>6}",
                            curses.color_pair(col))

        # ════════════════════════════════════════════════
        #  TAB 1 — Deep-Dive (your original v2 tab)
        # ════════════════════════════════════════════════
        elif tab == 1:
            safe_addstr(stdscr, 3, 0,
                        "  Protocol Deep-Dive  "
                        "(HTTP content · DNS queries/answers · TLS SNI · FTP · SMTP)",
                        curses.color_pair(C_DEEP)|curses.A_BOLD)
            safe_addstr(stdscr, 4, 0, "─"*W,
                        curses.color_pair(C_BORDER))
            with lock:
                dl_snap = list(deep_log)
            for i, entry in enumerate(dl_snap[:H-7]):
                row = 5+i
                if row >= H-1: break
                col = C_DIM
                if "HTTP" in entry: col = C_HTTP
                elif "DNS"  in entry: col = C_DNS
                elif "TLS"  in entry: col = C_ICMP
                elif "SMTP" in entry: col = C_UDP
                elif "FTP"  in entry: col = C_ARP
                safe_addstr(stdscr, row, 2, entry[:W-4],
                            curses.color_pair(col))
            if not dl_snap:
                safe_addstr(stdscr, H//2, W//2-20,
                            "No deep-dive data yet — generate some traffic!",
                            curses.color_pair(C_DIM))

        # ════════════════════════════════════════════════
        #  TAB 2 — Graphs (your original v2 tab)
        # ════════════════════════════════════════════════
        elif tab == 2:
            row = 3
            safe_addstr(stdscr, row, 2,
                        "Packets/second  (last 60 s)",
                        curses.color_pair(C_HEADER)|curses.A_BOLD)
            row += 1
            safe_addstr(stdscr, row, 0, "─"*W,
                        curses.color_pair(C_BORDER))
            row += 1
            with lock:
                spark_data = list(rate_ring)
            spark_w = min(W-16, 60)
            mx_rate = max(spark_data) if spark_data else 1
            spark_s = sparkline(spark_data, spark_w)
            safe_addstr(stdscr, row, 2,
                        f"max={mx_rate:>4}/s |{spark_s}|  now={rate_ring[-1]:>4}/s",
                        curses.color_pair(C_GRAPH)|curses.A_BOLD)
            row += 2
            safe_addstr(stdscr, row, 2, "Top Protocols",
                        curses.color_pair(C_HEADER)|curses.A_BOLD)
            row += 1
            safe_addstr(stdscr, row, 0, "─"*W,
                        curses.color_pair(C_BORDER))
            row += 1
            with lock:
                pc_snap = dict(proto_counts)
            for label, bar, cnt in bar_chart(pc_snap, W-4, n=6):
                if row >= H-2: break
                col = PROTO_COLOUR.get(label.strip(), C_OTHER)
                safe_addstr(stdscr, row, 2, f"{label:<12}",
                            curses.color_pair(col)|curses.A_BOLD)
                safe_addstr(stdscr, row, 15, bar,
                            curses.color_pair(C_GRAPH))
                safe_addstr(stdscr, row, 15+len(bar)+1, str(cnt),
                            curses.color_pair(C_DIM))
                row += 1
            row += 1
            if row+4 < H:
                safe_addstr(stdscr, row, 2, "Top Destination Ports",
                            curses.color_pair(C_HEADER)|curses.A_BOLD)
                row += 1
                safe_addstr(stdscr, row, 0, "─"*W,
                            curses.color_pair(C_BORDER))
                row += 1
                with lock:
                    port_snap = {
                        f"{p}({WELL_KNOWN.get(p,'')})": c
                        for p, c in port_counts.items()
                    }
                for label, bar, cnt in bar_chart(port_snap, W-4, n=5):
                    if row >= H-2: break
                    safe_addstr(stdscr, row, 2, f"{label:<14}",
                                curses.color_pair(C_UDP)|curses.A_BOLD)
                    safe_addstr(stdscr, row, 17, bar,
                                curses.color_pair(C_TCP))
                    safe_addstr(stdscr, row, 17+len(bar)+1, str(cnt),
                                curses.color_pair(C_DIM))
                    row += 1
            row += 1
            if row+4 < H:
                safe_addstr(stdscr, row, 2, "Top Source IPs",
                            curses.color_pair(C_HEADER)|curses.A_BOLD)
                row += 1
                safe_addstr(stdscr, row, 0, "─"*W,
                            curses.color_pair(C_BORDER))
                row += 1
                with lock:
                    src_snap = dict(src_counts)
                for label, bar, cnt in bar_chart(src_snap, W-4, n=5):
                    if row >= H-2: break
                    safe_addstr(stdscr, row, 2, f"{label:<16}",
                                curses.color_pair(C_DNS)|curses.A_BOLD)
                    safe_addstr(stdscr, row, 19, bar,
                                curses.color_pair(C_UDP))
                    safe_addstr(stdscr, row, 19+len(bar)+1, str(cnt),
                                curses.color_pair(C_DIM))
                    row += 1

        # ════════════════════════════════════════════════
        #  TAB 3 — Alerts (Live port-scan + Suricata)
        # ════════════════════════════════════════════════
        elif tab == 3:
            safe_addstr(stdscr, 3, 2,
                        "Security Alerts  "
                        "[LIVE] port-scan detection  |  "
                        "[SURICATA] IDS alerts",
                        curses.color_pair(C_ALERT)|curses.A_BOLD)
            safe_addstr(stdscr, 4, 0, "─"*W,
                        curses.color_pair(C_BORDER))
            with lock:
                al_snap = list(alert_log)
            if not al_snap:
                safe_addstr(stdscr, H//2, W//2-18,
                            "No alerts yet — run nmap / ping to trigger",
                            curses.color_pair(C_DIM))
            else:
                for i, a in enumerate(al_snap[:H-7]):
                    row = 5+i
                    if row >= H-1: break
                    # Color by source
                    if "[SURICATA]" in a:
                        if "[HIGH]" in a:
                            col = curses.color_pair(C_IDS)|curses.A_BOLD
                        else:
                            col = curses.color_pair(C_IDS)
                    else:
                        col = curses.color_pair(C_ALERT)|curses.A_BOLD
                    safe_addstr(stdscr, row, 2,
                                f">> {a[:W-6]}", col)

        # ════════════════════════════════════════════════
        #  TAB 4 — IDS Dashboard (Task 4 summary)
        # ════════════════════════════════════════════════
        elif tab == 4:
            safe_addstr(stdscr, 3, 2,
                        "IDS Dashboard  — Powered by Suricata  (Task 4)",
                        curses.color_pair(C_IDS)|curses.A_BOLD)
            safe_addstr(stdscr, 4, 0, "─"*W,
                        curses.color_pair(C_BORDER))

            log_path = find_ids_log()
            row = 5
            # Status
            if log_path:
                safe_addstr(stdscr, row, 2,
                            f"Suricata Log : {log_path}",
                            curses.color_pair(C_TCP)|curses.A_BOLD)
            else:
                safe_addstr(stdscr, row, 2,
                            "Suricata Log : NOT FOUND — "
                            "start: sudo suricata -c /etc/suricata/suricata.yaml "
                            "-i lo -l /root/CodeAlpha_ProjectName/Task4_IDS/",
                            curses.color_pair(C_ALERT)|curses.A_BOLD)
            row += 1
            with lock:
                total_ids    = ids_total[0]
                sig_snap     = dict(ids_by_sig)
                src_ids_snap = dict(ids_by_src)
                proto_snap   = dict(ids_by_proto)

            safe_addstr(stdscr, row, 2,
                        f"Total IDS Alerts : {total_ids}",
                        curses.color_pair(C_HEADER)|curses.A_BOLD)
            row += 2

            # Top Signatures
            mid = W//2
            safe_addstr(stdscr, row, 2,
                        "-- Top Alert Signatures --",
                        curses.color_pair(C_IDS)|curses.A_BOLD)
            row += 1
            safe_addstr(stdscr, row, 2, "─"*(mid-4),
                        curses.color_pair(C_BORDER))
            row += 1
            top_sigs = sorted(sig_snap.items(),
                              key=lambda x:-x[1])[:10]
            for sig, cnt in top_sigs:
                if row >= H-8: break
                short = sig[:mid-14] if len(sig)>mid-14 else sig
                safe_addstr(stdscr, row, 2,
                            f"[{cnt:>4}x] {short}",
                            curses.color_pair(C_ALERT))
                row += 1

            # Top source IPs (right side)
            row2 = 8
            safe_addstr(stdscr, row2, mid,
                        "-- Top Attacking IPs --",
                        curses.color_pair(C_IDS)|curses.A_BOLD)
            row2 += 1
            safe_addstr(stdscr, row2, mid, "─"*(W-mid-2),
                        curses.color_pair(C_BORDER))
            row2 += 1
            for ip, cnt in sorted(src_ids_snap.items(),
                                  key=lambda x:-x[1])[:8]:
                if row2 >= H-8: break
                safe_addstr(stdscr, row2, mid,
                            f"{ip:<22} {cnt} alerts",
                            curses.color_pair(C_ICMP)|curses.A_BOLD)
                row2 += 1

            # Protocol breakdown
            row2 += 1
            safe_addstr(stdscr, row2, mid,
                        "-- IDS Protocol Breakdown --",
                        curses.color_pair(C_IDS)|curses.A_BOLD)
            row2 += 1
            safe_addstr(stdscr, row2, mid, "─"*(W-mid-2),
                        curses.color_pair(C_BORDER))
            row2 += 1
            for pr, cnt in sorted(proto_snap.items(),
                                  key=lambda x:-x[1])[:5]:
                if row2 >= H-4: break
                bar  = "█" * min(cnt, W-mid-20)
                safe_addstr(stdscr, row2, mid,
                            f"{pr:<8} {bar} {cnt}",
                            curses.color_pair(C_GRAPH))
                row2 += 1

            # Bottom tip
            if not sig_snap:
                safe_addstr(stdscr, H-4, 2,
                            "No IDS alerts yet.  Run: nmap -sS 127.0.0.1  "
                            "| ping -c 30 127.0.0.1",
                            curses.color_pair(C_DIM))

        # ── Footer ──────────────────────────────────────
        safe_addstr(stdscr, H-1, 0,
                    " [1]Packets [2]Deep-Dive [3]Graphs "
                    "[4]Alerts [5]IDS-Dashboard   q:quit".ljust(W),
                    curses.color_pair(C_DIM)|curses.A_REVERSE)

        stdscr.refresh()
        time.sleep(0.15)

# ════════════════════════════════════════════════════════════
#  Sniffer thread
# ════════════════════════════════════════════════════════════
def start_sniffer(args):
    if not SCAPY:
        with lock:
            alert_log.appendleft(
                "Scapy not installed — pip3 install scapy --break-system-packages"
            )
        return
    kwargs = {"prn": on_packet, "store": False}
    if args.iface:
        kwargs["iface"] = args.iface
    if args.filter:
        kwargs["filter"] = args.filter
    if args.count:
        kwargs["count"]  = args.count
    try:
        sniff(**kwargs)
    except PermissionError:
        with lock:
            alert_log.appendleft("Permission denied — run with sudo!")
    except Exception as e:
        with lock:
            alert_log.appendleft(f"Sniffer error: {e}")

# ════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        description="CodeAlpha Combined Dashboard — Task1 + Task4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 combined_dashboard.py
  sudo python3 combined_dashboard.py -i eth0
  sudo python3 combined_dashboard.py -i lo -f "tcp or icmp"
  sudo python3 combined_dashboard.py --list-interfaces
        """)
    p.add_argument("-i","--iface",  default=None,
                   help="Interface to sniff (default: auto)")
    p.add_argument("-c","--count",  type=int, default=0,
                   help="Stop after N packets")
    p.add_argument("-f","--filter", default="",
                   help="BPF filter string")
    p.add_argument("--list-interfaces", action="store_true")
    return p.parse_args()

def main():
    args = parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        if SCAPY:
            for i in get_if_list():
                print(f"  * {i}")
        else:
            for _, name in socket.if_nameindex():
                print(f"  * {name}")
        return

    # Check Suricata log
    log_path = find_ids_log()
    if log_path:
        print(f"[OK] Suricata log found: {log_path}")
    else:
        print("[!] No Suricata log found.")
        print("    Start Suricata: sudo suricata -c "
              "/etc/suricata/suricata.yaml -i lo "
              "-l /root/CodeAlpha_ProjectName/Task4_IDS/")
        print("[*] Continuing with live detection only...\n")

    # Start all background threads
    threading.Thread(
        target=start_sniffer, args=(args,), daemon=True).start()
    threading.Thread(
        target=rate_ticker, daemon=True).start()
    threading.Thread(
        target=suricata_reader_thread, daemon=True).start()

    try:
        curses.wrapper(lambda s: draw_dashboard(s, args))
    except KeyboardInterrupt:
        pass

    # Final summary
    print(f"\n  Total packets : {total_pkts[0]}")
    print(f"  Total bytes   : {total_bytes[0]:,}")
    print(f"  IDS alerts    : {ids_total[0]}")
    print(f"  Duration      : {time.time()-start_ts[0]:.1f}s")
    print("\n  Top protocols:")
    for pr, cnt in sorted(
            proto_counts.items(), key=lambda x: -x[1])[:8]:
        print(f"    {pr:<10} {cnt}")
    if ids_by_sig:
        print("\n  Top IDS signatures:")
        for sig, cnt in sorted(
                ids_by_sig.items(), key=lambda x: -x[1])[:5]:
            print(f"    [{cnt}x] {sig}")

if __name__ == "__main__":
    main()

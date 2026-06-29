
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from datetime import datetime
import threading
import time
import os
SYN_FLOOD_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 15
BRUTE_FORCE_THRESHOLD = 20
BRUTE_FORCE_PORTS = [22, 23, 3389, 21, 5900]
LOG_FILE = "ids_alerts.log"
syn_count = defaultdict(int)
port_scan_tracker = defaultdict(set)
brute_force_count = defaultdict(int)
blocked_ips = set()
graph_data = {
    "time_labels":   [],
    "total_packets": [],
    "syn_flood":     [],
    "port_scan":     [],
    "brute_force":   [],
}

alert_count   = {"syn": 0, "scan": 0, "brute": 0}
packet_totals = {"count": 0}

lock = threading.Lock()

def log_alert(attack_type, src_ip, detail):
    """Print a colored alert to terminal and write to log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] ALERT | {attack_type:20s} | SRC: {src_ip:18s} | {detail}"

    # Terminal colors
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    RESET  = "\033[0m"

    if "SYN" in attack_type:
        print(RED + msg + RESET)
    else:
        print(YELLOW + msg + RESET)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")
def block_ip(ip, reason):
    """
    Automated response: block an IP address.
    On Linux this uses iptables. On other systems it just logs.
    """
    if ip in blocked_ips:
        return  
    blocked_ips.add(ip)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = f"[{timestamp}] RESPONSE | BLOCKED IP: {ip} | Reason: {reason}"

    GREEN = "\033[92m"
    RESET = "\033[0m"
    print(GREEN + msg + RESET)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")
def detect_syn_flood(src_ip):
    """
    SYN Flood Detection:
    If one IP sends too many SYN packets, it's likely a DoS attack.
    SYN packets are the first step of TCP handshake.
    An attacker sends thousands but never completes the handshake.
    """
    with lock:
        syn_count[src_ip] += 1
        count = syn_count[src_ip]
    if count == SYN_FLOOD_THRESHOLD:
        detail = f"Sent {count} SYN packets — possible DoS/SYN Flood"
        log_alert("SYN FLOOD", src_ip, detail)
        block_ip(src_ip, "SYN Flood")
        with lock:
            alert_count["syn"] += 1
def detect_port_scan(src_ip, dst_port):
    """
    Port Scan Detection:
    If one IP probes many different ports quickly,
    it is likely scanning for open services to exploit.
    """
    with lock:
        port_scan_tracker[src_ip].add(dst_port)
        num_ports = len(port_scan_tracker[src_ip])

    if num_ports == PORT_SCAN_THRESHOLD:
        detail = f"Probed {num_ports} ports — possible Port Scan"
        log_alert("PORT SCAN", src_ip, detail)
        block_ip(src_ip, "Port Scan")
        with lock:
            alert_count["scan"] += 1
def detect_brute_force(src_ip, dst_port):
    """
    Brute Force Detection:
    Repeated connection attempts to login ports (SSH=22, RDP=3389, etc.)
    suggests an attacker is trying many passwords.
    """
    if dst_port not in BRUTE_FORCE_PORTS:
        return

    with lock:
        brute_force_count[src_ip] += 1
        count = brute_force_count[src_ip]

    if count == BRUTE_FORCE_THRESHOLD:
        service = {22: "SSH", 23: "Telnet", 3389: "RDP",
                   21: "FTP", 5900: "VNC"}.get(dst_port, str(dst_port))
        detail = f"{count} attempts on port {dst_port} ({service}) — Brute Force"
        log_alert("BRUTE FORCE", src_ip, detail)
        block_ip(src_ip, f"Brute Force on {service}")
        with lock:
            alert_count["brute"]=+1
def handle_packet(packet):
    """
    This function is called automatically by scapy
    for every packet that passes through the network interface.
    It extracts key fields and passes them to each detector.
    """
    if not packet.haslayer(IP):
        return
    src_ip = packet[IP].src  
    dst_ip = packet[IP].dst  
    with lock:
        packet_totals["count"] += 1
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags
        if flags == 0x02:  
            detect_syn_flood(src_ip)
        detect_port_scan(src_ip, dst_port)
        detect_brute_force(src_ip, dst_port)
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        detect_port_scan(src_ip, dst_port)
    elif packet.haslayer(ICMP):
        detect_port_scan(src_ip, 0)  
def reset_counters():
    """
    Reset all per-IP counters every 60 seconds.
    This prevents false positives from legitimate heavy traffic.
    Only blocked IPs are kept permanently.
    """
    while True:
        time.sleep(60)
        with lock:
            syn_count.clear()
            port_scan_tracker.clear()
            brute_force_count.clear()
        print("\n[INFO] Counters reset for new detection window.\n")
fig, axes = plt.subplots(2, 2, figsize=(12, 7))
fig.suptitle("Network Intrusion Detection System — Live Monitor",
             fontsize=13, fontweight="bold")
fig.patch.set_facecolor("#0d1117")
for ax in axes.flat:
    ax.set_facecolor("#161b22")
    ax.tick_params(colors="white")
    ax.title.set_color("white")
def update_graph(frame):
    """Called by matplotlib every second to refresh all 4 charts."""
    now = datetime.now().strftime("%H:%M:%S")
    with lock:
        total   = packet_totals["count"]
        syn_a   = alert_count["syn"]
        scan_a  = alert_count["scan"]
        brute_a = alert_count["brute"]
    graph_data["time_labels"].append(now)
    graph_data["total_packets"].append(total)
    graph_data["syn_flood"].append(syn_a)
    graph_data["port_scan"].append(scan_a)
    graph_data["brute_force"].append(brute_a)
    # Keep only last 30 data points
    for key in graph_data:
        if len(graph_data[key]) > 30:
            graph_data[key].pop(0)
    labels = graph_data["time_labels"]
    ax = axes[0][0]
    ax.clear()
    ax.set_facecolor("#161b22")
    ax.plot(labels, graph_data["total_packets"],
            color="#58a6ff", linewidth=2)
    ax.set_title("Total Packets Captured", color="white")
    ax.set_ylabel("Count", color="white")
    ax.tick_params(colors="white", labelbottom=False)
    ax = axes[0][1]
    ax.clear()
    ax.set_facecolor("#161b22")
    bars = ax.bar(["SYN Flood", "Port Scan", "Brute Force"],
                  [syn_a, scan_a, brute_a],
                  color=["#f85149", "#e3b341", "#58a6ff"])
    ax.set_title("Alerts by Attack Type", color="white")
    ax.set_ylabel("Alerts", color="white")
    ax.tick_params(colors="white")
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.05,
                    str(int(h)), ha="center", color="white", fontsize=10)
    ax = axes[1][0]
    ax.clear()
    ax.set_facecolor("#161b22")
    ax.fill_between(range(len(graph_data["syn_flood"])),
                    graph_data["syn_flood"], color="#f85149", alpha=0.6)
    ax.plot(graph_data["syn_flood"], color="#f85149", linewidth=2)
    ax.set_title("SYN Flood Alerts Over Time", color="white")
    ax.tick_params(colors="white", labelbottom=False)
    ax = axes[1][1]
    ax.clear()
    ax.set_facecolor("#161b22")
    ax.plot(graph_data["port_scan"],   color="#e3b341",
            linewidth=2, label="Port Scan")
    ax.plot(graph_data["brute_force"], color="#58a6ff",
            linewidth=2, label="Brute Force")
    ax.set_title("Port Scan & Brute Force Over Time", color="white")
    ax.tick_params(colors="white", labelbottom=False)
    legend = ax.legend(facecolor="#0d1117", labelcolor="white", fontsize=9)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
if __name__ == "__main__":
    print("=" * 60)
    print("  Network Intrusion Detection System (NIDS)")
    print("  CodeAlpha Internship — Task 4")
    print("=" * 60)
    print(f"  SYN Flood threshold  : {SYN_FLOOD_THRESHOLD} pkts/IP")
    print(f"  Port Scan threshold  : {PORT_SCAN_THRESHOLD} ports/IP")
    print(f"  Brute Force threshold: {BRUTE_FORCE_THRESHOLD} attempts/IP")
    print(f"  Log file             : {LOG_FILE}")
    print("=" * 60)
    print("  Starting packet capture... (Press Ctrl+C to stop)\n")
    reset_thread = threading.Thread(target=reset_counters, daemon=True)
    reset_thread.start()
    sniff_thread = threading.Thread(
        target=lambda: sniff(prn=handle_packet, store=False),
        daemon=True
    )
    sniff_thread.start()
    ani = animation.FuncAnimation(fig, update_graph, interval=1000, cache_frame_data=False)
    plt.show()
import random
import time
from typing import Dict, Any, List
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

# --- Configuration Constants ---
# Simplified IP ranges for simulation
IP_RANGE = ["192.168.1.", "10.0.0.", "172.16.0."]
# Common ports and banned/sensitive ports
COMMON_PORTS = [80, 443, 21, 22, 23, 25, 110, 3389, 8080]
SENSITIVE_PORTS = [23, 3389, 5900]  # Telnet, RDP, VNC
BANNED_PORTS = [25565, 27015] # Example "banned" gaming/P2P ports
PROTOCOLS = ["TCP", "UDP", "ICMP"]
FLAGS = ["SYN", "ACK", "SYN/ACK", "FIN", "PSH", "RST"]

class Packet:
    """
    Represents a simplified TCP/IP packet for simulation.
    """
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                 protocol: str, payload_size: int, flags: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.payload_size = payload_size
        self.flags = flags
        self.timestamp = time.time()

    def __repr__(self):
        return (f"[{self.protocol}] {self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} | Flags: {self.flags} | Size: {self.payload_size} bytes")

class IntrusionDetector:
    """
    Simulates a simplified Intrusion Detection System (IDS).
    Maintains state to detect multi-packet attacks like port scanning.
    """
    def __init__(self):
        # Stores history for scanning detection: {src_ip: {dst_port_set}}
        self.scan_history: Dict[str, set] = {}
        # Configuration for rules
        self.SCAN_THRESHOLD = 5         # Number of unique ports hit from one IP
        self.LARGE_PAYLOAD_LIMIT = 5000 # Max normal payload size (bytes)
        self.SUSPICIOUS_PORTS = SENSITIVE_PORTS + BANNED_PORTS

    def _check_port_scan(self, packet: Packet, report: List[str]) -> bool:
        """Rule 1: Detects a simple port scan based on unique destination ports."""
        is_suspicious = False
        
        # Initialize history for the source IP if not present
        if packet.src_ip not in self.scan_history:
            self.scan_history[packet.src_ip] = set()

        # Add the current destination port
        self.scan_history[packet.src_ip].add(packet.dst_port)

        # Check if the number of unique ports exceeds the threshold
        if len(self.scan_history[packet.src_ip]) > self.SCAN_THRESHOLD:
            # We only clear the history if we report it, to keep tracking scans
            report.append(f"CRITICAL: Port Scan Detected! {packet.src_ip} targeted {len(self.scan_history[packet.src_ip])} unique ports.")
            is_suspicious = True
        
        return is_suspicious

    def _check_payload_size(self, packet: Packet, report: List[str]) -> bool:
        """Rule 2: Detects abnormally large packets (potential DDoS or data exfil)."""
        if packet.payload_size > self.LARGE_PAYLOAD_LIMIT:
            report.append(f"ALERT: Abnormally large payload ({packet.payload_size} bytes). Potential Flood or Bulk Transfer.")
            return True
        return False

    def _check_banned_ports(self, packet: Packet, report: List[str]) -> bool:
        """Rule 3: Detects traffic on known suspicious or banned ports."""
        if packet.dst_port in self.SUSPICIOUS_PORTS:
            # Differentiate the severity based on the port
            severity = "CRITICAL" if packet.dst_port == 23 else "WARNING"
            report.append(f"{severity}: Traffic to suspicious/banned port {packet.dst_port}.")
            return True
        return False
    
    def _check_syn_flood(self, packet: Packet, report: List[str]) -> bool:
        """Rule 4: Detects a SYN-only packet (part of a SYN flood, simplified)."""
        if packet.flags == "SYN" and packet.protocol == "TCP" and packet.dst_port == 80:
             # In a real IDS, we'd track SYN counts vs. SYN/ACK counts.
             # Here, we just flag a SYN attempt to a common web server.
             report.append("WARNING: Standalone TCP SYN packet detected on port 80. Could be a probe or SYN flood start.")
             return True
        return False

    def analyze_packet(self, packet: Packet) -> Dict[str, Any]:
        """
        Analyzes a single packet against all security rules.
        """
        detection_report: List[str] = []
        is_suspicious = False
        
        # Run all checks
        if self._check_port_scan(packet, detection_report):
            is_suspicious = True
        
        if self._check_payload_size(packet, detection_report):
            is_suspicious = True
            
        if self._check_banned_ports(packet, detection_report):
            is_suspicious = True

        if self._check_syn_flood(packet, detection_report):
            is_suspicious = True

        status = "SUSPICIOUS" if is_suspicious else "NORMAL"
        
        return {
            "status": status,
            "report": detection_report
        }

# --- Packet Generation Functions ---

def generate_ip(prefix: str) -> str:
    """Generates a random, simulated IP address."""
    return prefix + str(random.randint(1, 254))

def create_normal_packet() -> Packet:
    """Creates a benign, random packet."""
    prefix = random.choice(IP_RANGE)
    src_ip = generate_ip(prefix)
    dst_ip = generate_ip(random.choice(IP_RANGE))
    
    # Use common ports and small, normal payloads
    src_port = random.randint(49152, 65535) # High port
    dst_port = random.choice(COMMON_PORTS)
    
    protocol = "TCP" if dst_port in [80, 443, 21, 22, 25] else random.choice(PROTOCOLS)
    
    payload_size = random.randint(64, 1500)
    flags = random.choice(["ACK", "SYN/ACK", "PSH/ACK"])
    
    return Packet(src_ip, dst_ip, src_port, dst_port, protocol, payload_size, flags)

def create_suspicious_packet(attack_type: str) -> Packet:
    """Creates a deliberately malicious packet based on attack type."""
    if attack_type == "PortScan":
        # Attacker IP is fixed for the scan sequence
        src_ip = "192.168.1.100" 
        dst_ip = "10.0.0.5" # Target IP is fixed
        src_port = random.randint(50000, 60000)
        # Scan random, unique ports
        dst_port = random.randint(1, 10000)
        return Packet(src_ip, dst_ip, src_port, dst_port, "TCP", 64, "SYN")
    
    elif attack_type == "DDoS_Flood":
        src_ip = generate_ip(random.choice(IP_RANGE))
        dst_ip = "10.0.0.1" # A specific target
        src_port = random.randint(50000, 60000)
        dst_port = random.choice([80, 443])
        # Very large payload
        payload_size = random.randint(6000, 15000) 
        return Packet(src_ip, dst_ip, src_port, dst_port, "UDP", payload_size, "N/A")

    elif attack_type == "BannedPort":
        src_ip = generate_ip(random.choice(IP_RANGE))
        dst_ip = "10.0.0.2"
        src_port = random.randint(50000, 60000)
        dst_port = random.choice(SENSITIVE_PORTS) # Telnet or RDP
        return Packet(src_ip, dst_ip, src_port, dst_port, "TCP", 256, "SYN")
        
    return create_normal_packet()

# --- Simulation Logic ---

def simulate_traffic(num_packets: int):
    """
    Simulates network traffic and runs it through the Intrusion Detector.
    """
    detector = IntrusionDetector()
    packets_processed = 0
    suspicious_count = 0
    print("--- Starting Network Security Simulation ---")
    print(f"IDS Rules loaded: Scan threshold={detector.SCAN_THRESHOLD} unique ports, Max Payload={detector.LARGE_PAYLOAD_LIMIT} bytes.\n")
    
    # Define a sequence of packets to ensure we trigger the rules
    traffic_sequence = []
    
    # 1. Normal traffic (60% of total)
    normal_count = int(num_packets * 0.6)
    traffic_sequence.extend([create_normal_packet() for _ in range(normal_count)])
    
    # 2. Port Scan sequence (10 packets, 5 over threshold)
    for _ in range(detector.SCAN_THRESHOLD + 5):
        traffic_sequence.append(create_suspicious_packet("PortScan"))
        
    # 3. DDoS/Flood attempts
    traffic_sequence.append(create_suspicious_packet("DDoS_Flood"))
    traffic_sequence.append(create_suspicious_packet("DDoS_Flood"))
    
    # 4. Banned Port traffic
    traffic_sequence.append(create_suspicious_packet("BannedPort"))
    
    # Fill remaining with random normal traffic
    while len(traffic_sequence) < num_packets:
        traffic_sequence.append(create_normal_packet())
        
    # Shuffle the sequence to mix normal and malicious traffic
    random.shuffle(traffic_sequence)
    
    for packet in traffic_sequence:
        packets_processed += 1
        analysis = detector.analyze_packet(packet)
        
        # Simple console output formatting
        if analysis["status"] == "NORMAL":
            # Only print normal traffic occasionally to avoid excessive output
            if random.random() < 0.1: 
                print(f"[{packets_processed:03d}] [NORMAL] {packet}")
        
        elif analysis["status"] == "SUSPICIOUS":
            suspicious_count += 1
            print("\n" + "="*80)
            print(f"[{packets_processed:03d}] !!! DETECTED SUSPICIOUS TRAFFIC !!!")
            print(f"Packet: {packet}")
            for report_line in analysis["report"]:
                print(f"  -> {report_line}")
            print("="*80 + "\n")
            
        # time.sleep(0.01) # Uncomment to slow down the simulation

    print("\n--- Simulation Summary ---")
    print(f"Total Packets Processed: {packets_processed}")
    print(f"Suspicious Incidents Reported: {suspicious_count}")
    print(f"Detection Rate: {suspicious_count / packets_processed * 100:.2f}% (of all processed packets)")
    print("--------------------------")

def run_simulation_gui():
    def start_simulation():
        # Clear previous results
        for widget in results_frame.winfo_children():
            widget.destroy()
        suspicious_packets.clear()
        # Run simulation
        detector = IntrusionDetector()
        packets_processed = 0
        suspicious_count = 0
        traffic_sequence = []
        normal_count = int(100 * 0.6)
        traffic_sequence.extend([create_normal_packet() for _ in range(normal_count)])
        for _ in range(detector.SCAN_THRESHOLD + 5):
            traffic_sequence.append(create_suspicious_packet("PortScan"))
        traffic_sequence.append(create_suspicious_packet("DDoS_Flood"))
        traffic_sequence.append(create_suspicious_packet("DDoS_Flood"))
        traffic_sequence.append(create_suspicious_packet("BannedPort"))
        while len(traffic_sequence) < 100:
            traffic_sequence.append(create_normal_packet())
        random.shuffle(traffic_sequence)
        for packet in traffic_sequence:
            packets_processed += 1
            analysis = detector.analyze_packet(packet)
            if analysis["status"] == "SUSPICIOUS":
                suspicious_count += 1
                suspicious_packets.append((packets_processed, packet, analysis["report"]))
        # Update summary labels
        total_label.config(text=f"Total Packets Processed: {packets_processed}")
        suspicious_label.config(text=f"Suspicious Incidents Reported: {suspicious_count}")
        rate_label.config(text=f"Detection Rate: {suspicious_count / packets_processed * 100:.2f}%")
        # Populate suspicious packets list
        for idx, (num, packet, report) in enumerate(suspicious_packets):
            packet_frame = tk.Frame(results_frame, bd=1, relief=tk.RIDGE, padx=5, pady=5)
            packet_frame.pack(fill=tk.X, padx=2, pady=2)
            tk.Label(packet_frame, text=f"[{num:03d}] {packet}", font=("Arial", 10, "bold"), fg="red").pack(anchor=tk.W)
            for line in report:
                tk.Label(packet_frame, text=f"  -> {line}", font=("Arial", 9), fg="black").pack(anchor=tk.W)
    # Main window
    root = tk.Tk()
    root.title("Network Security Simulation Output")
    # Summary section
    summary_frame = tk.Frame(root)
    summary_frame.pack(fill=tk.X, padx=10, pady=5)
    total_label = tk.Label(summary_frame, text="Total Packets Processed: 0", font=("Arial", 12))
    total_label.pack(side=tk.LEFT, padx=5)
    suspicious_label = tk.Label(summary_frame, text="Suspicious Incidents Reported: 0", font=("Arial", 12))
    suspicious_label.pack(side=tk.LEFT, padx=5)
    rate_label = tk.Label(summary_frame, text="Detection Rate: 0.00%", font=("Arial", 12))
    rate_label.pack(side=tk.LEFT, padx=5)
    # Results section
    results_canvas = tk.Canvas(root, width=900, height=500)
    results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)
    scrollbar = tk.Scrollbar(root, orient="vertical", command=results_canvas.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    results_canvas.configure(yscrollcommand=scrollbar.set)
    results_frame = tk.Frame(results_canvas)
    results_canvas.create_window((0,0), window=results_frame, anchor='nw')
    def on_configure(event):
        results_canvas.configure(scrollregion=results_canvas.bbox('all'))
    results_frame.bind('<Configure>', on_configure)
    suspicious_packets = []
    # Start button
    start_button = tk.Button(root, text="Run Simulation", command=start_simulation, font=("Arial", 12, "bold"), bg="#4CAF50", fg="white")
    start_button.pack(pady=5)
    root.mainloop()

if __name__ == "__main__":
    run_simulation_gui()

# Network Security & Intrusion Detection Simulator

A Python-based network security simulation tool that demonstrates intrusion detection capabilities through simulated TCP/IP traffic analysis and real-time threat detection.

## 🚀 Features

- **Network Traffic Simulation**: Generates realistic TCP/IP packets with configurable parameters
- **Multi-Rule Intrusion Detection**: Implements signature-based detection for various attack patterns
- **Real-Time Analysis**: Processes network packets and identifies threats instantly
- **Interactive GUI**: User-friendly interface built with Tkinter for visualization
- **Comprehensive Reporting**: Detailed incident reports with threat severity classification

## 🛡️ Detection Capabilities

### Attack Types Detected
- **Port Scanning**: Identifies reconnaissance attempts across multiple ports
- **DDoS/Flood Attacks**: Detects abnormally large payloads and volumetric attacks
- **Suspicious Port Access**: Monitors access to sensitive/banned ports (Telnet, RDP, VNC)
- **SYN Flood Detection**: Identifies potential TCP SYN flood attack patterns

### Security Rules Engine
- Configurable detection thresholds
- Stateful connection tracking
- Multi-severity alert classification (CRITICAL, WARNING, ALERT)
- Historical attack pattern analysis

## 📋 Prerequisites

- Python 3.7 or higher
- Tkinter (usually included with Python)
- Standard library modules: `random`, `time`, `typing`

## 🔧 Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd network-security-simulator
   ```

2. **Verify Python installation:**
   ```bash
   python --version
   # Should display Python 3.7+
   ```

3. **Run the simulator:**
   ```bash
   python main.py
   ```

## 🎮 Usage

### GUI Mode (Recommended)
1. Launch the application: `python main.py`
2. Click **"Run Simulation"** button
3. View real-time detection results in the scrollable panel
4. Analyze summary statistics and incident reports

### Console Mode
```python
from main import simulate_traffic

# Run simulation with 1000 packets
simulate_traffic(1000)
```

### Custom Configuration
```python
from main import IntrusionDetector

# Create detector with custom thresholds
detector = IntrusionDetector()
detector.SCAN_THRESHOLD = 10        # Ports before flagging scan
detector.LARGE_PAYLOAD_LIMIT = 8000 # Maximum normal payload size
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Packet        │    │   Intrusion      │    │   GUI           │
│   Generator     │───▶│   Detector       │───▶│   Interface     │
│                 │    │   (IDS Engine)   │    │   (Tkinter)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Core Components

- **Packet Class**: Simulates TCP/IP packet structure with network and transport layer data
- **IntrusionDetector Class**: Implements multi-rule detection engine with stateful analysis
- **Traffic Generator**: Creates realistic normal and malicious network traffic patterns
- **GUI Interface**: Provides interactive visualization and real-time monitoring

## 📊 Sample Output

```
[001] [NORMAL] [TCP] 192.168.1.45:52341 -> 10.0.0.12:443 | Flags: ACK | Size: 892 bytes

================================================================================
[015] !!! DETECTED SUSPICIOUS TRAFFIC !!!
Packet: [TCP] 192.168.1.100:51234 -> 10.0.0.5:8080 | Flags: SYN | Size: 64 bytes
  -> CRITICAL: Port Scan Detected! 192.168.1.100 targeted 6 unique ports.
================================================================================

--- Simulation Summary ---
Total Packets Processed: 100
Suspicious Incidents Reported: 12
Detection Rate: 12.00%
```

## ⚙️ Configuration

### Network Parameters
```python
IP_RANGE = ["192.168.1.", "10.0.0.", "172.16.0."]
COMMON_PORTS = [80, 443, 21, 22, 23, 25, 110, 3389, 8080]
SENSITIVE_PORTS = [23, 3389, 5900]  # Telnet, RDP, VNC
BANNED_PORTS = [25565, 27015]       # Gaming/P2P ports
```

### Detection Thresholds
```python
SCAN_THRESHOLD = 5         # Unique ports for scan detection
LARGE_PAYLOAD_LIMIT = 5000 # Maximum normal payload (bytes)
```

## 🧪 Testing

Run built-in tests to verify detection accuracy:

```python
# Test port scan detection
from main import create_suspicious_packet, IntrusionDetector

detector = IntrusionDetector()
for _ in range(10):
    packet = create_suspicious_packet("PortScan")
    result = detector.analyze_packet(packet)
    print(f"Detection: {result['status']}")
```

## 📈 Performance Metrics

- **Throughput**: ~1,000 packets/second (single-threaded)
- **Memory Usage**: ~10MB for 10,000 packet simulation
- **Detection Latency**: <1ms per packet analysis
- **GUI Responsiveness**: Real-time updates with smooth scrolling

## 🔍 Understanding the Code

### Key Classes
- `Packet`: Represents network packet with TCP/IP attributes
- `IntrusionDetector`: Core IDS engine with multiple detection rules
- `simulate_traffic()`: Main simulation orchestrator
- `run_simulation_gui()`: GUI application controller

### Detection Algorithms
1. **Port Scan**: Tracks unique destination ports per source IP
2. **Payload Analysis**: Identifies abnormally large packet sizes
3. **Port Monitoring**: Flags access to sensitive/banned ports
4. **Protocol Analysis**: Detects suspicious TCP flag combinations

## 🛠️ Customization

### Adding New Detection Rules
```python
def _check_custom_rule(self, packet, report):
    """Custom detection rule implementation"""
    if your_condition:
        report.append("ALERT: Custom threat detected!")
        return True
    return False

# Add to analyze_packet() method
if self._check_custom_rule(packet, detection_report):
    is_suspicious = True
```

### Custom Traffic Patterns
```python
def create_custom_attack():
    """Generate custom attack packets"""
    return Packet(
        src_ip="attacker.ip",
        dst_ip="target.ip", 
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        payload_size=1024,
        flags="SYN"
    )
```

## 📚 Educational Value

This simulator demonstrates:
- **Network Security Concepts**: IDS principles, attack patterns, threat detection
- **Python Programming**: OOP design, GUI development, data structures
- **Algorithm Implementation**: Pattern matching, statistical analysis, state management
- **Software Architecture**: Modular design, separation of concerns, extensibility

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional attack pattern detection
- Performance optimization
- Enhanced GUI features
- Network protocol parsing
- Machine learning integration

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🎯 Use Cases

- **Education**: Learn network security and IDS concepts
- **Training**: Practice threat detection and analysis
- **Demonstration**: Showcase security monitoring capabilities
- **Research**: Test new detection algorithms and patterns
- **Portfolio**: Demonstrate programming and security skills

## 📞 Support

For questions, issues, or suggestions:
- Create an issue in the repository
- Review the documentation in `PROJECT_INTERVIEW_GUIDE.md`
- Check the detailed explanation in `network_simulator_explained.md`

---

**Note**: This is a simulation tool for educational purposes. For production network security, use enterprise-grade IDS/IPS solutions like Snort, Suricata, or commercial alternatives.
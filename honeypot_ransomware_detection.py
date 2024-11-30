import os
import time
import psutil  # For detecting active network interfaces
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import scapy.all as scapy

# Class for monitoring filesystem activities
class RansomwareFileMonitor(FileSystemEventHandler):
    def __init__(self, watch_directory):
        self.watch_directory = watch_directory

    def on_modified(self, event):
        if not event.is_directory:
            print(f"[FILE MODIFIED] {event.src_path}")
            self.analyze_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            print(f"[FILE CREATED] {event.src_path}")
            self.analyze_file(event.src_path)

    def analyze_file(self, file_path):
        try:
            file_size = os.path.getsize(file_path)
            # Basic heuristic: File size above 1MB might be suspicious
            if file_size > 1048576:  # 1MB
                print(f"[ALERT] Large file detected: {file_path} (Size: {file_size} bytes)")
                self.log_event(file_path, "Large file created/modified")
        except Exception as e:
            print(f"[ERROR] Could not analyze file: {file_path} - {e}")

    def log_event(self, file_path, message):
        try:
            with open("ransomware_activity.log", "a") as log_file:
                log_file.write(f"{time.ctime()} - {file_path} - {message}\n")
        except Exception as e:
            print(f"[ERROR] Could not log event: {e}")

# Function to monitor network traffic
def monitor_network_traffic(interface):
    try:
        print(f"[*] Monitoring network traffic on interface {interface}...")
        scapy.sniff(iface=interface, prn=process_packet, store=0)
    except Exception as e:
        print(f"[ERROR] Network monitoring failed: {e}")

# Process captured packets and analyze for suspicious patterns
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        packet_size = len(packet)
        protocol = packet[scapy.IP].proto
        # Heuristic: Alert if packet size is unusually large
        if packet_size > 1500:  # Typical MTU size
            print(f"[NETWORK ALERT] Large packet detected! Size: {packet_size}, Protocol: {protocol}, Source: {src_ip}, Destination: {dst_ip}")
            log_network_event(src_ip, dst_ip, packet_size, protocol)

# Log malicious network events
def log_network_event(src_ip, dst_ip, packet_size, protocol):
    try:
        with open("network_activity.log", "a") as log_file:
            log_file.write(f"{time.ctime()} - Large Packet - Source: {src_ip}, Destination: {dst_ip}, Size: {packet_size}, Protocol: {protocol}\n")
    except Exception as e:
        print(f"[ERROR] Could not log network event: {e}")

# Detect the active network interface
def get_active_interface():
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        if interface.startswith(("eth", "wlan")):  # Look for Ethernet or Wireless interfaces
            stats = psutil.net_if_stats()
            if interface in stats and stats[interface].isup:  # Check if the interface is up
                return interface
    return None

# Main function to start monitoring
def start_monitoring(directory):
    # Start filesystem monitoring
    if not os.path.exists(directory):
        print(f"[ERROR] Directory {directory} does not exist!")
        return

    observer = Observer()
    event_handler = RansomwareFileMonitor(directory)
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()

    print(f"[*] Monitoring filesystem changes in {directory}...")
    
    # Detect active network interface
    active_interface = get_active_interface()
    if not active_interface:
        print("[ERROR] No active network interface found!")
        observer.stop()
        return

    print(f"[*] Active network interface detected: {active_interface}")

    # Start network monitoring
    try:
        monitor_network_traffic(active_interface)
    except KeyboardInterrupt:
        print("[*] Stopping monitoring...")
        observer.stop()
    except Exception as e:
        print(f"[ERROR] Monitoring interrupted: {e}")

    observer.join()

if __name__ == "__main__":
    # Directory to monitor
    watch_directory = "/home/huzaifa/Desktop/HoneyPot_Testing/Testing_HoneyPot"
    
    # Start monitoring
    start_monitoring(watch_directory)


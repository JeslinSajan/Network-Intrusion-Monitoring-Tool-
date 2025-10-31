#!/usr/bin/env python3
"""
Network Intrusion Detection System (IDS)

This script implements a simple network intrusion detection system that monitors
network traffic for suspicious patterns and potential attacks.
"""

import argparse
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from scapy.all import *
from colorama import init, Fore, Style

# Initialize colorama for colored console output
init()

class NetworkIDS:
    def __init__(self, interface=None, log_file='intrusion_log.csv'):
        """Initialize the Network IDS with default values."""
        self.interface = interface or conf.iface
        self.log_file = log_file
        self.running = False
        
        # Statistics and tracking
        self.packet_count = 0
        self.alerts = []
        self.syn_count = defaultdict(int)
        self.port_scan_attempts = defaultdict(int)
        
        # Thresholds for detection (can be moved to config)
        self.SYN_FLOOD_THRESHOLD = 100  # Max SYN packets per second
        self.PORT_SCAN_THRESHOLD = 20   # Max connection attempts to different ports
        
        # Initialize logging
        self.setup_logging()
        
    def setup_logging(self):
        """Set up logging to file and console."""
        # Create logs directory if it doesn't exist
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'ids.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('NetworkIDS')
        
    def packet_callback(self, packet):
        """Process each captured packet."""
        if not self.running:
            return
            
        self.packet_count += 1
        
        try:
            if IP in packet and TCP in packet:
                self.analyze_tcp_packet(packet)
                
            # Add more protocol handlers here (UDP, ICMP, etc.)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def analyze_tcp_packet(self, packet):
        """Analyze TCP packets for suspicious patterns."""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        
        # Check for SYN flood
        if flags & 0x02:  # SYN flag is set
            self.syn_count[src_ip] += 1
            if self.syn_count[src_ip] > self.SYN_FLOOD_THRESHOLD:
                self.log_alert(
                    "SYN Flood", 
                    src_ip, 
                    dst_ip, 
                    f"Excessive SYN packets ({self.syn_count[src_ip]}) from {src_ip}"
                )
        
        # Check for port scanning
        if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
            self.port_scan_attempts[(src_ip, dst_port)] += 1
            if self.port_scan_attempts[(src_ip, dst_port)] > self.PORT_SCAN_THRESHOLD:
                self.log_alert(
                    "Port Scan", 
                    src_ip, 
                    dst_ip, 
                    f"Multiple connection attempts to port {dst_port} from {src_ip}"
                )
    
    def log_alert(self, alert_type, src_ip, dst_ip, description):
        """Log security alerts to file and console."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp},{alert_type},{src_ip},{dst_ip},\"{description}\"\n"
        
        # Print to console with colors
        print(f"{Fore.RED}[!] ALERT: {alert_type}{Style.RESET_ALL}")
        print(f"    Source: {src_ip}")
        print(f"    Target: {dst_ip}")
        print(f"    Details: {description}\n")
        
        # Save to log file
        with open(self.log_file, 'a') as f:
            if f.tell() == 0:  # Write header if file is empty
                f.write("timestamp,alert_type,source_ip,destination_ip,description\n")
            f.write(log_entry)
        
        self.alerts.append({
            'timestamp': timestamp,
            'type': alert_type,
            'source': src_ip,
            'destination': dst_ip,
            'description': description
        })
    
    def start(self):
        """Start the IDS and begin monitoring network traffic."""
        self.running = True
        self.logger.info(f"Starting Network IDS on interface {self.interface}")
        
        try:
            # Start sniffing in the background
            sniff(iface=self.interface, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
            self.stop()
    
    def stop(self):
        """Stop the IDS and clean up resources."""
        self.running = False
        self.logger.info("Network IDS stopped")
        self.logger.info(f"Total packets analyzed: {self.packet_count}")
        self.logger.info(f"Total alerts generated: {len(self.alerts)}")
        sys.exit(0)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', help='Network interface to monitor', default=None)
    parser.add_argument('-l', '--log', help='Log file for alerts', default='intrusion_log.csv')
    return parser.parse_args()

def main():
    """Main entry point for the IDS."""
    args = parse_arguments()
    
    # Create IDS instance
    try:
        ids = NetworkIDS(interface=args.interface, log_file=args.log)
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\nShutting down IDS...")
            ids.stop()
            
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start the IDS
        print(f"{Fore.GREEN}[*] Starting Network IDS on interface {ids.interface}{Style.RESET_ALL}")
        print("Press Ctrl+C to stop monitoring...\n")
        
        ids.start()
        
    except PermissionError:
        print(f"{Fore.RED}[!] Error: Permission denied. Try running with sudo.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()

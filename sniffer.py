import logging as log
import pyshark 
import sys 
import os 
import csv
import subprocess
import threading
import time
from datetime import datetime

from pkt_processor import PacketProcessor
from flows import FlowAggregator

# Configure logging
log.basicConfig(
    level=log.INFO,
    format="[%(asctime)s] [%(levelname)s] --> %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

class Sniffer:
    def __init__(self, iface: str = None, csv_file: str = "network_flows.csv"):
        self.iface = iface
        self.csv_file = csv_file
        
        # Check for tshark
        self.check_tshark_installation()
        
        # Setup CSV file for flow data
        self.csv_file_obj = open(csv_file, 'w', newline='')
        self.csv_writer = csv.writer(self.csv_file_obj)
        
        # Initialize flow aggregator with CSV writer
        self.flow_aggregator = FlowAggregator(self.csv_writer)
        
        # Initialize processor with flow aggregator
        self.processor = PacketProcessor(self.flow_aggregator)
        
        if not self.iface:
            self.select_interface()
        
        self.start()
    
    def check_tshark_installation(self):
        """Check if tshark is installed and accessible"""
        try:
            result = subprocess.run(['which', 'tshark'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                tshark_path = result.stdout.strip()
                log.info(f"TShark found at: {tshark_path}")
                
                # Get version
                version_result = subprocess.run(['tshark', '--version'], 
                                              capture_output=True, text=True)
                if version_result.returncode == 0:
                    version_line = version_result.stdout.split('\n')[0]
                    log.info(f"TShark version: {version_line}")
                return True
            else:
                log.error("TShark not found!")
                return False
        except Exception as e:
            log.error(f"Error checking tshark: {e}")
            return False
    
    def get_interfaces_simple(self):
        """Get interfaces using tshark command directly"""
        try:
            result = subprocess.run(['tshark', '-D'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.strip().split('\n'):
                    if line and '.' in line:
                        # Format: "1. eth0"
                        iface_name = line.split('. ', 1)[-1]
                        interfaces.append(iface_name)
                return interfaces
        except Exception as e:
            log.error(f"Error getting interfaces: {e}")
        
        # Try alternative method
        try:
            import netifaces
            return netifaces.interfaces()
        except ImportError:
            # Common interface names
            return ['eth0', 'wlan0', 'en0', 'en1', 'Wi-Fi', 'Ethernet', 'lo']
    
    def select_interface(self):
        """Let user select interface"""
        print("\n" + "="*60)
        print("Network Interface Selection")
        print("="*60)
        
        interfaces = self.get_interfaces_simple()
        
        if not interfaces:
            print("Could not detect interfaces automatically.")
            self.iface = input("Enter interface name (e.g., eth0, wlan0): ").strip()
            return
        
        print("\nAvailable interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface}")
        
        print(f"  {len(interfaces)+1}. Enter custom interface")
        
        while True:
            try:
                choice = input(f"\nSelect interface (1-{len(interfaces)+1}): ").strip()
                
                if choice.isdigit():
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(interfaces):
                        self.iface = interfaces[choice_num-1]
                        break
                    elif choice_num == len(interfaces) + 1:
                        self.iface = input("Enter interface name: ").strip()
                        break
                
                print(f"Please enter a number between 1 and {len(interfaces)+1}")
            except KeyboardInterrupt:
                print("\nExiting...")
                sys.exit(0)
        
        print(f"\nSelected interface: {self.iface}")
    
    def test_capture(self):
        """Test if we can capture packets on the interface"""
        print(f"\nTesting interface {self.iface}...")
        
        # Create a simple test capture
        test_cmd = ['timeout', '3', 'tshark', '-i', self.iface, '-c', '5']
        
        try:
            result = subprocess.run(test_cmd, 
                                  capture_output=True, 
                                  text=True,
                                  timeout=5)
            
            if result.returncode == 0 or result.returncode == 124:  # 124 is timeout exit code
                if result.stdout:
                    print(f"✓ Interface test successful!")
                    print(f"  Captured {len(result.stdout.strip().split(chr(10)))} packets")
                    return True
                else:
                    print("⚠ Interface works but no packets captured")
                    print("  (Make sure there's network traffic)")
                    return True
            else:
                print(f"✗ Interface test failed")
                if result.stderr:
                    print(f"  Error: {result.stderr[:100]}")
                return False
                
        except subprocess.TimeoutExpired:
            print("✓ Interface test completed (timeout)")
            return True
        except Exception as e:
            print(f"✗ Interface test error: {e}")
            return False
    
    def start(self):
        """Start packet capture"""
        if not self.test_capture():
            print("\nInterface test failed. Try:")
            print("  1. Different interface")
            print("  2. Running with sudo: sudo python3 sniffer.py")
            print("  3. Check interface name with: tshark -D")
            proceed = input("\nContinue anyway? (y/n): ").lower()
            if proceed != 'y':
                sys.exit(1)
        
        print("\n" + "="*60)
        print("Starting Network Flow Analyzer")
        print("="*60)
        print(f"Interface: {self.iface}")
        print(f"CSV output: {self.csv_file}")
        print("="*60)
        print("Press Ctrl+C to stop\n")
        
        # Start capture in a separate thread
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        # Monitor and display stats
        try:
            while self.capture_thread.is_alive():
                self.display_stats()
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n\nStopping capture...")
        finally:
            self.cleanup()
    
    def _capture_packets(self):
        """Capture packets using pyshark with minimal configuration"""
        try:
            # SIMPLEST configuration - remove all optional parameters
            capture = pyshark.LiveCapture(interface=self.iface)
            
            # Try without use_json first
            log.info(f"Starting capture on {self.iface}")
            
            for packet in capture.sniff_continuously():
                self.processor.process_packet(packet)
                
        except Exception as e:
            log.error(f"Capture error: {e}")
            
            # Try alternative method with tshark directly
            print("\nTrying alternative capture method...")
            self._capture_with_tshark_direct()
    
    def _capture_with_tshark_direct(self):
        """Alternative: Use tshark directly and parse output"""
        try:
            # Use tshark with JSON output
            cmd = [
                'tshark',
                '-i', self.iface,
                '-T', 'json',
                '-l'  # Line buffered
            ]
            
            import json
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            for line in process.stdout:
                try:
                    packet_data = json.loads(line)
                    # Create a simple packet object
                    class SimplePacket:
                        def __init__(self, data):
                            self._data = data
                            self.length = 0
                            if '_source' in data and 'layers' in data['_source']:
                                self.layers = data['_source']['layers']
                                
                                # Try to get length
                                for layer in self.layers.values():
                                    if isinstance(layer, dict) and 'frame' in layer:
                                        if 'frame.len' in layer['frame']:
                                            self.length = int(layer['frame']['frame.len'])
                                    
                    packet = SimplePacket(packet_data)
                    self.processor.process_packet(packet)
                    
                except json.JSONDecodeError:
                    continue
                    
        except Exception as e:
            log.error(f"Direct tshark capture failed: {e}")
    
    def display_stats(self):
        """Display current statistics"""
        active = self.flow_aggregator.flow_count
        completed = self.flow_aggregator.get_completed_flows_count()
        packets = len(self.processor.processed_packets)
        
        print(f"\r[Stats] Packets: {packets} | Active flows: {active} | Completed: {completed}", end="")
    
    def cleanup(self):
        """Cleanup resources"""
        print("\n\n" + "="*60)
        print("Finalizing...")
        
        # Finalize all remaining flows
        active_flows = list(self.flow_aggregator.flows.keys())
        if active_flows:
            print(f"Finalizing {len(active_flows)} active flows...")
            for flow_id in active_flows:
                self.flow_aggregator.finalize_flow(flow_id)
        
        # Close CSV file
        if hasattr(self, 'csv_file_obj'):
            self.csv_file_obj.close()
            print(f"✓ Flow data saved to {self.csv_file}")
        
        print(f"✓ Total packets processed: {len(self.processor.processed_packets)}")
        print(f"✓ Total flows processed: {self.flow_aggregator.get_completed_flows_count()}")
        print("="*60)

if __name__ == "__main__":
    # Simple command-line interface
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Flow Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-o", "--output", default="network_flows.csv", 
                       help="Output CSV file (default: network_flows.csv)")
    parser.add_argument("--sudo", action="store_true", 
                       help="Remind to run with sudo if needed")
    
    args = parser.parse_args()
    
    # Check if we need root
    if os.name == 'posix' and os.geteuid() != 0:
        print("\n⚠  Warning: Not running as root")
        print("Some interfaces may require root privileges.")
        print("If you get permission errors, run with: sudo python3 sniffer.py")
        
        if args.sudo:
            print("\nExiting. Please run with sudo.")
            sys.exit(1)
        
        proceed = input("\nContinue anyway? (y/n): ").lower()
        if proceed != 'y':
            sys.exit(0)
    
    # Start sniffer
    try:
        sniffer = Sniffer(
            iface=args.interface,
            csv_file=args.output
        )
    except KeyboardInterrupt:
        print("\n\nExiting...")
    except Exception as e:
        print(f"\nFatal error: {e}")
        print("\nTroubleshooting:")
        print("1. Install tshark: sudo apt-get install tshark")
        print("2. Run with sudo: sudo python3 sniffer.py")
        print("3. Check interface: tshark -D")
        print("4. Specify interface: python3 sniffer.py -i eth0")
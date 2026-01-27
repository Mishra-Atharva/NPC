import logging as log
import pyshark 
import sys 
import os 
import csv
from datetime import datetime

from pkt_processor import PacketProcessor
from flows import FlowAggregator

if os.name == 'posix' and os.geteuid() != 0:
    print("ERROR: Require root privileges for promiscuous mode!")
    print("Please run with: sudo python3 sniffer.py")
    sys.exit(1)

class Sniffer:
    def __init__(self, iface: str = None, use_json: bool = True, 
                 include_raw: bool = False, output_file: str = "traffic.pcapng",
                 csv_file: str = "network_flows.csv"):
        
        self.iface = iface
        self.use_json = use_json 
        self.include_raw = include_raw 
        self.output_file = output_file
        self.csv_file = csv_file
        
        # Setup CSV file for flow data
        self.csv_file_obj = open(csv_file, 'w', newline='')
        self.csv_writer = csv.writer(self.csv_file_obj)
        
        # Initialize flow aggregator with CSV writer
        self.flow_aggregator = FlowAggregator(self.csv_writer)
        
        # Initialize processor with flow aggregator
        self.processor = PacketProcessor(self.flow_aggregator)
        
        self.find_interface()
    
    def find_interface(self):
        try: 
            print("\nAvailable network interfaces:")
            interfaces = pyshark.LiveCapture().interfaces
            
            for index, iface in enumerate(interfaces):
                print(f"{index+1}: {iface}")
            
            if interfaces:
                option = int(input("\n[*] Select interface (number): "))
                if 1 <= option <= len(interfaces):
                    self.iface = interfaces[option-1]
                    print(f"\nSelected interface: {self.iface}")
                    self.start()
                else:
                    print("Invalid selection!")
                    sys.exit(1)
            else:
                print("No interfaces found!")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    def start(self):
        print(f"\nStarting capture on {self.iface}...")
        print(f"PCAP output: {self.output_file}")
        print(f"CSV output: {self.csv_file}")
        print("Press Ctrl+C to stop\n")
        
        try:
            capture = pyshark.LiveCapture(
                interface=self.iface, 
                use_json=self.use_json,
                include_raw=self.include_raw,
                output_file=self.output_file,
            )
            
            print("Sniffing packets...")
            for packet in capture.sniff_continuously():
                self.processor.process_packet(packet)
                
                # Periodically show stats
                if self.flow_aggregator.flow_count % 10 == 0:
                    print(f"\rActive flows: {self.flow_aggregator.flow_count}, "
                          f"Completed flows: {self.flow_aggregator.get_completed_flows_count()}", 
                          end="")
                
        except KeyboardInterrupt:
            print("\n\nStopping capture...")
        except Exception as e:
            print(f"\nError during capture: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Cleanup resources"""
        print("\nFinalizing...")
        
        # Finalize all remaining flows (even without FIN)
        for flow_id in list(self.flow_aggregator.flows.keys()):
            self.flow_aggregator.finalize_flow(flow_id)
        
        # Close CSV file
        if hasattr(self, 'csv_file_obj'):
            self.csv_file_obj.close()
            print(f"Flow data saved to {self.csv_file}")
        
        print(f"Total flows processed: {self.flow_aggregator.get_completed_flows_count()}")
        print("Capture stopped.")

if __name__ == "__main__":
    sniff = Sniffer(use_json=True, include_raw=True, csv_file="network_flows.csv")
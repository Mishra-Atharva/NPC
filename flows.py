import logging as lg
from datetime import datetime

# Log formatting
lg.basicConfig(level=lg.DEBUG, format="[ %(asctime)s ] [ %(levelname)s ]  -->  %(message)s", datefmt="%Y-%m-%d %H:%M:%S", filename="packet.log")

class NetworkFlow:
    def __init__(self, first_packet): 
        self.flow_id = self.create_flow_id(first_packet)
        self.packets = [first_packet]
        
        self.total_packets = 1
        self.total_bytes = first_packet.packet_length
        
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        
        # Track flow state
        self.start_time = first_packet.timestamp
        self.end_time = first_packet.timestamp
        self.is_complete = False  # Will be set to True when FIN is received
        
        # Update counters for the first packet
        self.update_counter(first_packet)
    
    def create_flow_id(self, packet):
        # Ensure consistent flow ID regardless of direction
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        src_port = packet.src_port or 0
        dst_port = packet.dst_port or 0
        protocol = packet.protocol or "UNKNOWN"
        
        # Create canonical flow ID (sorted by IP and port)
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def update_counter(self, packet):
        if packet.protocol == "TCP" and packet.flags:
            flags = packet.flags.upper()
            
            if "S" in flags:  # SYN flag
                self.syn_count += 1
            
            if "A" in flags:  # ACK flag
                self.ack_count += 1
            
            if "F" in flags:  # FIN flag
                self.fin_count += 1
                # Mark flow as complete when FIN is received
                if self.fin_count >= 2:  # Typically need FIN from both sides
                    self.is_complete = True
    
    def add_packet(self, packet):
        self.packets.append(packet)
        self.total_packets += 1
        self.total_bytes += packet.packet_length
        self.end_time = packet.timestamp
        self.update_counter(packet)
        
        # Check if flow should be marked as complete
        if packet.protocol == "TCP" and packet.flags and "F" in packet.flags.upper():
            # For simplicity, we'll mark as complete on any FIN
            # In a more sophisticated system, you might wait for FIN-ACK
            self.is_complete = True
    
    # Basic Stats from the packets
    def get_basic_stats(self):
        if not self.packets:
            return {}
        
        # Calculating duration
        duration = self.end_time - self.start_time
        
        first_packet = self.packets[0]
        
        return {
            'flow_id': self.flow_id,
            'src_ip': first_packet.src_ip,
            'dst_ip': first_packet.dst_ip,
            'src_port': first_packet.src_port or 0,
            'dst_port': first_packet.dst_port or 0,
            'protocol': first_packet.protocol or "UNKNOWN",
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'duration': duration,
            'syn_count': self.syn_count,
            'ack_count': self.ack_count,
            'fin_count': self.fin_count,
            'is_complete': self.is_complete,
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.fromtimestamp(self.end_time).isoformat()
        }
    
    def to_csv_row(self):
        stats = self.get_basic_stats()
        # Convert to CSV-friendly format
        return [
            stats['flow_id'],
            stats['src_ip'],
            stats['dst_ip'],
            stats['src_port'],
            stats['dst_port'],
            stats['protocol'],
            stats['total_packets'],
            stats['total_bytes'],
            f"{stats['duration']:.6f}",
            stats['syn_count'],
            stats['ack_count'],
            stats['fin_count'],
            stats['is_complete'],
            stats['start_time'],
            stats['end_time']
        ]

class FlowAggregator:
    def __init__(self, csv_writer=None):
        self.flows = {}
        self.flow_count = 0
        self.completed_flows = []
        self.csv_writer = csv_writer
        
        # CSV headers
        self.csv_headers = [
            'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'total_packets', 'total_bytes', 'duration',
            'syn_count', 'ack_count', 'fin_count', 'is_complete',
            'start_time', 'end_time'
        ]
        
        # Write headers if CSV writer is provided
        if self.csv_writer:
            self.csv_writer.writerow(self.csv_headers)
    
    def process_packet(self, packet):
        # Generating unique flow id
        flow_id = self.get_flow_id(packet)
        
        # Checking if flow id doesn't exist in the flows
        if flow_id not in self.flows:
            # Creating a new network flow object
            self.flows[flow_id] = NetworkFlow(packet)
            self.flow_count += 1
            lg.info(f"New flow created: {flow_id}")
        else:
            # Add the packet to the existing flow
            self.flows[flow_id].add_packet(packet)
            
            # Check if flow is complete and needs to be finalized
            if self.flows[flow_id].is_complete:
                self.finalize_flow(flow_id)
    
    def get_flow_id(self, packet):
        # Consistent with NetworkFlow.create_flow_id
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        src_port = packet.src_port or 0
        dst_port = packet.dst_port or 0
        protocol = packet.protocol or "UNKNOWN"
        
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def finalize_flow(self, flow_id):
        """Finalize a flow and write to CSV"""
        if flow_id in self.flows:
            flow = self.flows[flow_id]
            
            # Get flow stats
            flow_stats = flow.get_basic_stats()
            
            # Add to completed flows list
            self.completed_flows.append(flow_stats)
            
            # Write to CSV if writer is available
            if self.csv_writer:
                self.csv_writer.writerow(flow.to_csv_row())
                lg.info(f"Flow {flow_id} written to CSV")
            
            # Remove from active flows
            del self.flows[flow_id]
            self.flow_count -= 1
            
            return flow_stats
    
    def get_flow_statistics(self):
        stats = []
        
        # Get stats for all active flows
        for _id, flow in self.flows.items():
            stats.append(flow.get_basic_stats())
        
        # Also include completed flows
        stats.extend(self.completed_flows)
        
        return stats
    
    def get_completed_flows_count(self):
        return len(self.completed_flows)
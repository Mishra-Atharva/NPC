import logging as lg
import pyshark
from datetime import datetime

# Log formatting
lg.basicConfig(level=lg.DEBUG, format="[ %(asctime)s ] [ %(levelname)s ]  -->  %(message)s", datefmt="%Y-%m-%d %H:%M:%S", filename="packet.log")

class PacketInfo:
    def __init__(self, packet):
        # Features that need to be extracted from the packet
        self.raw_packet = packet
        self.timestamp = self._parse_timestamp(packet)
        self.protocol = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.packet_length = packet.length
        self.ttl = None
        self.flags = None
        self.extract_info()
    
    def _parse_timestamp(self, packet):
        try:
            # Try to get sniff_time first (usually a datetime object)
            if hasattr(packet, 'sniff_time') and packet.sniff_time:
                if isinstance(packet.sniff_time, (int, float)):
                    return packet.sniff_time
                elif isinstance(packet.sniff_time, datetime):
                    return packet.sniff_time.timestamp()
                elif isinstance(packet.sniff_time, str):
                    # Try to parse ISO format string
                    try:
                        dt = datetime.fromisoformat(packet.sniff_time.replace('Z', '+00:00'))
                        return dt.timestamp()
                    except:
                        pass
            
            # Try packet.time (could be float or string)
            if hasattr(packet, 'time'):
                if isinstance(packet.time, (int, float)):
                    return packet.time
                elif isinstance(packet.time, str):
                    # Try to parse ISO format string
                    try:
                        dt = datetime.fromisoformat(packet.time.replace('Z', '+00:00'))
                        return dt.timestamp()
                    except:
                        # Try to convert string to float
                        try:
                            return float(packet.time)
                        except:
                            pass
            
            # Fallback: use current time
            return datetime.now().timestamp()
            
        except Exception as e:
            lg.error(f"Error parsing timestamp: {e}")
            return datetime.now().timestamp()
    
    # Extracting information from the packet
    def extract_info(self):
        try:
            # Check for IP layer
            if hasattr(self.raw_packet, 'ip'):
                self.src_ip = self.raw_packet.ip.src
                self.dst_ip = self.raw_packet.ip.dst
                self.ttl = int(self.raw_packet.ip.ttl)
            
            # Check for transport layer
            if hasattr(self.raw_packet, 'transport_layer'):
                self.protocol = self.raw_packet.transport_layer
                
                # TCP
                if hasattr(self.raw_packet, 'tcp'):
                    self.src_port = int(self.raw_packet.tcp.srcport)
                    self.dst_port = int(self.raw_packet.tcp.dstport)
                    self.flags = self.raw_packet.tcp.flags_str
                
                # UDP
                elif hasattr(self.raw_packet, 'udp'):
                    self.src_port = int(self.raw_packet.udp.srcport)
                    self.dst_port = int(self.raw_packet.udp.dstport)
                    self.flags = None
                
                # Other protocols
                else:
                    self.src_port = 0
                    self.dst_port = 0
                    self.flags = None
            else:
                self.protocol = "UNKNOWN"
                self.src_port = 0
                self.dst_port = 0
            
        except Exception as e:
            lg.error(f"Error extracting packet info: {e}")
    
    # Converting information extracted into a dictionary format
    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port or 0,
            'dst_port': self.dst_port or 0,
            'protocol': self.protocol or "UNKNOWN",
            'packet_length': self.packet_length,
            'ttl': self.ttl or 0,
            'flags': self.flags
        }
    
    def __str__(self):
        return (f"SOURCE IP [ {self.src_ip} ] : SOURCE PORT [ {self.src_port} ] ==> "
                f"DESTINATION IP [ {self.dst_ip} ] : DESTINATION PORT [ {self.dst_port} ] "
                f"PROTOCOL {self.protocol}, LENGTH: {self.packet_length}")

class PacketProcessor:
    def __init__(self, flow_aggregator=None):
        self.processed_packets = []
        self.flow_aggregator = flow_aggregator
    
    # Processing the packets
    def process_packet(self, raw_packet):
        try:
            lg.debug("Processing packet")
            packet_info = PacketInfo(raw_packet)
            self.processed_packets.append(packet_info)
            lg.debug(f"Processed packet: {packet_info}")
            
            # Pass to flow aggregator if available
            if self.flow_aggregator:
                self.flow_aggregator.process_packet(packet_info)
            
            return packet_info
            
        except Exception as e:
            lg.error(f'Unable to process packet: {e}')
            return None
    
    # Returning list of packets in a dictionary format
    def get_packets_dicts(self):
        return [p.to_dict() for p in self.processed_packets]
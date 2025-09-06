import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
import logging

class PacketCapture:
    def __init__(self, interface, flow_manager):
        self.interface = interface
        self.flow_manager = flow_manager
        self.running = False
        self.capture_thread = None
        
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            if IP in packet:
                # Extract packet information
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto
                
                src_port = 0
                dst_port = 0
                
                # Extract port information for TCP/UDP
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = 6  # TCP
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = 17  # UDP
                
                # Create packet info dictionary
                packet_info = {
                    'timestamp': time.time(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'length': len(packet),
                    'packet': packet
                }
                
                # Add packet to flow manager
                self.flow_manager.add_packet(packet_info)
                
        except Exception as e:
            self.logger.error(f"Error handling packet: {str(e)}")
    
    def start_capture(self):
        """Start packet capture"""
        self.running = True
        self.logger.info(f"Starting packet capture on interface: {self.interface}")
        
        try:
            # Start packet capture with filter for better performance
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_handler,
                stop_filter=lambda x: not self.running,
                store=False,  # Don't store packets in memory
                filter="ip"  # Only capture IP packets
            )
        except Exception as e:
            self.logger.error(f"Error starting packet capture: {str(e)}")
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        self.logger.info("Stopping packet capture")

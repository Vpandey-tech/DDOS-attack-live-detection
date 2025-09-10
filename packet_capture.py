import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
import logging
import netifaces
import socket

class PacketCapture:
    def __init__(self, interface=None, flow_manager=None):
        self.interface = interface or self.auto_detect_interface()
        self.flow_manager = flow_manager
        self.running = False
        self.capture_thread = None
        self.packet_count = 0
        
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Log detected interface
        self.logger.info(f"Initialized packet capture for interface: {self.interface}")
    
    def auto_detect_interface(self):
        """Automatically detect the best network interface to use"""
        try:
            # Get all available interfaces
            interfaces = netifaces.interfaces()
            
            # Priority order for interface detection
            interface_priorities = [
                'WiFi',           # Windows WiFi
                'Wi-Fi',          # Alternative Windows WiFi
                'wlan0',          # Linux WiFi
                'eth0',           # Linux Ethernet
                'en0',            # macOS WiFi
                'en1',            # macOS Ethernet
            ]
            
            # Try priority interfaces first
            for priority_iface in interface_priorities:
                if priority_iface in interfaces:
                    # Check if interface has an IP address
                    try:
                        addrs = netifaces.ifaddresses(priority_iface)
                        if netifaces.AF_INET in addrs:
                            ip_info = addrs[netifaces.AF_INET][0]
                            if 'addr' in ip_info and ip_info['addr'] != '127.0.0.1':
                                self.logger.info(f"Auto-detected interface: {priority_iface} ({ip_info['addr']})")
                                return priority_iface
                    except:
                        continue
            
            # If no priority interface found, find any interface with IP
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        if 'addr' in ip_info and ip_info['addr'] != '127.0.0.1':
                            # Check if this looks like the user's WiFi interface (192.168.1.105)
                            if ip_info['addr'].startswith('192.168.1.'):
                                self.logger.info(f"Found user's WiFi interface: {iface} ({ip_info['addr']})")
                                return iface
                except:
                    continue
            
            # Fallback to first available interface
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        if 'addr' in ip_info and ip_info['addr'] != '127.0.0.1':
                            self.logger.warning(f"Using fallback interface: {iface} ({ip_info['addr']})")
                            return iface
                except:
                    continue
            
            # Ultimate fallback
            self.logger.warning("No suitable interface found, using default")
            return interfaces[0] if interfaces else None
            
        except Exception as e:
            self.logger.error(f"Error detecting interface: {str(e)}")
            return None
    
    def get_interface_info(self):
        """Get detailed information about the current interface"""
        try:
            if not self.interface:
                return "No interface selected"
            
            addrs = netifaces.ifaddresses(self.interface)
            info = f"Interface: {self.interface}\n"
            
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                info += f"IP Address: {ip_info.get('addr', 'Unknown')}\n"
                info += f"Netmask: {ip_info.get('netmask', 'Unknown')}\n"
            
            return info
            
        except Exception as e:
            return f"Error getting interface info: {str(e)}"
    
    def packet_handler(self, packet):
        """Enhanced packet handler with better filtering and logging"""
        try:
            if IP in packet:
                # Increment packet counter
                self.packet_count += 1
                
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
                else:
                    # For other protocols, still process but with 0 ports
                    pass
                
                # Filter out localhost traffic for cleaner results
                if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1':
                    return
                
                # Create enhanced packet info dictionary
                packet_info = {
                    'timestamp': time.time(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'length': len(packet),
                    'packet': packet,
                    'interface': self.interface
                }
                
                # Add packet to flow manager if available
                if self.flow_manager:
                    self.flow_manager.add_packet(packet_info)
                
                # Log packet every 100 packets for monitoring
                if self.packet_count % 100 == 0:
                    self.logger.info(f"Captured {self.packet_count} packets from {self.interface}")
                
        except Exception as e:
            self.logger.error(f"Error handling packet: {str(e)}")
    
    def start_capture(self):
        """Enhanced packet capture with better error handling"""
        if not self.interface:
            self.logger.error("No network interface available for capture")
            return False
        
        self.running = True
        self.packet_count = 0
        self.logger.info(f"Starting packet capture on interface: {self.interface}")
        
        try:
            # Enhanced packet capture with optimized filters
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_handler,
                stop_filter=lambda x: not self.running,
                store=False,  # Don't store packets in memory for performance
                filter="ip and (tcp or udp)",  # Focus on TCP/UDP traffic
                timeout=1  # Add timeout for better control
            )
            return True
            
        except PermissionError:
            self.logger.error("Permission denied: Packet capture requires administrator/root privileges")
            return False
        except OSError as e:
            self.logger.error(f"OS Error during packet capture: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during packet capture: {str(e)}")
            return False
    
    def stop_capture(self):
        """Stop packet capture with statistics"""
        self.running = False
        self.logger.info(f"Stopping packet capture. Total packets captured: {self.packet_count}")
        return self.packet_count
    
    def get_capture_stats(self):
        """Get capture statistics"""
        return {
            'interface': self.interface,
            'packet_count': self.packet_count,
            'running': self.running
        }

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import threading
import time
import logging
import psutil
import socket
import os
import struct

class PacketCapture:
    def __init__(self, interface=None, flow_manager=None):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        self.flow_manager = flow_manager
        self.running = False
        self.capture_thread = None
        self.packet_count = 0
        self.interface = interface
        self.use_raw_socket = False

        if self.interface:
            self.logger.info(f"PacketCapture initialized for interface: {self.interface}")
        else:
            self.logger.warning("PacketCapture initialized without a specified interface.")

    @staticmethod
    def get_available_interfaces():
        """
        Get a list of all valid, non-loopback interfaces.
        """
        valid_interfaces = []
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addr_list in addrs.items():
                if iface in stats and stats[iface].isup:
                    for addr in addr_list:
                        if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                            valid_interfaces.append(iface)
                            break
        except Exception as e:
            logging.error(f"Could not get available interfaces: {e}")
        return valid_interfaces

    @staticmethod
    def auto_detect_interface():
        """
        Auto-detect the best network interface.
        Prioritizes common interface names like Wi-Fi and Ethernet.
        """
        logging.info("Auto-detecting network interface with psutil...")
        try:
            valid_interfaces = {iface: addr.address for iface, addrs in psutil.net_if_addrs().items()
                                for addr in addrs if addr.family == socket.AF_INET and not addr.address.startswith('127.')
                                and iface in psutil.net_if_stats() and psutil.net_if_stats()[iface].isup}

            if not valid_interfaces:
                logging.warning("No active network interfaces with an IPv4 address found.")
                return None

            priority_order = ['WiFi', 'Wi-Fi', 'Ethernet', 'eth0', 'en0', 'wlan0']
            for iface_name in priority_order:
                if iface_name in valid_interfaces:
                    logging.info(f"Auto-detected priority interface: {iface_name}")
                    return iface_name
            
            fallback_iface = list(valid_interfaces.keys())[0]
            logging.warning(f"Using fallback interface: {fallback_iface}")
            return fallback_iface
        except Exception as e:
            logging.error(f"Error auto-detecting interface: {e}")
            return None
    
    def packet_handler(self, packet):
        """
        Processes each captured packet.
        Handles both Scapy packet objects and manual submissions.
        """
        try:
            # Check if it's a Scapy packet
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                length = len(packet)
                
                src_port = 0
                dst_port = 0
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                
                self._submit_packet(src_ip, dst_ip, proto, length, src_port, dst_port)

        except Exception:
            pass

    def _submit_packet(self, src, dst, proto, length, sport, dport):
        """Helper to submit parsed stats to flow manager"""
        self.packet_count += 1
        packet_info = {
            'timestamp': time.time(),
            'src_ip': src,
            'dst_ip': dst,
            'protocol': proto,
            'length': length,
            'src_port': sport,
            'dst_port': dport,
        }
        if self.flow_manager:
            self.flow_manager.add_packet(packet_info)

    def _get_ip_address(self, iface_name):
        try:
            addrs = psutil.net_if_addrs()
            if iface_name in addrs:
                for addr in addrs[iface_name]:
                    if addr.family == socket.AF_INET:
                        return addr.address
        except Exception:
            pass
        return None

    def start_capture_thread(self):
        """Starts the packet capture in a separate thread. Tries Raw Socket first on Windows."""
        if self.running:
            self.logger.warning("Capture is already running.")
            return

        if not self.interface:
            self.logger.error("Cannot start capture: No network interface is set.")
            raise ValueError("Network interface not provided.")

        self.running = True
        self.packet_count = 0
        
        # Determine capture method
        # Raw sockets are faster but require Admin and binding to specific IP
        self.use_raw_socket = False
        if os.name == 'nt':
            try:
                # Test if we can open a raw socket
                # Note: This checks for Admin privileges effectively
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.close()
                self.use_raw_socket = True
            except PermissionError:
                self.logger.warning("Admin privileges missing for Raw Sockets. Falling back to Scapy.")
            except Exception as e:
                self.logger.warning(f"Raw socket check failed: {e}. Falling back to Scapy.")

        if self.use_raw_socket:
            self.logger.info(f"🚀 PERFORMANCE MODE: Starting Raw Socket Sniffer on {self.interface}")
            self.capture_thread = threading.Thread(target=self._run_raw_socket_sniffer, daemon=True)
        else:
            self.logger.info(f"🛡️ STANDARD MODE: Starting Scapy Sniffer on {self.interface}")
            self.capture_thread = threading.Thread(target=self._run_scapy_sniffer, daemon=True)
            
        self.capture_thread.start()

    def _run_raw_socket_sniffer(self):
        """High-performance raw socket sniffer for Windows."""
        host_ip = self._get_ip_address(self.interface)
        if not host_ip:
            self.logger.error("Could not resolve IP for interface. Aborting raw socket sniff.")
            self.running = False
            return

        sniffer = None
        try:
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((host_ip, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Windows specific: Receive all packets (Promiscuous-like)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            # Pre-allocate buffer
            RECV_BUFFER_SIZE = 65535
            
            while self.running:
                # Receive packet
                raw_buffer = sniffer.recvfrom(RECV_BUFFER_SIZE)[0]
                
                # Manual parsing for speed (IP Header is first 20 bytes usually)
                # IHL is in the first byte (lower 4 bits) * 4
                version_ihl = raw_buffer[0]
                ihl = (version_ihl & 0xF) * 4
                
                protocol = raw_buffer[9]
                
                # Filter useful protocols early: 6=TCP, 17=UDP
                if protocol not in (6, 17):
                    continue
                
                # Source and Dest IP are at offset 12 and 16
                s_addr = socket.inet_ntoa(raw_buffer[12:16])
                d_addr = socket.inet_ntoa(raw_buffer[16:20])
                total_len = len(raw_buffer)
                
                src_port = 0
                dst_port = 0
                
                # Parse Transport Layer
                if protocol == 6: # TCP
                    # TCP Header starts after IHL
                    tcp_header = raw_buffer[ihl:ihl+20]
                    # Source Port (2 bytes), Dest Port (2 bytes)
                    # !HH means Big Endian, Unsigned Short, Unsigned Short
                    ports = struct.unpack('!HH', tcp_header[0:4])
                    src_port = ports[0]
                    dst_port = ports[1]
                    
                elif protocol == 17: # UDP
                    udp_header = raw_buffer[ihl:ihl+8]
                    ports = struct.unpack('!HH', udp_header[0:4])
                    src_port = ports[0]
                    dst_port = ports[1]
                    
                self._submit_packet(s_addr, d_addr, protocol, total_len, src_port, dst_port)
                
        except Exception as e:
            self.logger.error(f"Raw Socket Sniffer critical error: {e}")
        finally:
            if sniffer:
                try:
                    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    sniffer.close()
                except:
                    pass
            self.running = False

    def _run_scapy_sniffer(self):
        """Standard Scapy sniffer (Fallback)."""
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_handler,
                stop_filter=lambda x: not self.running,
                store=False,
            )
        except (PermissionError, OSError) as e:
            self.logger.error(f"Capture failed on '{self.interface}'. Try running with sudo/admin privileges. Error: {e}")
            self.running = False
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during packet capture: {e}")
            self.running = False

    def stop_capture(self):
        """Stops the packet capture."""
        if not self.running:
            return
        
        self.running = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        self.logger.info(f"Stopping packet capture. Total packets captured: {self.packet_count}")

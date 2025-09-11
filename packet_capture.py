import scapy.all as scapy
from scapy.layers.inet import IP
import threading
import time
import logging
import psutil
import socket

class PacketCapture:
    def __init__(self, interface=None, flow_manager=None):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        self.flow_manager = flow_manager
        self.running = False
        self.capture_thread = None
        self.packet_count = 0
        self.interface = interface

        if self.interface:
            self.logger.info(f"PacketCapture initialized for interface: {self.interface}")
        else:
            self.logger.warning("PacketCapture initialized without a specified interface.")

    @staticmethod
    def get_available_interfaces():
        """
        FIX: A new static method to get a list of all valid, non-loopback interfaces.
        This is crucial for making the app portable.
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
        FIX: A static method for robustly auto-detecting the best network interface.
        It prioritizes common interface names like Wi-Fi and Ethernet.
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
        """Processes each captured packet."""
        try:
            if IP in packet:
                self.packet_count += 1
                packet_info = {
                    'timestamp': time.time(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet),
                    'src_port': packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else 0,
                    'dst_port': packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else 0,
                }
                if self.flow_manager:
                    self.flow_manager.add_packet(packet_info)
        except Exception:
            pass
    
    def start_capture_thread(self):
        """Starts the packet capture in a separate thread."""
        if self.running:
            self.logger.warning("Capture is already running.")
            return

        if not self.interface:
            self.logger.error("Cannot start capture: No network interface is set.")
            raise ValueError("Network interface not provided.")

        self.running = True
        self.packet_count = 0
        self.capture_thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self.capture_thread.start()
        self.logger.info(f"Packet capture thread started on interface: {self.interface}")

    def _run_sniffer(self):
        """Internal method that runs the Scapy sniffer."""
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
            self.logger.info("Capture is not currently running.")
            return
        
        self.running = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        self.logger.info(f"Stopping packet capture. Total packets captured: {self.packet_count}")

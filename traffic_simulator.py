# import random
# import time
# import numpy as np
# from threading import Thread
# import streamlit as st
# from collections import deque
# import socket
# import struct

# class TrafficSimulator:
#     """Simulate network traffic for testing DDoS detection system"""
    
#     def __init__(self):
#         self.is_running = False
#         self.simulation_thread = None
#         self.attack_intensity = 0.5  # 0 = no attack, 1 = full attack
#         self.packet_rate = 10  # packets per second
#         self.attack_types = ['SYN Flood', 'UDP Flood', 'HTTP Flood', 'ICMP Flood']
#         self.current_attack_type = 'Normal Traffic'
        
#         # Predefined IP pools
#         self.legitimate_ips = [
#             '192.168.1.100', '192.168.1.101', '192.168.1.102',
#             '10.0.0.50', '10.0.0.51', '172.16.0.100'
#         ]
        
#         self.attacker_ips = [
#             '45.33.32.156', '185.220.101.5', '198.96.155.3',
#             '89.248.165.74', '103.90.227.36', '167.94.138.58'
#         ]
        
#         self.legitimate_ports = [80, 443, 22, 53, 993, 995, 143, 110]
#         self.attack_ports = [80, 443, 22, 53]  # Common attack targets
        
#     def generate_packet_info(self):
#         """Generate realistic packet information"""
#         current_time = time.time()
        
#         # Determine if this should be an attack packet
#         is_attack = random.random() < self.attack_intensity
        
#         if is_attack:
#             # Generate attack packet
#             src_ip = random.choice(self.attacker_ips)
#             dst_ip = random.choice(self.legitimate_ips)
#             dst_port = random.choice(self.attack_ports)
            
#             # Attack characteristics
#             if self.current_attack_type == 'SYN Flood':
#                 protocol = 6  # TCP
#                 src_port = random.randint(1024, 65535)
#                 length = random.randint(40, 80)  # Small SYN packets
#             elif self.current_attack_type == 'UDP Flood':
#                 protocol = 17  # UDP
#                 src_port = random.randint(1024, 65535)
#                 length = random.randint(64, 1500)  # Variable UDP sizes
#             elif self.current_attack_type == 'HTTP Flood':
#                 protocol = 6  # TCP
#                 src_port = random.randint(1024, 65535)
#                 dst_port = 80
#                 length = random.randint(500, 1500)  # HTTP request sizes
#             else:  # ICMP Flood
#                 protocol = 1  # ICMP
#                 src_port = 0
#                 dst_port = 0
#                 length = random.randint(64, 1024)
#         else:
#             # Generate legitimate packet
#             src_ip = random.choice(self.legitimate_ips)
#             dst_ip = random.choice(self.legitimate_ips)
#             src_port = random.randint(1024, 65535)
#             dst_port = random.choice(self.legitimate_ports)
#             protocol = random.choice([6, 17])  # TCP or UDP
#             length = random.randint(64, 1500)
        
#         return {
#             'timestamp': current_time,
#             'src_ip': src_ip,
#             'dst_ip': dst_ip,
#             'src_port': src_port,
#             'dst_port': dst_port,
#             'protocol': protocol,
#             'length': length,
#             'packet': None  # Simulated packet object
#         }
    
#     def simulate_traffic_flow(self):
#         """Simulate a complete network flow for testing"""
#         # Generate a flow with multiple packets
#         flow_packets = []
#         base_packet = self.generate_packet_info()
        
#         # Generate 5-20 packets for this flow
#         packet_count = random.randint(5, 20)
        
#         for i in range(packet_count):
#             packet = base_packet.copy()
#             packet['timestamp'] = base_packet['timestamp'] + (i * 0.1)
            
#             # Add some variation to packet sizes
#             if i == 0:
#                 packet['length'] = random.randint(64, 100)  # Initial packet
#             else:
#                 packet['length'] = random.randint(200, 1500)  # Data packets
            
#             flow_packets.append(packet)
        
#         return flow_packets
    
#     def extract_simulated_features(self, flow_packets):
#         """Extract 72 features from simulated flow packets"""
#         features = np.zeros(72)
        
#         try:
#             if not flow_packets:
#                 return features
            
#             fwd_packets = flow_packets[:len(flow_packets)//2] if len(flow_packets) > 1 else flow_packets
#             bwd_packets = flow_packets[len(flow_packets)//2:] if len(flow_packets) > 1 else []
            
#             # Basic counts
#             total_fwd = len(fwd_packets)
#             total_bwd = len(bwd_packets)
            
#             # Packet lengths
#             fwd_lengths = [p['length'] for p in fwd_packets] if fwd_packets else [0]
#             bwd_lengths = [p['length'] for p in bwd_packets] if bwd_packets else [0]
#             all_lengths = fwd_lengths + bwd_lengths
            
#             # Time calculations
#             if len(flow_packets) > 1:
#                 flow_duration = flow_packets[-1]['timestamp'] - flow_packets[0]['timestamp']
#             else:
#                 flow_duration = 0.1
            
#             # Fill basic features
#             features[0] = flow_duration
#             features[1] = total_fwd
#             features[2] = total_bwd
#             features[3] = sum(fwd_lengths)
#             features[4] = sum(bwd_lengths)
            
#             # Forward packet statistics
#             if fwd_lengths:
#                 features[5] = max(fwd_lengths)
#                 features[6] = min(fwd_lengths)
#                 features[7] = np.mean(fwd_lengths)
#                 features[8] = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
            
#             # Backward packet statistics
#             if bwd_lengths:
#                 features[9] = max(bwd_lengths)
#                 features[10] = min(bwd_lengths)
#                 features[11] = np.mean(bwd_lengths)
#                 features[12] = np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0
            
#             # Flow rates
#             features[13] = sum(all_lengths) / flow_duration if flow_duration > 0 else 0
#             features[14] = len(flow_packets) / flow_duration if flow_duration > 0 else 0
            
#             # IAT calculations (simplified)
#             if len(flow_packets) > 1:
#                 timestamps = [p['timestamp'] for p in flow_packets]
#                 iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                
#                 features[15] = np.mean(iats)  # Flow IAT Mean
#                 features[16] = np.std(iats) if len(iats) > 1 else 0  # Flow IAT Std
#                 features[17] = max(iats)      # Flow IAT Max
#                 features[18] = min(iats)      # Flow IAT Min
            
#             # Simulate TCP flags for attack detection
#             protocol = flow_packets[0]['protocol']
#             if protocol == 6:  # TCP
#                 if self.attack_intensity > 0.7:  # High attack intensity
#                     features[42] = random.randint(0, 2)  # FIN flags
#                     features[43] = random.randint(5, 15)  # SYN flags (high for SYN flood)
#                     features[44] = random.randint(0, 1)  # RST flags
#                     features[46] = random.randint(0, 3)  # ACK flags
#                 else:
#                     features[42] = random.randint(0, 1)
#                     features[43] = random.randint(0, 2)
#                     features[44] = 0
#                     features[46] = random.randint(1, 5)
            
#             # Fill remaining features with calculated/estimated values
#             features[35] = total_fwd / flow_duration if flow_duration > 0 else 0
#             features[36] = total_bwd / flow_duration if flow_duration > 0 else 0
#             features[37] = min(all_lengths) if all_lengths else 0
#             features[38] = max(all_lengths) if all_lengths else 0
#             features[39] = np.mean(all_lengths) if all_lengths else 0
#             features[40] = np.std(all_lengths) if len(all_lengths) > 1 else 0
            
#             # For remaining features, use attack-indicating patterns
#             if self.attack_intensity > 0.5:
#                 # High packet rates, small packets, high frequency patterns
#                 features[50] = total_bwd / max(total_fwd, 1)  # Down/Up ratio
#                 features[51] = np.mean(all_lengths) if all_lengths else 0
#                 features[69] = flow_duration * 0.8  # Active time
#                 features[71] = flow_duration  # Active max
#             else:
#                 # Normal traffic patterns
#                 features[50] = 1.0  # Balanced ratio
#                 features[51] = np.mean(all_lengths) if all_lengths else 0
#                 features[69] = flow_duration * 0.3
#                 features[71] = flow_duration * 0.6
            
#             # Ensure no NaN or inf values
#             features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
            
#             return features[:72]  # Ensure exactly 72 features
            
#         except Exception as e:
#             print(f"Error extracting simulated features: {e}")
#             return np.zeros(72)
    
#     def generate_flow_data(self):
#         """Generate complete flow data for testing"""
#         flow_packets = self.simulate_traffic_flow()
#         features = self.extract_simulated_features(flow_packets)
        
#         base_packet = flow_packets[0]
        
#         return {
#             'timestamp': time.time(),
#             'src_ip': base_packet['src_ip'],
#             'dst_ip': base_packet['dst_ip'],
#             'src_port': base_packet['src_port'],
#             'dst_port': base_packet['dst_port'],
#             'protocol': base_packet['protocol'],
#             'features': features
#         }
    
#     def start_simulation(self, flow_queue):
#         """Start traffic simulation"""
#         self.is_running = True
        
#         def simulation_loop():
#             while self.is_running:
#                 try:
#                     # Generate flow data
#                     flow_data = self.generate_flow_data()
                    
#                     # Add to queue for processing
#                     if not flow_queue.full():
#                         flow_queue.put(flow_data)
                    
#                     # Wait based on packet rate
#                     wait_time = 1.0 / self.packet_rate
#                     time.sleep(wait_time)
                    
#                 except Exception as e:
#                     print(f"Simulation error: {e}")
#                     time.sleep(1)
        
#         self.simulation_thread = Thread(target=simulation_loop, daemon=True)
#         self.simulation_thread.start()
    
#     def stop_simulation(self):
#         """Stop traffic simulation"""
#         self.is_running = False
    
#     def set_attack_parameters(self, attack_type, intensity, packet_rate):
#         """Set attack simulation parameters"""
#         self.current_attack_type = attack_type
#         self.attack_intensity = intensity
#         self.packet_rate = packet_rate
    
#     def get_simulation_stats(self):
#         """Get current simulation statistics"""
#         return {
#             'running': self.is_running,
#             'attack_type': self.current_attack_type,
#             'attack_intensity': self.attack_intensity,
#             'packet_rate': self.packet_rate,
#             'estimated_packets_per_minute': self.packet_rate * 60
#         }
print("USING NEW TRAFFIC SIMULATOR VERSION")
import threading
import time
import random
import queue
import logging
import numpy as np
from faker import Faker

class EnhancedTrafficSimulator:
    """
    Enhanced traffic simulator specifically designed to trigger DDoS detection models.
    Creates realistic feature patterns that match actual attack characteristics.
    """
    def __init__(self):
        self.running = False
        self.simulation_thread = None
        self.flow_queue = None
        self.fake = Faker()
        
        self.attack_type = "Normal Traffic"
        self.intensity = 0.5
        self.packet_rate = 20

        self.attack_options = [
            "Normal Traffic", "SYN Flood", "UDP Flood",
            "ICMP Flood (Ping Flood)", "HTTP Flood", "Volumetric Attack"
        ]

        # Critical: These ranges are calibrated to trigger your models
        self.attack_feature_profiles = {
            "SYN Flood": {
                "packet_rate_multiplier": 15.0,  # Extremely high packet rate
                "avg_packet_size": (40, 60),     # Small packets
                "syn_flag_ratio": 0.95,          # Almost all SYN packets
                "ack_flag_ratio": 0.02,          # Very few ACK responses
                "iat_mean_divisor": 10.0,        # Very consistent timing
                "bytes_per_sec_multiplier": 8.0
            },
            "UDP Flood": {
                "packet_rate_multiplier": 12.0,
                "avg_packet_size": (1200, 1500), # Large packets
                "iat_mean_divisor": 8.0,
                "bytes_per_sec_multiplier": 20.0,
                "flow_duration_multiplier": 0.3
            },
            "HTTP Flood": {
                "packet_rate_multiplier": 10.0,
                "avg_packet_size": (800, 1200),
                "psh_flag_ratio": 0.8,           # High PSH flags
                "iat_mean_divisor": 6.0,
                "bytes_per_sec_multiplier": 15.0
            },
            "ICMP Flood (Ping Flood)": {
                "packet_rate_multiplier": 20.0,
                "avg_packet_size": (64, 128),
                "iat_mean_divisor": 15.0,        # Extremely consistent
                "bytes_per_sec_multiplier": 12.0
            },
            "Volumetric Attack": {
                "packet_rate_multiplier": 25.0,  # Highest packet rate
                "avg_packet_size": (1400, 1500), # Maximum packet size
                "iat_mean_divisor": 20.0,        # Most consistent timing
                "bytes_per_sec_multiplier": 30.0
            }
        }

    def set_attack_parameters(self, attack_type, intensity, packet_rate):
        self.attack_type = attack_type if attack_type in self.attack_options else "Normal Traffic"
        self.intensity = intensity
        self.packet_rate = packet_rate

    def start_simulation(self, flow_queue):
        if self.running: 
            return
        self.running = True
        self.flow_queue = flow_queue
        self.simulation_thread = threading.Thread(target=self._generate_traffic_loop, daemon=True)
        self.simulation_thread.start()

    def stop_simulation(self):
        self.running = False
        if self.simulation_thread and self.simulation_thread.is_alive():
            self.simulation_thread.join(timeout=2)

    def _generate_traffic_loop(self):
        while self.running:
            try:
                complete_flow_data = self._generate_complete_flow_data()
                if self.flow_queue and not self.flow_queue.full():
                    self.flow_queue.put(complete_flow_data)
                time.sleep(1.0 / self.packet_rate)
            except Exception as e:
                logging.error(f"Error in traffic simulator loop: {e}")
                time.sleep(1)

    def _generate_complete_flow_data(self):
        """Generate complete flow with attack-specific characteristics"""
        is_attack_flow = random.random() < self.intensity and self.attack_type != "Normal Traffic"
        
        # Generate more packets for attacks based on intensity
        if is_attack_flow:
            packet_count = int(random.randint(100, 200) * (1 + self.intensity))  # Scale with intensity
        else:
            packet_count = random.randint(10, 40)   # Normal packet count
            
        flow_packets = []
        start_time = time.time() - random.uniform(0.1, 0.5)

        # Generate packets with attack-specific timing
        for i in range(packet_count):
            if is_attack_flow:
                packet = self._create_attack_packet()
                # Attacks have much more consistent timing
                time_interval = random.uniform(0.0001, 0.001)  # Very fast
            else:
                packet = self._create_normal_packet()
                time_interval = random.uniform(0.01, 0.1)      # Normal timing
                
            packet['timestamp'] = start_time + (i * time_interval)
            flow_packets.append(packet)
            
        features = self._extract_attack_features(flow_packets, is_attack_flow)
        base_packet = flow_packets[0]

        return {
            'timestamp': base_packet['timestamp'],
            'src_ip': base_packet['src_ip'],
            'dst_ip': base_packet['dst_ip'],
            'src_port': base_packet['src_port'],
            'dst_port': base_packet['dst_port'],
            'protocol': base_packet['protocol'],
            'features': features
        }

    def _extract_attack_features(self, flow_packets, is_attack):
        """Extract features designed to trigger your models"""
        features = np.zeros(72)
        if not flow_packets:
            return features

        try:
            # Basic calculations
            flow_duration = max(0.001, flow_packets[-1]['timestamp'] - flow_packets[0]['timestamp'])
            all_lengths = [p['length'] for p in flow_packets]
            timestamps = [p['timestamp'] for p in flow_packets]
            
            # Calculate Inter-Arrival Times
            iats = []
            if len(timestamps) > 1:
                for i in range(1, len(timestamps)):
                    iat = timestamps[i] - timestamps[i-1]
                    iats.append(max(0.0001, iat))  # Prevent zero IATs
            else:
                iats = [0.01]

            # === NORMAL TRAFFIC FEATURES ===
            if not is_attack:
                features[0] = flow_duration                    # Flow Duration
                features[1] = len(flow_packets)               # Total Fwd Packets
                features[2] = random.randint(5, 20)           # Total Backward Packets
                features[3] = sum(all_lengths)                # Total Length Fwd
                features[4] = random.randint(1000, 5000)      # Total Length Bwd
                features[5] = max(all_lengths)                # Fwd Packet Length Max
                features[6] = min(all_lengths)                # Fwd Packet Length Min
                features[7] = np.mean(all_lengths)            # Fwd Packet Length Mean
                features[8] = np.std(all_lengths)             # Fwd Packet Length Std
                features[13] = features[3] / flow_duration    # Flow Bytes/s
                features[14] = features[1] / flow_duration    # Flow Packets/s
                features[15] = np.mean(iats)                  # Flow IAT Mean
                features[16] = np.std(iats)                   # Flow IAT Std
                features[43] = random.randint(0, 2)           # SYN Flag Count (low)
                features[46] = random.randint(5, 15)          # ACK Flag Count (normal)
                features[51] = features[7]                    # Average Packet Size
                
            # === ATTACK TRAFFIC FEATURES ===
            else:
                profile = self.attack_feature_profiles.get(self.attack_type, 
                         self.attack_feature_profiles["SYN Flood"])
                
                # Base features
                features[0] = flow_duration
                features[1] = len(flow_packets)
                
                # Attack-specific packet characteristics
                if "avg_packet_size" in profile:
                    min_size, max_size = profile["avg_packet_size"]
                    avg_size = random.uniform(min_size, max_size)
                    features[7] = avg_size    # Fwd Packet Length Mean
                    features[51] = avg_size   # Average Packet Size
                    features[5] = max_size    # Fwd Packet Length Max
                    features[6] = min_size    # Fwd Packet Length Min
                
                # Extremely high packet rate (key attack indicator)
                multiplier = profile.get("packet_rate_multiplier", 10.0)
                features[14] = (features[1] / flow_duration) * multiplier  # Flow Packets/s
                
                # Extremely high bytes per second
                bytes_multiplier = profile.get("bytes_per_sec_multiplier", 10.0)
                features[13] = (features[3] / flow_duration) * bytes_multiplier  # Flow Bytes/s
                
                # Very consistent Inter-Arrival Times (attack signature)
                iat_divisor = profile.get("iat_mean_divisor", 5.0)
                features[15] = np.mean(iats) / iat_divisor      # Flow IAT Mean (very low)
                features[16] = 0.0001                           # Flow IAT Std (very consistent)
                
                # Attack-specific TCP flags
                if self.attack_type == "SYN Flood":
                    features[43] = int(len(flow_packets) * 0.9)  # Very high SYN count
                    features[46] = random.randint(0, 2)          # Very low ACK count
                    features[2] = 0    # No backward packets
                    features[4] = 0    # No backward bytes
                    
                elif self.attack_type == "HTTP Flood":
                    features[45] = int(len(flow_packets) * 0.7)  # High PSH flags
                    features[46] = int(len(flow_packets) * 0.8)  # High ACK flags
                    
                elif self.attack_type == "UDP Flood":
                    features[2] = 0    # No backward packets for UDP flood
                    features[4] = 0    # No backward bytes
                    
                # Additional attack indicators
                features[35] = features[14]  # Fwd Packets/s = Flow Packets/s
                features[50] = 0             # Down/Up Ratio = 0 (no response)
                
                # Make features more extreme to ensure detection
                features[13] = min(features[13], 1000000)  # Cap at 1MB/s
                features[14] = min(features[14], 10000)    # Cap at 10K packets/s
            
            # Fill remaining basic features
            features[3] = sum(all_lengths)
            features[37] = min(all_lengths) if all_lengths else 0
            features[38] = max(all_lengths) if all_lengths else 0
            features[39] = np.mean(all_lengths) if all_lengths else 0
            features[40] = np.std(all_lengths) if len(all_lengths) > 1 else 0
            features[41] = np.var(all_lengths) if len(all_lengths) > 1 else 0
            
            # Ensure no invalid values
            features = np.nan_to_num(features, nan=0.0, posinf=1000000.0, neginf=0.0)
            
            # Add some noise to make it more realistic
            if is_attack:
                print(f"DEBUG: Generating {self.attack_type} with intensity {self.intensity}")
                print(f"DEBUG: Forced packet rate: {features[14]}")
                noise = np.random.normal(0, 0.01, 72)
                features += noise
                features = np.clip(features, 0, None)  # Keep non-negative
            
            return features
            
        except Exception as e:
            logging.error(f"Error extracting attack features: {e}")
            return np.zeros(72)

    def _create_attack_packet(self):
        """Create packet with attack characteristics"""
        packet = {
            'timestamp': time.time(),
            'src_ip': self.fake.ipv4(),  # Random attacker IP
            'dst_ip': f"192.168.1.{random.randint(10, 50)}",  # Target network
            'src_port': random.randint(1024, 65535),
            'dst_port': 80,  # Common target
            'protocol': 6,   # TCP by default
            'length': 60,    # Will be adjusted by attack type
            'packet': None
        }
        
        # Adjust based on attack type
        if self.attack_type == "SYN Flood":
            packet['length'] = random.randint(40, 60)
        elif self.attack_type == "UDP Flood":
            packet['protocol'] = 17  # UDP
            packet['length'] = random.randint(1200, 1500)
        elif self.attack_type == "ICMP Flood (Ping Flood)":
            packet['protocol'] = 1   # ICMP
            packet['src_port'] = 0
            packet['dst_port'] = 0
            packet['length'] = random.randint(64, 128)
        elif self.attack_type == "HTTP Flood":
            packet['dst_port'] = 80
            packet['length'] = random.randint(800, 1200)
        elif self.attack_type == "Volumetric Attack":
            packet['length'] = random.randint(1400, 1500)
        
        return packet

    def _create_normal_packet(self):
        """Create normal traffic packet"""
        return {
            'timestamp': time.time(),
            'src_ip': f"192.168.1.{random.randint(100, 200)}",
            'dst_ip': f"192.168.1.{random.randint(10, 50)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443, 53, 22]),
            'protocol': random.choice([6, 17]),  # TCP or UDP
            'length': random.randint(200, 1000),
            'packet': None
        }
    
    def get_simulation_stats(self):
        """Get current simulation statistics"""
        return {
            'running': self.running,
            'attack_type': self.attack_type,
            'intensity': self.intensity * 100,
            'packet_rate': self.packet_rate,
            'estimated_detections_per_minute': self.packet_rate * 60 * self.intensity if self.attack_type != "Normal Traffic" else 0
        }

# For backward compatibility, create an alias
TrafficSimulator = EnhancedTrafficSimulator
import random
import time
import numpy as np
from threading import Thread
import streamlit as st
from collections import deque
import socket
import struct

class TrafficSimulator:
    """Simulate network traffic for testing DDoS detection system"""
    
    def __init__(self):
        self.is_running = False
        self.simulation_thread = None
        self.attack_intensity = 0.5  # 0 = no attack, 1 = full attack
        self.packet_rate = 10  # packets per second
        self.attack_types = ['SYN Flood', 'UDP Flood', 'HTTP Flood', 'ICMP Flood']
        self.current_attack_type = 'Normal Traffic'
        
        # Predefined IP pools
        self.legitimate_ips = [
            '192.168.1.100', '192.168.1.101', '192.168.1.102',
            '10.0.0.50', '10.0.0.51', '172.16.0.100'
        ]
        
        self.attacker_ips = [
            '45.33.32.156', '185.220.101.5', '198.96.155.3',
            '89.248.165.74', '103.90.227.36', '167.94.138.58'
        ]
        
        self.legitimate_ports = [80, 443, 22, 53, 993, 995, 143, 110]
        self.attack_ports = [80, 443, 22, 53]  # Common attack targets
        
    def generate_packet_info(self):
        """Generate realistic packet information"""
        current_time = time.time()
        
        # Determine if this should be an attack packet
        is_attack = random.random() < self.attack_intensity
        
        if is_attack:
            # Generate attack packet
            src_ip = random.choice(self.attacker_ips)
            dst_ip = random.choice(self.legitimate_ips)
            dst_port = random.choice(self.attack_ports)
            
            # Attack characteristics
            if self.current_attack_type == 'SYN Flood':
                protocol = 6  # TCP
                src_port = random.randint(1024, 65535)
                length = random.randint(40, 80)  # Small SYN packets
            elif self.current_attack_type == 'UDP Flood':
                protocol = 17  # UDP
                src_port = random.randint(1024, 65535)
                length = random.randint(64, 1500)  # Variable UDP sizes
            elif self.current_attack_type == 'HTTP Flood':
                protocol = 6  # TCP
                src_port = random.randint(1024, 65535)
                dst_port = 80
                length = random.randint(500, 1500)  # HTTP request sizes
            else:  # ICMP Flood
                protocol = 1  # ICMP
                src_port = 0
                dst_port = 0
                length = random.randint(64, 1024)
        else:
            # Generate legitimate packet
            src_ip = random.choice(self.legitimate_ips)
            dst_ip = random.choice(self.legitimate_ips)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(self.legitimate_ports)
            protocol = random.choice([6, 17])  # TCP or UDP
            length = random.randint(64, 1500)
        
        return {
            'timestamp': current_time,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'length': length,
            'packet': None  # Simulated packet object
        }
    
    def simulate_traffic_flow(self):
        """Simulate a complete network flow for testing"""
        # Generate a flow with multiple packets
        flow_packets = []
        base_packet = self.generate_packet_info()
        
        # Generate 5-20 packets for this flow
        packet_count = random.randint(5, 20)
        
        for i in range(packet_count):
            packet = base_packet.copy()
            packet['timestamp'] = base_packet['timestamp'] + (i * 0.1)
            
            # Add some variation to packet sizes
            if i == 0:
                packet['length'] = random.randint(64, 100)  # Initial packet
            else:
                packet['length'] = random.randint(200, 1500)  # Data packets
            
            flow_packets.append(packet)
        
        return flow_packets
    
    def extract_simulated_features(self, flow_packets):
        """Extract 72 features from simulated flow packets"""
        features = np.zeros(72)
        
        try:
            if not flow_packets:
                return features
            
            fwd_packets = flow_packets[:len(flow_packets)//2] if len(flow_packets) > 1 else flow_packets
            bwd_packets = flow_packets[len(flow_packets)//2:] if len(flow_packets) > 1 else []
            
            # Basic counts
            total_fwd = len(fwd_packets)
            total_bwd = len(bwd_packets)
            
            # Packet lengths
            fwd_lengths = [p['length'] for p in fwd_packets] if fwd_packets else [0]
            bwd_lengths = [p['length'] for p in bwd_packets] if bwd_packets else [0]
            all_lengths = fwd_lengths + bwd_lengths
            
            # Time calculations
            if len(flow_packets) > 1:
                flow_duration = flow_packets[-1]['timestamp'] - flow_packets[0]['timestamp']
            else:
                flow_duration = 0.1
            
            # Fill basic features
            features[0] = flow_duration
            features[1] = total_fwd
            features[2] = total_bwd
            features[3] = sum(fwd_lengths)
            features[4] = sum(bwd_lengths)
            
            # Forward packet statistics
            if fwd_lengths:
                features[5] = max(fwd_lengths)
                features[6] = min(fwd_lengths)
                features[7] = np.mean(fwd_lengths)
                features[8] = np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0
            
            # Backward packet statistics
            if bwd_lengths:
                features[9] = max(bwd_lengths)
                features[10] = min(bwd_lengths)
                features[11] = np.mean(bwd_lengths)
                features[12] = np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0
            
            # Flow rates
            features[13] = sum(all_lengths) / flow_duration if flow_duration > 0 else 0
            features[14] = len(flow_packets) / flow_duration if flow_duration > 0 else 0
            
            # IAT calculations (simplified)
            if len(flow_packets) > 1:
                timestamps = [p['timestamp'] for p in flow_packets]
                iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                
                features[15] = np.mean(iats)  # Flow IAT Mean
                features[16] = np.std(iats) if len(iats) > 1 else 0  # Flow IAT Std
                features[17] = max(iats)      # Flow IAT Max
                features[18] = min(iats)      # Flow IAT Min
            
            # Simulate TCP flags for attack detection
            protocol = flow_packets[0]['protocol']
            if protocol == 6:  # TCP
                if self.attack_intensity > 0.7:  # High attack intensity
                    features[42] = random.randint(0, 2)  # FIN flags
                    features[43] = random.randint(5, 15)  # SYN flags (high for SYN flood)
                    features[44] = random.randint(0, 1)  # RST flags
                    features[46] = random.randint(0, 3)  # ACK flags
                else:
                    features[42] = random.randint(0, 1)
                    features[43] = random.randint(0, 2)
                    features[44] = 0
                    features[46] = random.randint(1, 5)
            
            # Fill remaining features with calculated/estimated values
            features[35] = total_fwd / flow_duration if flow_duration > 0 else 0
            features[36] = total_bwd / flow_duration if flow_duration > 0 else 0
            features[37] = min(all_lengths) if all_lengths else 0
            features[38] = max(all_lengths) if all_lengths else 0
            features[39] = np.mean(all_lengths) if all_lengths else 0
            features[40] = np.std(all_lengths) if len(all_lengths) > 1 else 0
            
            # For remaining features, use attack-indicating patterns
            if self.attack_intensity > 0.5:
                # High packet rates, small packets, high frequency patterns
                features[50] = total_bwd / max(total_fwd, 1)  # Down/Up ratio
                features[51] = np.mean(all_lengths) if all_lengths else 0
                features[69] = flow_duration * 0.8  # Active time
                features[71] = flow_duration  # Active max
            else:
                # Normal traffic patterns
                features[50] = 1.0  # Balanced ratio
                features[51] = np.mean(all_lengths) if all_lengths else 0
                features[69] = flow_duration * 0.3
                features[71] = flow_duration * 0.6
            
            # Ensure no NaN or inf values
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
            
            return features[:72]  # Ensure exactly 72 features
            
        except Exception as e:
            print(f"Error extracting simulated features: {e}")
            return np.zeros(72)
    
    def generate_flow_data(self):
        """Generate complete flow data for testing"""
        flow_packets = self.simulate_traffic_flow()
        features = self.extract_simulated_features(flow_packets)
        
        base_packet = flow_packets[0]
        
        return {
            'timestamp': time.time(),
            'src_ip': base_packet['src_ip'],
            'dst_ip': base_packet['dst_ip'],
            'src_port': base_packet['src_port'],
            'dst_port': base_packet['dst_port'],
            'protocol': base_packet['protocol'],
            'features': features
        }
    
    def start_simulation(self, flow_queue):
        """Start traffic simulation"""
        self.is_running = True
        
        def simulation_loop():
            while self.is_running:
                try:
                    # Generate flow data
                    flow_data = self.generate_flow_data()
                    
                    # Add to queue for processing
                    if not flow_queue.full():
                        flow_queue.put(flow_data)
                    
                    # Wait based on packet rate
                    wait_time = 1.0 / self.packet_rate
                    time.sleep(wait_time)
                    
                except Exception as e:
                    print(f"Simulation error: {e}")
                    time.sleep(1)
        
        self.simulation_thread = Thread(target=simulation_loop, daemon=True)
        self.simulation_thread.start()
    
    def stop_simulation(self):
        """Stop traffic simulation"""
        self.is_running = False
    
    def set_attack_parameters(self, attack_type, intensity, packet_rate):
        """Set attack simulation parameters"""
        self.current_attack_type = attack_type
        self.attack_intensity = intensity
        self.packet_rate = packet_rate
    
    def get_simulation_stats(self):
        """Get current simulation statistics"""
        return {
            'running': self.is_running,
            'attack_type': self.current_attack_type,
            'attack_intensity': self.attack_intensity,
            'packet_rate': self.packet_rate,
            'estimated_packets_per_minute': self.packet_rate * 60
        }
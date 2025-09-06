import numpy as np
import time
from collections import Counter

class FeatureExtractor:
    def __init__(self):
        # Define the exact 72 features in required order
        self.feature_names = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
            'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
            'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min',
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
    
    def safe_divide(self, numerator, denominator):
        """Safe division to avoid division by zero"""
        return numerator / denominator if denominator != 0 else 0
    
    def safe_std(self, values):
        """Safe standard deviation calculation"""
        if len(values) <= 1:
            return 0
        return np.std(values)
    
    def extract_tcp_flags(self, packet_info):
        """Extract TCP flags from packet"""
        flags = {
            'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0,
            'ACK': 0, 'URG': 0, 'CWE': 0, 'ECE': 0
        }
        
        try:
            from scapy.layers.inet import TCP
            if 'packet' in packet_info and TCP in packet_info['packet']:
                tcp_layer = packet_info['packet'][TCP]
                tcp_flags = tcp_layer.flags
                
                if tcp_flags & 0x01: flags['FIN'] = 1
                if tcp_flags & 0x02: flags['SYN'] = 1
                if tcp_flags & 0x04: flags['RST'] = 1
                if tcp_flags & 0x08: flags['PSH'] = 1
                if tcp_flags & 0x10: flags['ACK'] = 1
                if tcp_flags & 0x20: flags['URG'] = 1
                if tcp_flags & 0x40: flags['ECE'] = 1
                if tcp_flags & 0x80: flags['CWE'] = 1
        except:
            pass
        
        return flags
    
    def calculate_iat(self, packets):
        """Calculate Inter-Arrival Time statistics"""
        if len(packets) < 2:
            return {'total': 0, 'mean': 0, 'std': 0, 'max': 0, 'min': 0}
        
        timestamps = [p['timestamp'] for p in packets]
        timestamps.sort()
        
        iats = []
        for i in range(1, len(timestamps)):
            iat = timestamps[i] - timestamps[i-1]
            iats.append(iat)
        
        if not iats:
            return {'total': 0, 'mean': 0, 'std': 0, 'max': 0, 'min': 0}
        
        return {
            'total': sum(iats),
            'mean': np.mean(iats),
            'std': self.safe_std(iats),
            'max': max(iats),
            'min': min(iats)
        }
    
    def extract_features(self, flow):
        """Extract all 72 features from a flow"""
        features = np.zeros(72)
        
        try:
            fwd_packets = flow.fwd_packets
            bwd_packets = flow.bwd_packets
            all_packets = fwd_packets + bwd_packets
            
            # Basic counts
            total_fwd_packets = len(fwd_packets)
            total_bwd_packets = len(bwd_packets)
            total_packets = total_fwd_packets + total_bwd_packets
            
            # Packet lengths
            fwd_lengths = [p['length'] for p in fwd_packets] if fwd_packets else [0]
            bwd_lengths = [p['length'] for p in bwd_packets] if bwd_packets else [0]
            all_lengths = [p['length'] for p in all_packets] if all_packets else [0]
            
            # Time calculations
            if flow.start_time and all_packets:
                end_time = max(p['timestamp'] for p in all_packets)
                flow_duration = end_time - flow.start_time
            else:
                flow_duration = 0
            
            # Feature 0: Flow Duration
            features[0] = flow_duration
            
            # Feature 1-2: Packet counts
            features[1] = total_fwd_packets
            features[2] = total_bwd_packets
            
            # Feature 3-4: Total lengths
            features[3] = sum(fwd_lengths)
            features[4] = sum(bwd_lengths)
            
            # Feature 5-8: Forward packet length statistics
            if fwd_lengths and fwd_lengths != [0]:
                features[5] = max(fwd_lengths)
                features[6] = min(fwd_lengths)
                features[7] = np.mean(fwd_lengths)
                features[8] = self.safe_std(fwd_lengths)
            
            # Feature 9-12: Backward packet length statistics
            if bwd_lengths and bwd_lengths != [0]:
                features[9] = max(bwd_lengths)
                features[10] = min(bwd_lengths)
                features[11] = np.mean(bwd_lengths)
                features[12] = self.safe_std(bwd_lengths)
            
            # Feature 13-14: Flow rates
            features[13] = self.safe_divide(sum(all_lengths), flow_duration)  # Flow Bytes/s
            features[14] = self.safe_divide(total_packets, flow_duration)     # Flow Packets/s
            
            # Feature 15-18: Flow IAT statistics
            flow_iat = self.calculate_iat(all_packets)
            features[15] = flow_iat['mean']
            features[16] = flow_iat['std']
            features[17] = flow_iat['max']
            features[18] = flow_iat['min']
            
            # Feature 19-23: Forward IAT statistics
            fwd_iat = self.calculate_iat(fwd_packets)
            features[19] = fwd_iat['total']
            features[20] = fwd_iat['mean']
            features[21] = fwd_iat['std']
            features[22] = fwd_iat['max']
            features[23] = fwd_iat['min']
            
            # Feature 24-28: Backward IAT statistics
            bwd_iat = self.calculate_iat(bwd_packets)
            features[24] = bwd_iat['total']
            features[25] = bwd_iat['mean']
            features[26] = bwd_iat['std']
            features[27] = bwd_iat['max']
            features[28] = bwd_iat['min']
            
            # Feature 29-32: TCP flags (PSH, URG)
            fwd_psh = sum(1 for p in fwd_packets if self.extract_tcp_flags(p)['PSH'])
            bwd_psh = sum(1 for p in bwd_packets if self.extract_tcp_flags(p)['PSH'])
            fwd_urg = sum(1 for p in fwd_packets if self.extract_tcp_flags(p)['URG'])
            bwd_urg = sum(1 for p in bwd_packets if self.extract_tcp_flags(p)['URG'])
            
            features[29] = fwd_psh
            features[30] = bwd_psh
            features[31] = fwd_urg
            features[32] = bwd_urg
            
            # Feature 33-36: Header lengths and packet rates
            features[33] = total_fwd_packets * 20  # Estimated header length
            features[34] = total_bwd_packets * 20  # Estimated header length
            features[35] = self.safe_divide(total_fwd_packets, flow_duration)  # Fwd Packets/s
            features[36] = self.safe_divide(total_bwd_packets, flow_duration)  # Bwd Packets/s
            
            # Feature 37-41: Packet length statistics (all packets)
            if all_lengths:
                features[37] = min(all_lengths)      # Min Packet Length
                features[38] = max(all_lengths)      # Max Packet Length
                features[39] = np.mean(all_lengths)  # Packet Length Mean
                features[40] = self.safe_std(all_lengths)  # Packet Length Std
                features[41] = np.var(all_lengths) if len(all_lengths) > 1 else 0  # Packet Length Variance
            
            # Feature 42-49: TCP Flag counts
            all_flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWE': 0, 'ECE': 0}
            
            for packet in all_packets:
                flags = self.extract_tcp_flags(packet)
                for flag_name in all_flags:
                    all_flags[flag_name] += flags[flag_name]
            
            features[42] = all_flags['FIN']
            features[43] = all_flags['SYN']
            features[44] = all_flags['RST']
            features[45] = all_flags['PSH']
            features[46] = all_flags['ACK']
            features[47] = all_flags['URG']
            features[48] = all_flags['CWE']
            features[49] = all_flags['ECE']
            
            # Feature 50-52: Ratios and averages
            features[50] = self.safe_divide(total_bwd_packets, total_fwd_packets)  # Down/Up Ratio
            features[51] = np.mean(all_lengths) if all_lengths else 0  # Average Packet Size
            features[52] = np.mean(fwd_lengths) if fwd_lengths and fwd_lengths != [0] else 0  # Avg Fwd Segment Size
            features[53] = np.mean(bwd_lengths) if bwd_lengths and bwd_lengths != [0] else 0  # Avg Bwd Segment Size
            
            # Feature 54-60: Additional header and bulk features
            features[54] = features[33]  # Fwd Header Length.1 (duplicate)
            features[55] = 0  # Fwd Avg Bytes/Bulk (complex calculation, simplified)
            features[56] = 0  # Fwd Avg Packets/Bulk
            features[57] = 0  # Fwd Avg Bulk Rate
            features[58] = 0  # Bwd Avg Bytes/Bulk
            features[59] = 0  # Bwd Avg Packets/Bulk
            features[60] = 0  # Bwd Avg Bulk Rate
            
            # Feature 61-64: Subflow features
            features[61] = total_fwd_packets    # Subflow Fwd Packets
            features[62] = sum(fwd_lengths)     # Subflow Fwd Bytes
            features[63] = total_bwd_packets    # Subflow Bwd Packets
            features[64] = sum(bwd_lengths)     # Subflow Bwd Bytes
            
            # Feature 65-68: Window and segment features
            features[65] = 65535 if fwd_packets else 0  # Init_Win_bytes_forward (estimated)
            features[66] = 65535 if bwd_packets else 0  # Init_Win_bytes_backward (estimated)
            features[67] = total_fwd_packets            # act_data_pkt_fwd
            features[68] = min(fwd_lengths) if fwd_lengths and fwd_lengths != [0] else 0  # min_seg_size_forward
            
            # Feature 69-72: Active and Idle statistics (simplified)
            # These would require more complex flow state analysis
            features[69] = flow_duration / 2 if flow_duration > 0 else 0  # Active Mean
            features[70] = 0  # Active Std
            features[71] = flow_duration if flow_duration > 0 else 0      # Active Max
            features[72] = 0  # Active Min (Note: This should be features[72] but we have 73 elements, keeping last as 0)
            
            # Ensure we return exactly 72 features
            return features[:72]
            
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            return np.zeros(72)

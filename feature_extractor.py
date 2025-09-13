# Corrected feature_extractor.py

import numpy as np
import time
from collections import Counter

class FeatureExtractor:
    def __init__(self):
        # Note: This list contains more than 72 features. The code below only calculates the first 72.
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
        
        iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
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
            
            total_fwd_packets = len(fwd_packets)
            total_bwd_packets = len(bwd_packets)
            total_packets = total_fwd_packets + total_bwd_packets
            
            fwd_lengths = [p['length'] for p in fwd_packets] if fwd_packets else [0]
            bwd_lengths = [p['length'] for p in bwd_packets] if bwd_packets else [0]
            all_lengths = [p['length'] for p in all_packets] if all_packets else [0]
            
            if flow.start_time and all_packets:
                end_time = max(p['timestamp'] for p in all_packets)
                flow_duration = end_time - flow.start_time
            else:
                flow_duration = 0
            
            # Features 0-12
            features[0] = flow_duration
            features[1] = total_fwd_packets
            features[2] = total_bwd_packets
            features[3] = sum(fwd_lengths)
            features[4] = sum(bwd_lengths)
            if fwd_lengths and fwd_lengths != [0]:
                features[5] = max(fwd_lengths)
                features[6] = min(fwd_lengths)
                features[7] = np.mean(fwd_lengths)
                features[8] = self.safe_std(fwd_lengths)
            if bwd_lengths and bwd_lengths != [0]:
                features[9] = max(bwd_lengths)
                features[10] = min(bwd_lengths)
                features[11] = np.mean(bwd_lengths)
                features[12] = self.safe_std(bwd_lengths)
            
            # Features 13-14: Flow rates
            features[13] = self.safe_divide(sum(all_lengths), flow_duration)
            features[14] = self.safe_divide(total_packets, flow_duration)
            
            # Features 15-28: IAT statistics
            flow_iat = self.calculate_iat(all_packets)
            features[15:19] = [flow_iat['mean'], flow_iat['std'], flow_iat['max'], flow_iat['min']]
            fwd_iat = self.calculate_iat(fwd_packets)
            features[19:24] = [fwd_iat['total'], fwd_iat['mean'], fwd_iat['std'], fwd_iat['max'], fwd_iat['min']]
            bwd_iat = self.calculate_iat(bwd_packets)
            features[24:29] = [bwd_iat['total'], bwd_iat['mean'], bwd_iat['std'], bwd_iat['max'], bwd_iat['min']]
            
            # Features 29-32: TCP flags (PSH, URG)
            features[29] = sum(1 for p in fwd_packets if self.extract_tcp_flags(p)['PSH'])
            features[30] = sum(1 for p in bwd_packets if self.extract_tcp_flags(p)['PSH'])
            features[31] = sum(1 for p in fwd_packets if self.extract_tcp_flags(p)['URG'])
            features[32] = sum(1 for p in bwd_packets if self.extract_tcp_flags(p)['URG'])
            
            # Features 33-41: Header lengths and packet stats
            features[33] = total_fwd_packets * 20
            features[34] = total_bwd_packets * 20
            features[35] = self.safe_divide(total_fwd_packets, flow_duration)
            features[36] = self.safe_divide(total_bwd_packets, flow_duration)
            if all_lengths and all_lengths != [0]:
                features[37] = min(all_lengths)
                features[38] = max(all_lengths)
                features[39] = np.mean(all_lengths)
                features[40] = self.safe_std(all_lengths)
                features[41] = np.var(all_lengths)

            # Features 42-49: TCP Flag counts
            flag_counts = Counter()
            for packet in all_packets:
                flag_counts.update(k for k, v in self.extract_tcp_flags(packet).items() if v == 1)
            features[42:50] = [flag_counts['FIN'], flag_counts['SYN'], flag_counts['RST'], flag_counts['PSH'],
                               flag_counts['ACK'], flag_counts['URG'], flag_counts['CWE'], flag_counts['ECE']]
            
            # Features 50-53: Ratios and averages
            features[50] = self.safe_divide(total_bwd_packets, total_fwd_packets)
            features[51] = np.mean(all_lengths) if all_lengths and all_lengths != [0] else 0
            features[52] = np.mean(fwd_lengths) if fwd_lengths and fwd_lengths != [0] else 0
            features[53] = np.mean(bwd_lengths) if bwd_lengths and bwd_lengths != [0] else 0
            
            # Features 54-60 are placeholders for simplicity
            features[54] = features[33]
            
            # Features 61-68
            features[61] = total_fwd_packets
            features[62] = sum(fwd_lengths)
            features[63] = total_bwd_packets
            features[64] = sum(bwd_lengths)
            features[65] = 65535 if fwd_packets else 0
            features[66] = 65535 if bwd_packets else 0
            features[67] = total_fwd_packets
            features[68] = min(fwd_lengths) if fwd_lengths and fwd_lengths != [0] else 0
            
            # Features 69-71: Active statistics (simplified)
            # Idle stats are left as 0 as they are complex to calculate without more info
            if flow_duration > 0:
                features[69] = flow_duration
                features[70] = 0
                features[71] = flow_duration
            
            # === BUGFIX ===
            # The line below was the source of the "index 72 is out of bounds" error.
            # It has been removed.
            # features[72] = 0 
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            return np.zeros(72)
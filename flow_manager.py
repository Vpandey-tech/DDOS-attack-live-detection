import time
import threading
from collections import defaultdict, deque
from feature_extractor import FeatureExtractor

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Use simple lists, but we generally process often so they don't grow indefinitely
        self.fwd_packets = []
        self.bwd_packets = []
        self.start_time = None
        self.last_activity = time.time()
        
    def add_packet(self, packet_info):
        """Add packet to flow"""
        if self.start_time is None:
            self.start_time = packet_info['timestamp']
        
        # Determine packet direction
        if (packet_info['src_ip'] == self.src_ip and 
            packet_info['dst_ip'] == self.dst_ip and
            packet_info['src_port'] == self.src_port and
            packet_info['dst_port'] == self.dst_port):
            # Forward direction
            self.fwd_packets.append(packet_info)
        else:
            # Backward direction
            self.bwd_packets.append(packet_info)
        
        self.last_activity = packet_info['timestamp']
    
    def get_flow_key(self):
        """Get unique flow identifier"""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)
    
    def is_expired(self, timeout):
        """Check if flow has expired"""
        return time.time() - self.last_activity > timeout

class FlowManager:
    def __init__(self, flow_queue, timeout=10):
        self.flows = {}
        # Ensure flow_queue is treated safely; if it's a Queue, this is fine
        self.flow_queue = flow_queue
        self.timeout = timeout
        self.feature_extractor = FeatureExtractor()
        # Use RLock for reentrant safety
        self.lock = threading.RLock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_flows, daemon=True)
        self.cleanup_thread.start()
    
    def add_packet(self, packet_info):
        """Add packet to appropriate flow"""
        with self.lock:
            # Create flow key (bidirectional)
            flow_key1 = (
                packet_info['src_ip'], packet_info['dst_ip'],
                packet_info['src_port'], packet_info['dst_port'],
                packet_info['protocol']
            )
            flow_key2 = (
                packet_info['dst_ip'], packet_info['src_ip'],
                packet_info['dst_port'], packet_info['src_port'],
                packet_info['protocol']
            )
            
            # Check if flow already exists (either direction)
            flow = None
            flow_key = None
            
            if flow_key1 in self.flows:
                flow = self.flows[flow_key1]
                flow_key = flow_key1
            elif flow_key2 in self.flows:
                flow = self.flows[flow_key2]
                flow_key = flow_key2
            else:
                # Create new flow
                flow = Flow(
                    packet_info['src_ip'], packet_info['dst_ip'],
                    packet_info['src_port'], packet_info['dst_port'],
                    packet_info['protocol']
                )
                flow_key = flow_key1
                self.flows[flow_key] = flow
            
            # Add packet to flow
            flow.add_packet(packet_info)
    
    def _cleanup_expired_flows(self):
        """Clean up expired flows and extract features"""
        while True:
            try:
                current_time = time.time()
                expired_flows = []
                
                # Minimize lock time: Identify expired first
                with self.lock:
                    # Create a snapshot of keys to iterate safely
                    keys = list(self.flows.keys())
                    for flow_key in keys:
                        flow = self.flows.get(flow_key)
                        if flow and flow.is_expired(self.timeout):
                            expired_flows.append((flow_key, flow))
                            
                    # Remove from main dict immediately
                    for k, _ in expired_flows:
                        del self.flows[k]
                
                # Process strictly OUTSIDE the lock to avoid blocking capture threads
                for flow_key, flow in expired_flows:
                    self._process_flow(flow)
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                print(f"Error in cleanup thread: {str(e)}")
                time.sleep(1)
    
    def _process_flow(self, flow):
        """Extract features from flow and add to queue"""
        try:
            # Only process flows with sufficient packets (min 2 for meaning)
            if len(flow.fwd_packets) + len(flow.bwd_packets) >= 2:
                features = self.feature_extractor.extract_features(flow)
                
                flow_data = {
                    'timestamp': time.time(),
                    'src_ip': flow.src_ip,
                    'dst_ip': flow.dst_ip,
                    'src_port': flow.src_port,
                    'dst_port': flow.dst_port,
                    'protocol': flow.protocol,
                    'features': features
                }
                
                # Add to processing queue
                self.flow_queue.put(flow_data)
                
        except Exception as e:
            print(f"Error processing flow: {str(e)}")

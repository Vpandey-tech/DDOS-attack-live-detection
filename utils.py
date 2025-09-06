import time
import socket
import struct

def get_network_interfaces():
    """Get available network interfaces"""
    try:
        import netifaces
        interfaces = netifaces.interfaces()
        return interfaces
    except ImportError:
        # Fallback to common interface names
        return ["lo", "eth0", "wlan0", "any"]

def ip_to_int(ip_string):
    """Convert IP string to integer"""
    try:
        return struct.unpack("!I", socket.inet_aton(ip_string))[0]
    except:
        return 0

def int_to_ip(ip_int):
    """Convert integer to IP string"""
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except:
        return "0.0.0.0"

def format_bytes(bytes_value):
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"

def calculate_throughput(packets, duration):
    """Calculate network throughput"""
    if duration <= 0:
        return 0
    
    total_bytes = sum(packet.get('length', 0) for packet in packets)
    return total_bytes / duration

def validate_flow_data(flow_data):
    """Validate flow data before processing"""
    required_fields = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'features']
    
    for field in required_fields:
        if field not in flow_data:
            return False, f"Missing required field: {field}"
    
    # Validate features array
    if len(flow_data['features']) != 72:
        return False, f"Expected 72 features, got {len(flow_data['features'])}"
    
    return True, "Valid"

def log_detection_result(result):
    """Log detection result for debugging"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result['timestamp']))
    print(f"[{timestamp}] {result['src_ip']}:{result['src_port']} -> "
          f"{result['dst_ip']}:{result['dst_port']} | "
          f"Prediction: {result['final_prediction']} | "
          f"Threat Level: {result['threat_level']}")

class PerformanceMonitor:
    """Monitor system performance metrics"""
    
    def __init__(self):
        self.start_time = time.time()
        self.packet_count = 0
        self.flow_count = 0
        self.prediction_count = 0
        self.last_reset = time.time()
    
    def record_packet(self):
        """Record a processed packet"""
        self.packet_count += 1
    
    def record_flow(self):
        """Record a processed flow"""
        self.flow_count += 1
    
    def record_prediction(self):
        """Record a model prediction"""
        self.prediction_count += 1
    
    def get_statistics(self):
        """Get performance statistics"""
        current_time = time.time()
        elapsed = current_time - self.last_reset
        
        if elapsed <= 0:
            return {
                'packets_per_second': 0,
                'flows_per_second': 0,
                'predictions_per_second': 0,
                'uptime': current_time - self.start_time
            }
        
        return {
            'packets_per_second': self.packet_count / elapsed,
            'flows_per_second': self.flow_count / elapsed,
            'predictions_per_second': self.prediction_count / elapsed,
            'uptime': current_time - self.start_time
        }
    
    def reset_counters(self):
        """Reset performance counters"""
        self.packet_count = 0
        self.flow_count = 0
        self.prediction_count = 0
        self.last_reset = time.time()

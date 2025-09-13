import numpy as np
import pickle
import os
import tensorflow as tf
import torch
import torch.nn as nn
from tensorflow.keras.layers import Layer
from tensorflow.keras.utils import custom_object_scope
import warnings
import time
from collections import deque

warnings.filterwarnings(action='ignore', category=UserWarning)
warnings.filterwarnings(action='ignore', category=FutureWarning)

class ExpandDimsLayer(Layer):
    """Custom Keras layer required to load the lucid.h5 model."""
    def __init__(self, axis=-1, **kwargs):
        super(ExpandDimsLayer, self).__init__(**kwargs)
        self.axis = axis
    
    def call(self, inputs):
        return tf.expand_dims(inputs, axis=self.axis)
    
    def get_config(self):
        config = super(ExpandDimsLayer, self).get_config()
        config.update({'axis': self.axis})
        return config

class Autoencoder(nn.Module):
    """PyTorch Autoencoder architecture, must match the training script."""
    def __init__(self, input_dim=72, encoding_dim=32, hidden_dims=[128, 64]):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dims[0]), nn.ReLU(),
            nn.Linear(hidden_dims[0], hidden_dims[1]), nn.ReLU(),
            nn.Linear(hidden_dims[1], encoding_dim)
        )
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, hidden_dims[1]), nn.ReLU(),
            nn.Linear(hidden_dims[1], hidden_dims[0]), nn.ReLU(),
            nn.Linear(hidden_dims[0], input_dim), nn.Sigmoid()
        )
    def forward(self, x):
        return self.decoder(self.encoder(x))

class ModelInference:
    def __init__(self):
        self.lucid_model = None
        self.lucid_scaler = None
        self.autoencoder_model = None
        self.autoencoder_scaler = None
        
        # Updated thresholds based on your normal traffic analysis
        self.LUCID_THRESHOLD = 0.3              # Below 99th percentile
        self.AUTOENCODER_THRESHOLD = 500       # Slightly above 99th percentile
        
        # False positive prevention
        self.attack_history = deque(maxlen=5)   # Track last 5 predictions
        self.last_alert_time = 0
        self.ALERT_COOLDOWN = 10                # Wait 10 seconds between alerts
        self.MIN_CONSECUTIVE_ATTACKS = 3        # Need 3+ attacks in window
        
        self.load_models()
    
    def load_models(self):
        """Loads both pre-trained models and their corresponding scalers."""
        try:
            print("Loading LucidCNN model...")
            with custom_object_scope({'ExpandDimsLayer': ExpandDimsLayer}):
                self.lucid_model = tf.keras.models.load_model('lucid.h5', compile=False)
            
            with open('lucid.pkl', 'rb') as f:
                self.lucid_scaler = pickle.load(f)
            print("✅ LucidCNN model loaded successfully")
            
            print("Loading AutoEncoder model...")
            with open('auto.pkl', 'rb') as f:
                auto_data = pickle.load(f)
                self.autoencoder_scaler = auto_data['scaler']
            
            input_dim = self.lucid_scaler.n_features_in_
            self.autoencoder_model = Autoencoder(input_dim=input_dim)
            self.autoencoder_model.load_state_dict(torch.load('auto.pth', map_location='cpu'))
            self.autoencoder_model.eval()
            print("✅ AutoEncoder model loaded successfully")
            
        except Exception as e:
            print(f"❌ CRITICAL ERROR during model loading: {e}")
            raise

    def _is_heavy_usage_flow(self, features):
        """Detect if this might be legitimate heavy usage (streaming, downloads)"""
        # Large average packet size + consistent timing = likely streaming/download
        avg_packet_size = features[39] if len(features) > 39 else 0
        flow_bytes_per_sec = features[13] if len(features) > 13 else 0
        
        # If large packets with high throughput but not extreme rates, likely legitimate
        if avg_packet_size > 800 and flow_bytes_per_sec > 1000000:  # 1MB/s
            packet_rate = features[14] if len(features) > 14 else 0
            if packet_rate < 1000:  # Not extremely high packet rate
                return True
        return False

    def predict(self, features):
        """Performs prediction with false positive prevention."""
        try:
            features_np = np.array(features).reshape(1, -1)
            features_np = np.nan_to_num(features_np, nan=0.0, posinf=0.0, neginf=0.0)

            # LucidCNN Prediction
            lucid_features = self.lucid_scaler.transform(features_np)
            lucid_confidence = self.lucid_model.predict(lucid_features, verbose=0)[0][0]
            lucid_class = "Attack" if lucid_confidence > self.LUCID_THRESHOLD else "Benign"
            
            # AutoEncoder Anomaly Detection
            auto_features = self.autoencoder_scaler.transform(features_np)
            auto_input = torch.FloatTensor(auto_features)
            
            with torch.no_grad():
                reconstructed = self.autoencoder_model(auto_input)
                error = torch.mean((auto_input - reconstructed) ** 2).item()
            
            is_anomaly = error > self.AUTOENCODER_THRESHOLD
            
            # Check if this might be legitimate heavy usage
            is_heavy_usage = self._is_heavy_usage_flow(features)
            
            # Initial prediction
            both_models_agree = lucid_class == "Attack" and is_anomaly
            
            # Add to history
            current_time = time.time()
            self.attack_history.append({
                'time': current_time,
                'is_attack': both_models_agree and not is_heavy_usage,
                'confidence': lucid_confidence,
                'error': error
            })
            
            # Count recent attacks (last 10 seconds)
            recent_attacks = sum(1 for h in self.attack_history 
                               if current_time - h['time'] < 10 and h['is_attack'])
            
            # Final decision with temporal logic
            final_prediction = "Benign"
            threat_level = "LOW"
            
            if recent_attacks >= self.MIN_CONSECUTIVE_ATTACKS:
                # Multiple attacks in short time = likely real attack
                if current_time - self.last_alert_time > self.ALERT_COOLDOWN:
                    final_prediction = "Attack"
                    threat_level = "HIGH"
                    self.last_alert_time = current_time
                else:
                    # In cooldown period
                    final_prediction = "Attack (Cooldown)"
                    threat_level = "MEDIUM"
            elif both_models_agree and not is_heavy_usage:
                # Single detection without pattern
                threat_level = "MEDIUM"
            elif is_heavy_usage:
                # Detected as heavy usage, likely legitimate
                threat_level = "LOW"
                final_prediction = "Heavy Usage (Benign)"

            print(f"L_Score: {lucid_confidence:.2f} | AE_Error: {error:.2f} | Recent_Attacks: {recent_attacks} | Final: {final_prediction}")

            return {
                'lucid_prediction': lucid_class,
                'lucid_confidence': float(lucid_confidence),
                'autoencoder_anomaly': is_anomaly,
                'reconstruction_error': float(error),
                'final_prediction': final_prediction,
                'threat_level': threat_level,
                'recent_attack_count': recent_attacks,
                'is_heavy_usage': is_heavy_usage
            }
            
        except Exception as e:
            print(f"Error during model inference: {e}")
            return {
                'lucid_prediction': "Error", 'lucid_confidence': 0.0,
                'autoencoder_anomaly': False, 'reconstruction_error': 0.0,
                'final_prediction': "Error", 'threat_level': "UNKNOWN",
                'recent_attack_count': 0, 'is_heavy_usage': False
            }
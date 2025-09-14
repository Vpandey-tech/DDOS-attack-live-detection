# model_inference.py

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
        
        # === MODIFIED: Replaced static thresholds with dynamic ones ===
        self.LUCID_THRESHOLD = 0.5  # Fixed threshold for LucidCNN is still okay
        
        # Adaptive thresholding state
        self.baseline_errors = deque(maxlen=1000) # Store up to 1000 normal errors
        self.current_autoencoder_threshold = 500.0  # A safe default, will be replaced by calibration
        self.k_multiplier = 3.0  # Sensitivity: mean + (3 * std_dev)
        # =============================================================
        
        # False positive prevention
        self.attack_history = deque(maxlen=5)
        self.last_alert_time = 0
        self.ALERT_COOLDOWN = 10
        self.MIN_CONSECUTIVE_ATTACKS = 3
        
        self.load_models()

    # === NEW METHOD: To initialize the baseline from app.py ===
    def initialize_baseline(self, initial_errors):
        """
        Accepts a list of errors from the initial calibration period
        and calculates the first dynamic threshold.
        """
        if not initial_errors:
            print("⚠️ WARNING: Calibration finished with no data. Using default threshold.")
            return
            
        self.baseline_errors.extend(initial_errors)
        self.recalculate_threshold()
    # =============================================================

    # === NEW METHOD: To calculate the dynamic threshold ===
    def recalculate_threshold(self):
        """
        Calculates a new dynamic threshold based on the mean and standard deviation
        of the collected normal traffic errors.
        """
        if len(self.baseline_errors) > 30:  # Need enough data for a meaningful calculation
            mean = np.mean(self.baseline_errors)
            std_dev = np.std(self.baseline_errors)
            self.current_autoencoder_threshold = mean + (self.k_multiplier * std_dev)
            
            # Sanity check: ensure threshold is not excessively low
            if self.current_autoencoder_threshold < 10:
                self.current_autoencoder_threshold = 10
                
            print(f"✅ ADAPTIVE THRESHOLD UPDATED: New Threshold = {self.current_autoencoder_threshold:.4f} (μ={mean:.4f}, σ={std_dev:.4f})")
        else:
            print("Insufficient baseline data to update threshold. Need > 30 samples.")
    # =============================================================
    
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
        avg_packet_size = features[39] if len(features) > 39 else 0
        flow_bytes_per_sec = features[13] if len(features) > 13 else 0
        
        if avg_packet_size > 800 and flow_bytes_per_sec > 1000000:
            packet_rate = features[14] if len(features) > 14 else 0
            if packet_rate < 1000:
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
            
            # === MODIFIED: Use the dynamic threshold ===
            is_anomaly = error > self.current_autoencoder_threshold
            # ==========================================
            
            is_heavy_usage = self._is_heavy_usage_flow(features)
            both_models_agree = lucid_class == "Attack" and is_anomaly
            current_time = time.time()
            
            self.attack_history.append({
                'time': current_time,
                'is_attack': both_models_agree and not is_heavy_usage,
                'confidence': lucid_confidence,
                'error': error
            })
            
            recent_attacks = sum(1 for h in self.attack_history 
                               if current_time - h['time'] < 10 and h['is_attack'])
            
            final_prediction = "Benign"
            threat_level = "LOW"
            
            if recent_attacks >= self.MIN_CONSECUTIVE_ATTACKS:
                if current_time - self.last_alert_time > self.ALERT_COOLDOWN:
                    final_prediction = "Attack"
                    threat_level = "HIGH"
                    self.last_alert_time = current_time
                else:
                    final_prediction = "Attack (Cooldown)"
                    threat_level = "MEDIUM"
            elif both_models_agree and not is_heavy_usage:
                threat_level = "MEDIUM"
            elif is_heavy_usage:
                threat_level = "LOW"
                final_prediction = "Heavy Usage (Benign)"

            # === NEW: Continuous learning ===
            # If the final verdict is a low threat, add its error to our baseline to keep learning.
            if threat_level == 'LOW':
                self.baseline_errors.append(error)
                # Periodically recalculate the threshold based on new normal data
                if len(self.baseline_errors) % 100 == 0:
                    self.recalculate_threshold()
            # ===============================

            # print(f"L_Score: {lucid_confidence:.2f} | AE_Error: {error:.2f} | THR: {self.current_autoencoder_threshold:.2f} | Final: {final_prediction}")

            return {
                'lucid_prediction': lucid_class,
                'lucid_confidence': float(lucid_confidence),
                'autoencoder_anomaly': is_anomaly,
                'reconstruction_error': float(error),
                'final_prediction': final_prediction,
                'threat_level': threat_level,
                'recent_attack_count': recent_attacks,
                'is_heavy_usage': is_heavy_usage,
                'current_threshold': self.current_autoencoder_threshold
            }
            
        except Exception as e:
            print(f"Error during model inference: {e}")
            return {
                'lucid_prediction': "Error", 'lucid_confidence': 0.0,
                'autoencoder_anomaly': False, 'reconstruction_error': 0.0,
                'final_prediction': "Error", 'threat_level': "UNKNOWN",
                'recent_attack_count': 0, 'is_heavy_usage': False,
                'current_threshold': self.current_autoencoder_threshold
            }
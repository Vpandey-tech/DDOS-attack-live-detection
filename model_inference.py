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
from typing import List, Dict, Any, Optional, Union

# Suppress Warnings for cleaner logs
warnings.filterwarnings(action='ignore', category=UserWarning)
warnings.filterwarnings(action='ignore', category=FutureWarning)

class ExpandDimsLayer(Layer):
    """Custom Keras layer required to load the lucid.h5 model."""
    def __init__(self, axis: int = -1, **kwargs):
        super(ExpandDimsLayer, self).__init__(**kwargs)
        self.axis = axis
    
    def call(self, inputs: tf.Tensor) -> tf.Tensor:
        return tf.expand_dims(inputs, axis=self.axis)
    
    def get_config(self) -> Dict[str, Any]:
        config = super(ExpandDimsLayer, self).get_config()
        config.update({'axis': self.axis})
        return config

class Autoencoder(nn.Module):
    """PyTorch Autoencoder architecture, must match the training script."""
    def __init__(self, input_dim: int = 72, encoding_dim: int = 32, hidden_dims: List[int] = [128, 64]):
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
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

class ModelInference:
    """
    Handles inference for the hybrid DDoS detection system.
    Combines LucidCNN (Classification) and AutoEncoder (Anomaly Detection).
    """
    def __init__(self):
        self.lucid_model = None
        self.lucid_scaler = None
        self.autoencoder_model = None
        self.autoencoder_scaler = None
        
        # Detection Thresholds
        self.LUCID_THRESHOLD = 0.1
        
        # Adaptive Thresholding State
        self.baseline_errors: deque = deque(maxlen=1000)
        self.current_autoencoder_threshold: float = 500.0  # Default safe margin
        self.k_multiplier: float = 3.0  # Sensitivity factor (mean + 3*std)
        
        # False Positive Mitigation
        self.attack_history: deque = deque(maxlen=5)
        self.last_alert_time: float = 0
        self.ALERT_COOLDOWN: int = 10
        self.MIN_CONSECUTIVE_ATTACKS: int = 3
        
        self.load_models()

    def initialize_baseline(self, initial_errors: List[float]) -> None:
        """
        Initializes the dynamic threshold using errors collected during calibration.
        """
        if not initial_errors:
            print("⚠️ WARNING: Calibration data empty. Using default threshold.")
            return
            
        self.baseline_errors.extend(initial_errors)
        self.recalculate_threshold()

    def recalculate_threshold(self) -> None:
        """
        Updates the anomaly detection threshold based on the statistical properties 
        of recent benign traffic (mean + k * std_dev).
        """
        if len(self.baseline_errors) > 30:
            mean_val = np.mean(self.baseline_errors)
            std_dev = np.std(self.baseline_errors)
            self.current_autoencoder_threshold = mean_val + (self.k_multiplier * std_dev)
            
            if self.current_autoencoder_threshold < 10:
                self.current_autoencoder_threshold = 10.0
                
            print(f"✅ THRESHOLD UPDATED: {self.current_autoencoder_threshold:.4f} (μ={mean_val:.3f}, σ={std_dev:.3f})")
            self.save_baseline()

    def save_baseline(self):
        """Saves the current calibration baseline to disk."""
        try:
            with open('baseline.pkl', 'wb') as f:
                pickle.dump({
                    'errors': list(self.baseline_errors),
                    'threshold': self.current_autoencoder_threshold
                }, f)
        except Exception as e:
            print(f"Failed to save baseline: {e}")

    def load_baseline_from_disk(self) -> bool:
        """Loads baseline from disk if available."""
        if os.path.exists('baseline.pkl'):
            try:
                with open('baseline.pkl', 'rb') as f:
                    data = pickle.load(f)
                    self.baseline_errors.extend(data['errors'])
                    self.current_autoencoder_threshold = data['threshold']
                print("✅ Calibrated baseline loaded from disk.")
                return True
            except Exception as e:
                print(f"Failed to load baseline: {e}")
        return False

    def load_models(self) -> None:
        """Loads models and scalers from disk."""
        try:
            print("Loading LucidCNN...")
            with custom_object_scope({'ExpandDimsLayer': ExpandDimsLayer}):
                self.lucid_model = tf.keras.models.load_model('lucid.h5', compile=False)
            
            with open('lucid.pkl', 'rb') as f:
                self.lucid_scaler = pickle.load(f)
            
            print("Loading AutoEncoder...")
            with open('auto.pkl', 'rb') as f:
                auto_data = pickle.load(f)
                self.autoencoder_scaler = auto_data['scaler']
            
            input_dim = self.lucid_scaler.n_features_in_
            self.autoencoder_model = Autoencoder(input_dim=input_dim)
            self.autoencoder_model.load_state_dict(torch.load('auto.pth', map_location='cpu'))
            self.autoencoder_model.eval()
            print("✅ All models loaded successfully.")
            
        except Exception as e:
            print(f"❌ CRITICAL ERROR loading models: {e}")
            raise

    def _is_heavy_usage_flow(self, features: List[float]) -> bool:
        """Heuristic to identify legitimate heavy usage (e.g., streaming)."""
        avg_packet_size = features[39] if len(features) > 39 else 0
        flow_bytes_per_sec = features[13] if len(features) > 13 else 0
        
        if avg_packet_size > 800 and flow_bytes_per_sec > 1_000_000:
            packet_rate = features[14] if len(features) > 14 else 0
            if packet_rate < 1000:
                return True
        return False

    def predict(self, features: List[float]) -> Dict[str, Any]:
        """
        Analyzes flow features to detect attacks.
        Returns a dictionary with prediction details and threat assessment.
        """
        try:
            features_np = np.array(features).reshape(1, -1)
            features_np = np.nan_to_num(features_np, nan=0.0, posinf=0.0, neginf=0.0)

            # 1. LucidCNN Classification
            lucid_features = self.lucid_scaler.transform(features_np)
            lucid_confidence = float(self.lucid_model.predict(lucid_features, verbose=0)[0][0])
            lucid_class = "Attack" if lucid_confidence > self.LUCID_THRESHOLD else "Benign"
            
            # 2. AutoEncoder Anomaly Detection
            auto_features = self.autoencoder_scaler.transform(features_np)
            auto_input = torch.FloatTensor(auto_features)
            
            with torch.no_grad():
                reconstructed = self.autoencoder_model(auto_input)
                error = float(torch.mean((auto_input - reconstructed) ** 2).item())
            
            is_anomaly = error > self.current_autoencoder_threshold
            
            # 3. Hybrid Logic
            is_heavy = self._is_heavy_usage_flow(features)
            both_agree = (lucid_class == "Attack") and is_anomaly
            current_time = time.time()
            
            # Track history for temporal analysis
            self.attack_history.append({
                'time': current_time,
                'is_attack': both_agree and not is_heavy,
            })
            
            recent_attacks = sum(1 for h in self.attack_history 
                               if current_time - h['time'] < 10 and h['is_attack'])
            
            final_pred = "Benign"
            threat_level = "LOW"
            
            if recent_attacks >= self.MIN_CONSECUTIVE_ATTACKS:
                if current_time - self.last_alert_time > self.ALERT_COOLDOWN:
                    final_pred = "Attack"
                    threat_level = "HIGH"
                    self.last_alert_time = current_time
                else:
                    final_pred = "Attack (Cooldown)"
                    threat_level = "MEDIUM"
            elif both_agree and not is_heavy:
                threat_level = "MEDIUM"
            elif is_heavy:
                final_pred = "Heavy Usage"
                threat_level = "LOW"

            # 4. Continuous Learning (Update baseline if benign)
            if threat_level == 'LOW':
                self.baseline_errors.append(error)
                if len(self.baseline_errors) % 100 == 0:
                    self.recalculate_threshold()

            return {
                'lucid_prediction': lucid_class,
                'lucid_confidence': lucid_confidence,
                'autoencoder_anomaly': is_anomaly,
                'reconstruction_error': error,
                'final_prediction': final_pred,
                'threat_level': threat_level,
                'recent_attack_count': recent_attacks,
                'is_heavy_usage': is_heavy,
                'current_threshold': self.current_autoencoder_threshold
            }
            
        except Exception as e:
            print(f"Inference Error: {e}")
            return {
                'lucid_prediction': "Error", 'lucid_confidence': 0.0,
                'autoencoder_anomaly': False, 'reconstruction_error': 0.0,
                'final_prediction': "Error", 'threat_level': "UNKNOWN",
                'recent_attack_count': 0, 'is_heavy_usage': False,
                'current_threshold': self.current_autoencoder_threshold
            }
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
import logging

try:
    import xgboost as xgb
except ImportError:
    xgb = None
    print("WARNING: XGBoost not installed.")

import sklearn
from sklearn.ensemble import RandomForestClassifier

# Suppress Warnings for cleaner logs
warnings.filterwarnings(action='ignore', category=UserWarning)
warnings.filterwarnings(action='ignore', category=FutureWarning)

class ExpandDimsLayer(Layer):
    """Custom Keras layer required to load the lucid.h5 model."""
    def __init__(self, axis: int = -1, **kwargs):
        # Remove dtype from kwargs if it exists (compatibility with different Keras versions)
        kwargs.pop('dtype', None)
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
    Combines LucidCNN (Classification), AutoEncoder (Anomaly Detection),
    XGBoost, and Random Forest in an Ensemble.
    """
    def __init__(self):
        self.lucid_model = None
        self.lucid_scaler = None
        self.autoencoder_model = None
        self.autoencoder_scaler = None
        self.xgboost_model = None
        self.random_forest_model = None
        
        # Detection Thresholds
        self.LUCID_THRESHOLD = 0.5 
        
        # Adaptive Thresholding State
        self.baseline_errors: deque = deque(maxlen=1000)
        self.current_autoencoder_threshold: float = 500.0
        self.k_multiplier: float = 3.0
        
        # False Positive Mitigation
        self.attack_history: deque = deque(maxlen=5)
        self.last_alert_time: float = 0
        self.ALERT_COOLDOWN: int = 10
        self.MIN_CONSECUTIVE_ATTACKS: int = 3
        
        self.load_models()

    def initialize_baseline(self, initial_errors: List[float]) -> None:
        """Initializes the dynamic threshold using errors collected during calibration."""
        if not initial_errors:
            print("⚠️ WARNING: Calibration data empty. Using default threshold.")
            return
        self.baseline_errors.extend(initial_errors)
        self.recalculate_threshold()

    def start_calibration(self):
        """Reset baseline for new calibration"""
        self.baseline_errors = deque(maxlen=2000)
        self.current_autoencoder_threshold = 500.0 # Reset to safe default
        print("DEBUG: Calibration started")

    def finalize_calibration(self):
        """Calculate new threshold from collected baseline errors"""
        if not self.baseline_errors:
            return 500.0
            
        errors = np.array(self.baseline_errors)
        mean_err = np.mean(errors)
        std_err = np.std(errors)
        
        # Set threshold to Mean + 3*STD (covers 99.7% of normal traffic)
        new_threshold = mean_err + (3 * std_err)
        # Ensure minimum safe floor
        new_threshold = max(new_threshold, 0.05) 
        
        self.current_autoencoder_threshold = float(new_threshold)
        print(f"DEBUG: Calibration Complete. New Threshold: {self.current_autoencoder_threshold:.4f}")
        return self.current_autoencoder_threshold

    def recalculate_threshold(self) -> None:
        """Updates the anomaly detection threshold."""
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

            # Load Ensemble Models
            print("Loading Ensemble Models (XGBoost & Random Forest)...")
            try:
                if os.path.exists('xgboost_ddos.pkl'):
                    with open('xgboost_ddos.pkl', 'rb') as f:
                        self.xgboost_model = pickle.load(f)
                    print("✅ XGBoost loaded.")
                else:
                    print("⚠️ XGBoost model file not found.")
            except Exception as e:
                print(f"⚠️ Failed to load XGBoost: {e}")

            try:
                if os.path.exists('random_forest_ddos.pkl'):
                    with open('random_forest_ddos.pkl', 'rb') as f:
                        self.random_forest_model = pickle.load(f)
                    print("✅ Random Forest loaded.")
                else:
                    print("⚠️ Random Forest model file not found.")
            except Exception as e:
                print(f"⚠️ Failed to load Random Forest: {e}")
            
            print("✅ All models loaded successfully.")
            self.load_baseline_from_disk()
            
        except Exception as e:
            print(f"❌ CRITICAL ERROR loading models: {e}")
            import traceback
            traceback.print_exc()
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
    
    def _get_subset_features(self, features_np, model):
        """
        Prepares features for XGBoost/Random Forest.
        Backward-compatible: works with both old models (fewer features, no scaler)
        and new models (72 features, trained with StandardScaler).
        """
        n_scaler = self.lucid_scaler.n_features_in_  # How many features the scaler expects
        n_expected = n_scaler  # Default
        if hasattr(model, 'n_features_in_'):
            n_expected = model.n_features_in_

        # If model expects same feature count as the scaler → new model, scale it
        if n_expected == n_scaler:
            return self.lucid_scaler.transform(features_np)

        # Otherwise → old model trained on fewer features without scaling
        # Just subset the raw features (no scaling)
        if n_expected < features_np.shape[1]:
            return features_np[:, :n_expected]
        else:
            padded = np.zeros((features_np.shape[0], n_expected))
            padded[:, :features_np.shape[1]] = features_np
            return padded

    def autoencoder_predict(self, features: List[float]) -> tuple[bool, float]:
        """
        Runs only the AutoEncoder for calibration or lightweight monitoring.
        Returns (is_anomaly, reconstruction_error).
        """
        try:
            features_np = np.array(features).reshape(1, -1)
            features_np = np.nan_to_num(features_np, nan=0.0, posinf=0.0, neginf=0.0)
            
            auto_features = self.autoencoder_scaler.transform(features_np)
            auto_input = torch.FloatTensor(auto_features)
            
            with torch.no_grad():
                reconstructed = self.autoencoder_model(auto_input)
                error = float(torch.mean((auto_input - reconstructed) ** 2).item())
            
            is_anomaly = error > self.current_autoencoder_threshold
            return is_anomaly, error
            
        except Exception as e:
            print(f"AutoEncoder Error: {e}")
            return False, 0.0

    def predict(self, features: List[float]) -> Dict[str, Any]:
        """
        Analyzes flow features using Enlightened Ensemble (Lucid + XGB + RF + AutoEncoder).
        Returns a dictionary with prediction details.
        """
        try:
            features_np = np.array(features).reshape(1, -1)
            features_np = np.nan_to_num(features_np, nan=0.0, posinf=0.0, neginf=0.0)

            # 1. LucidCNN Classification
            lucid_features = self.lucid_scaler.transform(features_np)
            lucid_confidence = float(self.lucid_model.predict(lucid_features, verbose=0)[0][0])
            lucid_vote = 1 if lucid_confidence > 0.5 else 0
            
            # 2. XGBoost Prediction
            xgb_vote = 0
            xgb_conf = 0.0
            if self.xgboost_model:
                try:
                    xgb_input = self._get_subset_features(features_np, self.xgboost_model)
                    if hasattr(self.xgboost_model, "predict_proba"):
                        xgb_conf = float(self.xgboost_model.predict_proba(xgb_input)[0][1])
                        xgb_vote = 1 if xgb_conf > 0.5 else 0
                    else:
                        xgb_vote = int(self.xgboost_model.predict(xgb_input)[0])
                        xgb_conf = float(xgb_vote)
                except Exception as e:
                    print(f"XGB Error: {e}")

            # 3. Random Forest Prediction
            rf_vote = 0
            rf_conf = 0.0
            if self.random_forest_model:
                try:
                    rf_input = self._get_subset_features(features_np, self.random_forest_model)
                    if hasattr(self.random_forest_model, "predict_proba"):
                        rf_conf = float(self.random_forest_model.predict_proba(rf_input)[0][1])
                        rf_vote = 1 if rf_conf > 0.5 else 0
                    else:
                        rf_vote = int(self.random_forest_model.predict(rf_input)[0])
                        rf_conf = float(rf_vote)
                except Exception as e:
                    print(f"RF Error: {e}")

            # 4. AutoEncoder Anomaly Detection
            auto_features = self.autoencoder_scaler.transform(features_np)
            auto_input = torch.FloatTensor(auto_features)
            with torch.no_grad():
                reconstructed = self.autoencoder_model(auto_input)
                error = float(torch.mean((auto_input - reconstructed) ** 2).item())
            is_anomaly = error > self.current_autoencoder_threshold

            # === ENSEMBLE LOGIC ===
            # Weights: Lucid (Deep Learning) gets highest trust, followed by tree models
            w_lucid, w_xgb, w_rf = 0.5, 0.25, 0.25
            active_weights = w_lucid
            
            if self.xgboost_model: active_weights += w_xgb
            if self.random_forest_model: active_weights += w_rf
            
            # Normalize weights dynamically based on loaded models
            w_lucid /= active_weights
            if self.xgboost_model: w_xgb /= active_weights
            else: w_xgb = 0
            if self.random_forest_model: w_rf /= active_weights
            else: w_rf = 0

            # Calculate Weighted Ensemble Score (0.0 to 1.0)
            ensemble_score = (lucid_confidence * w_lucid) + (xgb_conf * w_xgb) + (rf_conf * w_rf)
            
            # 5. Hybrid Decision Matrix
            is_heavy = self._is_heavy_usage_flow(features)
            final_pred = "Benign"
            threat_level = "LOW"
            
            # Decision Tree for Threat Level
            if is_heavy:
                final_pred = "Heavy Usage"
                threat_level = "LOW"
            else:
                # CASE 1: High Confidence Attack (Double Confirmation)
                # Both Ensemble and AutoEncoder agree
                if ensemble_score > 0.6 and is_anomaly:
                    final_pred = "Attack"
                    threat_level = "HIGH"
                
                # CASE 2: Strong Ensemble Detection (Known Attack Signature)
                # Even if AutoEncoder misses it (maybe low volume), if classifiers are sure, trust them.
                elif ensemble_score > 0.85:
                    final_pred = "Attack"
                    threat_level = "HIGH"
                    
                # CASE 3: Potential Anomaly (Zero-Day or Subtle Attack)
                # AutoEncoder sees anomaly, but classifiers are unsure.
                # OR Classifiers are somewhat suspicious (0.5-0.6) but not certain.
                elif is_anomaly or (ensemble_score > 0.5):
                     final_pred = "Potential Threat"
                     threat_level = "MEDIUM"

            # 6. Temporal Escalation (Make System "Smarter")
            # If we see a burst of "Medium" threats, escalate them to "High"
            # because isolated anomalies might be noise, but a group is an attack.
            current_time = time.time()
            if final_pred != "Benign" and final_pred != "Heavy Usage":
                self.attack_history.append({'time': current_time, 'level': threat_level})
            
            # Count recent threats in last 5 seconds
            recent_highs = sum(1 for h in self.attack_history if current_time - h['time'] < 5 and h['level'] == 'HIGH')
            recent_mediums = sum(1 for h in self.attack_history if current_time - h['time'] < 5 and h['level'] == 'MEDIUM')
            
            # Intelegent Escalation: 5+ Mediums become a High
            if threat_level == "MEDIUM" and recent_mediums >= 5:
                threat_level = "HIGH"
                final_pred = "Attack (Escalated)"

            # 7. Continuous Learning (Update baseline ONLY if comfortably Benign)
            if threat_level == 'LOW' and ensemble_score < 0.2:
                self.baseline_errors.append(error)
                if len(self.baseline_errors) % 100 == 0:
                    self.recalculate_threshold()

            # Fix: Ensure recent_attacks is defined for return (Count all recent non-benign events)
            recent_attacks = recent_highs + recent_mediums

            return {
                'lucid_prediction': "Attack" if lucid_confidence > 0.5 else "Benign",
                'lucid_confidence': lucid_confidence,
                'ensemble_score': ensemble_score,
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
            import traceback
            traceback.print_exc()
            return {
                'lucid_prediction': "Error", 'lucid_confidence': 0.0,
                'autoencoder_anomaly': False, 'reconstruction_error': 0.0,
                'final_prediction': "Error", 'threat_level': "UNKNOWN",
                'recent_attack_count': 0, 'is_heavy_usage': False,
                'current_threshold': self.current_autoencoder_threshold
            }
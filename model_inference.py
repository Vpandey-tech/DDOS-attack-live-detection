import numpy as np
import pickle
import os
import tensorflow as tf
import torch
import torch.nn as nn
from tensorflow.keras.layers import Layer
from tensorflow.keras.utils import custom_object_scope

# =================== FIX STARTS HERE ===================
#
# FIX: Correctly suppressed warnings without importing from sklearn.
# The standard 'warnings' module handles this properly.
#
import warnings
warnings.filterwarnings(action='ignore', category=UserWarning)
warnings.filterwarnings(action='ignore', category=FutureWarning)
# =================== FIX ENDS HERE ===================

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
        self.anomaly_threshold = None
        
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
                self.anomaly_threshold = auto_data['threshold']
            
            input_dim = self.lucid_scaler.n_features_in_
            self.autoencoder_model = Autoencoder(input_dim=input_dim)
            self.autoencoder_model.load_state_dict(torch.load('auto.pth', map_location='cpu'))
            self.autoencoder_model.eval()
            print("✅ AutoEncoder model loaded successfully")
            
        except Exception as e:
            print(f"❌ CRITICAL ERROR during model loading: {e}")
            raise

    def predict(self, features):
        """Performs prediction using the hybrid model system."""
        try:
            features_np = np.array(features).reshape(1, -1)
            features_np = np.nan_to_num(features_np, nan=0.0, posinf=0.0, neginf=0.0)

            # LucidCNN Prediction
            lucid_features = self.lucid_scaler.transform(features_np)
            lucid_confidence = self.lucid_model.predict(lucid_features, verbose=0)[0][0]
            lucid_class = "Attack" if lucid_confidence > 0.5 else "Benign"
            
            # AutoEncoder Anomaly Detection
            auto_features = self.autoencoder_scaler.transform(features_np)
            auto_input = torch.FloatTensor(auto_features)
            
            with torch.no_grad():
                reconstructed = self.autoencoder_model(auto_input)
                error = torch.mean((auto_input - reconstructed) ** 2).item()
            
            is_anomaly = error > self.anomaly_threshold
            
            # Hybrid Decision Logic
            final_prediction = "Benign"
            if lucid_class == "Attack" or is_anomaly:
                final_prediction = "Attack"
            
            threat_level = "LOW"
            if final_prediction == "Attack":
                threat_level = "HIGH" if (lucid_class == "Attack" and is_anomaly) else "MEDIUM"
            
            return {
                'lucid_prediction': lucid_class,
                'lucid_confidence': float(lucid_confidence),
                'autoencoder_anomaly': is_anomaly,
                'reconstruction_error': float(error),
                'final_prediction': final_prediction,
                'threat_level': threat_level
            }
        except Exception as e:
            print(f"Error during model inference: {e}")
            return {
                'lucid_prediction': "Error", 'lucid_confidence': 0.0,
                'autoencoder_anomaly': False, 'reconstruction_error': 0.0,
                'final_prediction': "Error", 'threat_level': "UNKNOWN"
            }

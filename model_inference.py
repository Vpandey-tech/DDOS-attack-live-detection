import numpy as np
import pickle
import os
import tensorflow as tf
import torch
import torch.nn as nn
from tensorflow.keras.layers import Layer
from tensorflow.keras.utils import custom_object_scope

# Custom Keras layer definition for ExpandDimsLayer
class ExpandDimsLayer(Layer):
    def __init__(self, axis=-1, **kwargs):
        super(ExpandDimsLayer, self).__init__(**kwargs)
        self.axis = axis
    
    def call(self, inputs):
        return tf.expand_dims(inputs, axis=self.axis)
    
    def get_config(self):
        config = super(ExpandDimsLayer, self).get_config()
        config.update({'axis': self.axis})
        return config

class AutoEncoder(nn.Module):
    """PyTorch AutoEncoder model structure"""
    def __init__(self, input_dim=72):
        super(AutoEncoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 36),
            nn.ReLU(),
            nn.Linear(36, 18),
            nn.ReLU(),
            nn.Linear(18, 9),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(9, 18),
            nn.ReLU(),
            nn.Linear(18, 36),
            nn.ReLU(),
            nn.Linear(36, input_dim),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

class ModelInference:
    def __init__(self):
        self.lucid_model = None
        self.lucid_scaler = None
        self.autoencoder_model = None
        self.autoencoder_scaler = None
        self.anomaly_threshold = None
        
        self.load_models()
    
    def load_models(self):
        """Load both pre-trained models and scalers"""
        try:
            # Load LucidCNN model and scaler with custom objects
            print("Loading LucidCNN model...")
            custom_objects = {'ExpandDimsLayer': ExpandDimsLayer}
            with custom_object_scope(custom_objects):
                self.lucid_model = tf.keras.models.load_model('lucid.h5')
            
            with open('lucid.pkl', 'rb') as f:
                self.lucid_scaler = pickle.load(f)
            
            print("✅ LucidCNN model loaded successfully")
            
            # Load AutoEncoder model and preprocessing
            print("Loading AutoEncoder model...")
            
            # Load the scaler and threshold
            with open('auto.pkl', 'rb') as f:
                auto_data = pickle.load(f)
                if isinstance(auto_data, dict):
                    self.autoencoder_scaler = auto_data.get('scaler')
                    self.anomaly_threshold = auto_data.get('threshold', 0.1)
                else:
                    # If it's just the scaler
                    self.autoencoder_scaler = auto_data
                    self.anomaly_threshold = 0.1  # Default threshold
            
            # Load PyTorch model
            self.autoencoder_model = AutoEncoder(input_dim=72)
            self.autoencoder_model.load_state_dict(torch.load('auto.pth', map_location='cpu'))
            self.autoencoder_model.eval()
            
            print("✅ AutoEncoder model loaded successfully")
            
        except Exception as e:
            raise Exception(f"Failed to load models: {str(e)}")
    
    def predict(self, features):
        """Perform prediction using both models"""
        try:
            features = np.array(features).reshape(1, -1)
            
            # Ensure we have exactly 72 features
            if features.shape[1] != 72:
                raise ValueError(f"Expected 72 features, got {features.shape[1]}")
            
            # Handle NaN and infinite values
            features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
            
            # LucidCNN Prediction
            lucid_features = self.lucid_scaler.transform(features)
            lucid_prediction = self.lucid_model.predict(lucid_features, verbose=0)[0][0]
            lucid_class = "Attack" if lucid_prediction > 0.5 else "Benign"
            
            # AutoEncoder Prediction
            autoencoder_features = self.autoencoder_scaler.transform(features)
            autoencoder_input = torch.FloatTensor(autoencoder_features)
            
            with torch.no_grad():
                reconstructed = self.autoencoder_model(autoencoder_input)
                reconstruction_error = torch.mean((autoencoder_input - reconstructed) ** 2).item()
            
            is_anomaly = reconstruction_error > self.anomaly_threshold
            
            # Hybrid Decision Logic
            final_prediction = "Attack" if (lucid_class == "Attack" or is_anomaly) else "Benign"
            
            # Determine threat level
            if final_prediction == "Attack":
                if lucid_class == "Attack" and is_anomaly:
                    threat_level = "HIGH"
                else:
                    threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            return {
                'lucid_prediction': lucid_class,
                'lucid_confidence': float(lucid_prediction),
                'autoencoder_anomaly': is_anomaly,
                'reconstruction_error': float(reconstruction_error),
                'final_prediction': final_prediction,
                'threat_level': threat_level
            }
            
        except Exception as e:
            print(f"Error during model inference: {str(e)}")
            return {
                'lucid_prediction': "Error",
                'lucid_confidence': 0.0,
                'autoencoder_anomaly': False,
                'reconstruction_error': 0.0,
                'final_prediction': "Error",
                'threat_level': "UNKNOWN"
            }

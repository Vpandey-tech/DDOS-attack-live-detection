# Real-Time DDoS Detection System

## Overview

This is a real-time DDoS detection system built with Python and Streamlit that monitors network traffic and identifies potential attacks using machine learning. The system captures live network packets, assembles them into flows, extracts comprehensive features, and uses two pre-trained models (LucidCNN and AutoEncoder) for attack detection. It provides a professional dashboard for real-time monitoring and visualization of network security threats.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Streamlit Dashboard**: Multi-page web interface with real-time updates
- **Visualization Components**: Plotly charts for metrics, alerts, and detection visualizations
- **State Management**: Session-based state handling for maintaining system status and data across refreshes
- **Auto-refresh**: Real-time dashboard updates without manual page reload

### Backend Architecture
- **Modular Design**: Separated concerns across multiple specialized modules
- **Threading Model**: Multi-threaded architecture for concurrent packet capture and processing
- **Queue-based Communication**: Thread-safe queues for data passing between components
- **Flow Management**: Time-based flow assembly with configurable timeout mechanisms

### Core Components

#### Packet Capture System
- **Scapy Integration**: Low-level packet capture from network interfaces
- **Protocol Support**: TCP and UDP packet processing with port extraction
- **Real-time Processing**: Continuous packet stream handling with minimal latency

#### Flow Assembly Engine
- **5-tuple Identification**: Groups packets by source IP, destination IP, source port, destination port, and protocol
- **Bidirectional Flow Tracking**: Separate forward and backward packet tracking
- **Timeout Management**: Automatic flow expiration and cleanup after configurable periods

#### Feature Extraction Pipeline
- **72-Feature Vector**: Comprehensive statistical feature extraction from network flows
- **Statistical Calculations**: Advanced metrics including Inter-Arrival Time (IAT), packet size statistics, and TCP flags
- **Performance Optimization**: Efficient calculations with safe division and error handling

#### Machine Learning Inference
- **Dual Model Architecture**: Hybrid detection using both classification and anomaly detection
- **LucidCNN Model**: TensorFlow-based binary classifier for attack/benign classification
- **AutoEncoder Model**: PyTorch-based anomaly detector trained on benign traffic
- **Preprocessing Pipeline**: Separate scaling for each model (StandardScaler for LucidCNN, MinMaxScaler for AutoEncoder)

### Data Flow Architecture
1. **Capture**: Raw packets captured from network interface
2. **Assembly**: Packets grouped into flows based on 5-tuple
3. **Feature Extraction**: 72 statistical features extracted per flow
4. **Inference**: Dual model prediction with hybrid logic
5. **Visualization**: Real-time dashboard updates with results

### Error Handling and Reliability
- **File Validation**: Checks for required model files on startup
- **Safe Operations**: Protected division and statistical calculations
- **Graceful Degradation**: System continues operation even with partial failures
- **Resource Management**: Automatic cleanup of expired flows and threads

### Performance Considerations
- **Minimal Latency**: Optimized feature extraction for real-time processing
- **Memory Efficiency**: Flow timeout and cleanup to prevent memory leaks
- **Thread Safety**: Queue-based communication between capture and processing threads
- **Scalable Architecture**: Modular design allows for easy component scaling

## External Dependencies

### Machine Learning Frameworks
- **TensorFlow/Keras**: For LucidCNN model inference and loading
- **PyTorch**: For AutoEncoder model inference and neural network architecture
- **scikit-learn**: Implied for scaler objects (StandardScaler, MinMaxScaler)

### Network and System Libraries
- **Scapy**: Low-level packet capture and network protocol parsing
- **netifaces**: Network interface discovery and management

### Web Framework and Visualization
- **Streamlit**: Web application framework and real-time dashboard
- **Plotly**: Interactive charts and data visualization components
- **Pandas**: Data manipulation and analysis for dashboard metrics

### Data Processing
- **NumPy**: Numerical computations and array operations for feature extraction
- **Python Standard Library**: Threading, queue, time, collections for core functionality

### Required Model Files
- **lucid.h5**: Pre-trained LucidCNN TensorFlow model
- **lucid.pkl**: StandardScaler for LucidCNN preprocessing
- **auto.pth**: Pre-trained AutoEncoder PyTorch model
- **auto.pkl**: MinMaxScaler and anomaly threshold for AutoEncoder

### System Requirements
- **Network Interface Access**: Requires appropriate permissions for packet capture
- **Real-time Processing**: System must handle continuous data streams with minimal buffering
- **File System Access**: Model files must be accessible in the application root directory
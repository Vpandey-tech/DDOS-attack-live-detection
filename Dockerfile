# Use Python 3.9 as base
FROM python:3.9-slim

# Install system dependencies
# libpcap-dev is required for Scapy
# iproute2 includes 'ip' command, sometimes useful
# git is useful for cloning if needed
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    python3-dev \
    net-tools \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip

# Copy requirements first to leverage caching
COPY requirements.txt .

# Install Python dependencies
# Using --no-cache-dir to keep image smaller
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Hugging Face Spaces specific configuration
# Runs as root by default in this container context if not specified otherwise, 
# but HF Spaces might override USER.
# However, for packet capture we ideally want root. 
# Docker spaces generally allow root.

# Expose the port Streamlit runs on (7860 is HF Spaces default)
EXPOSE 7860

# Command to run the application
# Use 0.0.0.0 to bind to all interfaces
CMD ["streamlit", "run", "enhanced_app.py", "--server.port=7860", "--server.address=0.0.0.0"]

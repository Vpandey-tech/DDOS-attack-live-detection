# 🚀 How to Deploy to Hugging Face Spaces

This guide explains how to deploy your **Fraud Detection System** to Hugging Face Spaces using Docker.

## ⚠️ Important Note on Admin Privileges & Networking

You asked for **Admin Privileges** (Root access).
*   **Good News**: By using **Docker Spaces**, this application runs as `root` *inside the container*. This allows `scapy` to capture packets and the application to run without "Access Denied" errors.
*   **Limitation**: Hugging Face Spaces are hosted on remote servers. 
    *   The "Network" you see will be the *container's* network, not your local home Wi-Fi.
    *   You will not be able to "protect" your personal computer from the cloud.
    *   However, `Simulation Mode` and the Dashboard will work perfectly to **demonstrate** the project.

---

## 🛠️ Deployment Steps

### Step 1: Create a Hugging Face Space
1.  Go to [huggingface.co/spaces](https://huggingface.co/spaces).
2.  Click **"Create new Space"**.
3.  **Space Name**: `fraud-detection-demo` (or similar).
4.  **License**: `MIT`.
5.  **SDK**: Select **Docker** (Critical! Do not select Streamlit).
6.  **Space Hardware**: `CPU Basic` (Free) is sufficient.
7.  Click **"Create Space"**.

### Step 2: Upload Your Code
You can upload files via the Web Interface or Git.

#### Option A: Web Interface (Easiest)
1.  In your new Space, go to the **"Files"** tab.
2.  Click **"Add file"** -> **"Upload files"**.
3.  Drag and drop **ALL** files from your project folder (`curr_ddos`) into the browser.
    *   **Crucial Files**: 
        *   `Dockerfile`
        *   `requirements.txt`
        *   `enhanced_app.py`
        *   `packet_capture.py` (and all other `.py` files)
        *   **Model Files**: `lucid.h5`, `lucid.pkl`, `auto.pth`, `auto.pkl`, `xgboost_ddos.pkl`, `random_forest_ddos.pkl`.
        *   `README.md`
4.  Click **"Commit changes to main"**.

#### Option B: Git (For Pro Users)
1.  Clone your Space locally:
    ```bash
    git clone https://huggingface.co/spaces/YOUR_USERNAME/YOUR_SPACE_NAME
    ```
2.  Copy all your project files into that folder.
3.  Push changes:
    ```bash
    git add .
    git commit -m "Deploy Application"
    git push
    ```

### Step 3: Wait for Build
1.  Click the **"App"** tab in your Space.
2.  You will see a "Building" status. This takes 2-5 minutes to install dependencies.
3.  Once finished, the App will flip to "Running".

### Step 4: Verify Admin/Root Access
1.  The application includes patches to detect it is running on Linux (Hugging Face).
2.  It will automatically use `Scapy` in standard mode (compatible with Linux).
3.  If you go to the "Testing" tab and run the **Traffic Simulator**, it should work perfectly.

---

## ❓ Troubleshooting

*   **"Build Failed"**: Check if you uploaded `requirements.txt`. The build needs this to know what libraries to install.
*   **"Model Not Found"**: Ensure you uploaded the `.h5`, `.pth`, and `.pkl` files. They are large and sometimes get skipped if you drag-drop too many files at once.
*   **"Permission Denied"**: Should not happen in Docker mode as it runs as root.

---

**Enjoy your deployed AI Defense System!** 🛡️

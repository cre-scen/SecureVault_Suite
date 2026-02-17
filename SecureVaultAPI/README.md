![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)
![Postman](https://img.shields.io/badge/Postman-FF6C37?style=for-the-badge&logo=postman&logoColor=white)
# 🛡️ SecureVault API
A lightweight, secure Python API for managing sensitive data strings. This project demonstrates a "Security Vertical Slice"—integrating database persistence with industry-standard authentication patterns.

## 🚀 Key Features
* **Persistent Storage:** Integrated **SQLite** for reliable, server-side data management.
* **Header-Based Auth:** Secured endpoints using custom `X-API-Key` validation.
* **Environment Security:** Implemented **Environment Variables** (`.env`) to decouple sensitive credentials from the source code.
* **RESTful Design:** Supports structured `GET` and `POST` requests for data lifecycle management.

## 🛠️ Installation
1.  **Clone & Navigate:**
    ```bash
    git clone <your-repo-url>
    cd SecureVaultAPI
    ```
2.  **Activate Environment:**
    ```bash
    .\venv\Scripts\activate
    ```
3.  **Install Dependencies:**
    ```bash
    pip install flask python-dotenv
    ```
4.  **Security Setup:**
    Create a `.env` file in the root folder:
    ```text
    VALID_API_KEY=your_secret_key_here
    ```

## 🔌 Usage
Start the server with `python app.py`. Use **Postman** to interact with the following endpoints:

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/add-secret` | Save a new secret to the vault | `X-API-Key` |

# Project: SecureVault API & LogSentinel Integration
## Status: Week 4 Milestone - Completed

### 🛡️ Features Added (Week 4)
- **Live Logging:** Configured Flask `logging.basicConfig` to stream events to `app.log`.
- **File-Tailing Monitor:** Created a Python script that monitors sibling folder logs without locking the file.
- **Stateful Counter Logic:** Implemented a threshold-based detection system (5 hits / 60 seconds).
- **Security Alert System:** Real-time terminal "Live Fire" alert banner for Brute Force detection.

### 🚀 Technical Overview

#### 1. Counter Logic & Timestamp Reset
Instead of alerting on every failed login, the system uses a **Temporal Window**:
- **What it is:** A state-tracking mechanism using `time.time()` and a counter variable.
- **Function:** It calculates the delta between the first failure and current failure. If `delta > 60s`, the counter resets.
- **Importance:** Differentiates between a human forgetting a password and an automated bot-net attack.



### 🛠️ Live Fire Test Instructions
1. **Start the API:** Navigate to `SecureVaultAPI` and run `python app.py`.
2. **Start the Monitor:** Navigate to `LogSentinel` and run `python sentinel.py`.
3. **Simulate Attack:** - Visit `http://127.0.0.1:5000/secret/test` in a browser.
   - Refresh the page **5 times** within one minute.
4. **Observation:** LogSentinel terminal will display `Hit Detected: X/5` and trigger a `SECURITY ALERT` banner on the 5th attempt.

### 📝 Lessons Learned
- **Relative Pathing:** Navigating sibling folders in a workspace using `../` requires careful terminal positioning.
- **File I/O:** Using `f.seek(0, 2)` is essential to ensure the monitor starts reading from the *newest* log entry, preventing historical alerts from triggering on restart.
- **Environment Management:** Virtual environments must be activated in every new terminal instance to load dependencies like `python-dotnv`.
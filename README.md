# Log Monitoring & Alerting System

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-7.x%2B-brightgreen.svg)
![Status](https://img.shields.io/badge/status-Stable-success.svg)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [Logging](#logging)
- [Troubleshooting](#troubleshooting)

## Overview

The **Log Monitoring & Alerting System** is a Python-based tool designed to monitor Elasticsearch logs for critical security-related events such as SSH login failures, unauthorized sudo usage, and potential Denial of Service (DoS) attacks. It sends real-time email alerts based on predefined thresholds and logs all activities for auditing and analysis.

## Features

- **Multi-Index Support**: Monitor multiple Elasticsearch indices simultaneously.
- **Real-Time Alerting**: Receive immediate email notifications for critical events.
- **Configurable Thresholds**: Define custom thresholds for different events during business and non-business hours.
- **Secure Configuration**: Protect sensitive information using environment variables.
- **Graceful Shutdown**: Handles termination signals to ensure smooth shutdowns.
- **Comprehensive Logging**: Detailed logs for monitoring the script's operations and troubleshooting.
- **Scalable**: Easily extendable to include more event types and alerting mechanisms.

## Prerequisites

Before setting up the Log Monitoring & Alerting System, ensure you have the following:

- **Python 3.6 or higher**
- **Elasticsearch 7.x or higher**
- **SMTP Server Credentials**: For sending email alerts (e.g., Gmail, Outlook)
- **Access to the Terminal/Command Prompt**

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/MouadAssouam/Log_MonitoringELK.git
   cd Log_MonitoringELK
   ```

2. **Create a Virtual Environment (Optional but Recommended)**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Required Python Packages**

   Ensure you have `pip` installed. Then run:

   ```bash
   pip install -r requirements.txt
   ```

   **`requirements.txt`**:

## Configuration

### 1. **Set Up Environment Variables**

To enhance security, sensitive information like Elasticsearch and SMTP credentials are managed through environment variables.

- **On Unix/Linux:**

  ```bash
  export ELASTIC_USER="your_elasticsearch_username"
  export ELASTIC_PASSWORD="your_elasticsearch_password"
  export SMTP_USERNAME="your_smtp_username"
  export SMTP_PASSWORD="your_smtp_password"
  ```

- **On Windows (PowerShell):**

  ```powershell
  $env:ELASTIC_USER="your_elasticsearch_username"
  $env:ELASTIC_PASSWORD="your_elasticsearch_password"
  $env:SMTP_USERNAME="your_smtp_username"
  $env:SMTP_PASSWORD="your_smtp_password"
  ```

### 2. **Configure `config.yaml`**

Update the `config.yaml` file in the project root directory with the following content. Replace placeholders and ensure environment variables are correctly set.

### **Notes:**

- **Multiple Indices**: Under `elasticsearch.indexes`, you can list all the Elasticsearch indices you want to monitor. Use wildcard patterns (`*`) to include multiple indices matching a pattern.
- **Environment Variables**: Sensitive fields like `user`, `password`, `smtp.username`, and `smtp.password` are referenced using `${VARIABLE_NAME}`. Ensure these environment variables are set in your system.
- **SMTP Settings**: Update `sender` and `receivers` as per your requirements.

## Usage

The script supports two primary operations:

1. **One-Time Scan**: Perform a single scan of logs within a specified timeframe.
2. **Continuous Monitoring**: Continuously monitor logs for a defined duration.

### **1. One-Time Scan**

Execute a one-time scan to analyze logs from the last `N` minutes across all specified indices.

```bash
python log_monitoring.py scan --duration 10
```

**Parameters:**

- `--duration`: (Optional) Duration in minutes for scanning logs. Default is `5` minutes.

**Example:**

```bash
python log_monitoring.py scan --duration 15
```

This command scans logs from the last 15 minutes.

### **2. Continuous Monitoring**

Start continuous monitoring of logs for a specified duration. The script will periodically query Elasticsearch based on the `sleep_interval` defined in `config.yaml`.

```bash
python log_monitoring.py monitor --duration 60
```

**Parameters:**

- `--duration`: (Optional) Duration in minutes for monitoring. Default is `5` minutes.

**Example:**

```bash
python log_monitoring.py monitor --duration 120
```

This command continuously monitors logs for 2 hours.

**Graceful Shutdown:**

To stop continuous monitoring before the specified duration, press `Ctrl+C`. The script will handle the termination signal and shut down gracefully.

## Security Considerations

- **Protect Configuration Files**: Ensure that `config.yaml` and any scripts containing sensitive information are secured with appropriate file permissions.

  - **On Unix/Linux/macOS:**

    ```bash
    chmod 600 config.yaml
    chmod 700 log_monitoring.py
    ```

  - **On Windows:**

    - Right-click the file, go to **Properties** > **Security**, and set appropriate permissions.

- **Use Environment Variables**: Avoid hardcoding sensitive information. Always use environment variables to manage credentials.

- **Elasticsearch Security**: Ensure that your Elasticsearch instance is secured with proper authentication and network security measures.

- **SMTP Security**: Use app-specific passwords if your email provider supports them and avoid using your primary email password.

## Logging

All activities, including informational messages, warnings, errors, and debug information, are logged to `log_monitoring.log`. The log file is managed using `RotatingFileHandler` to prevent excessive disk usage.

- **Log Levels**:
  - `DEBUG`: Detailed information, typically of interest only when diagnosing problems.
  - `INFO`: Confirmation that things are working as expected.
  - `WARNING`: An indication that something unexpected happened.
  - `ERROR`: Due to a more serious problem, the software has not been able to perform some function.
  - `CRITICAL`: A serious error, indicating that the program itself may be unable to continue running.

## Troubleshooting

### **1. Elasticsearch Connection Issues**

- **Verify Credentials**: Ensure that the `ELASTIC_USER` and `ELASTIC_PASSWORD` environment variables are set correctly.
- **Check Network Accessibility**: Confirm that the Elasticsearch host (`http://192.168.106.176:9200`) is reachable from the machine running the script.
- **Elasticsearch Status**: Ensure that the Elasticsearch service is running and healthy.

### **2. SMTP Issues**

- **Correct Credentials**: Ensure that `SMTP_USERNAME` and `SMTP_PASSWORD` are set correctly.
- **Less Secure Apps**: If using Gmail, ensure that "Less secure app access" is enabled or use an App Password if 2FA is enabled.
- **Firewall and Port Access**: Ensure that outbound connections to the SMTP server and port (`smtp.gmail.com:587`) are allowed.

### **3. Permission Errors**

- **File Permissions**: Verify that the script and configuration files have the appropriate read/write permissions.

### **4. Missing Logs or Alerts**

- **Index Patterns**: Ensure that the specified indices in `config.yaml` correctly match the indices in your Elasticsearch instance.
- **Event Codes**: Verify that the event codes specified under `events` in `config.yaml` align with the actual event codes in your logs.

### **5. Script Errors**

- **Check Logs**: Review the `log_monitoring.log` file for detailed error messages and debugging information.
- **Dependencies**: Ensure all required Python packages are installed and up-to-date.

---

**Happy Monitoring!** 🚀

---

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
import logging
import uuid
import signal
import sys
from datetime import datetime, timedelta, timezone, time as dt_time

import yaml
from elasticsearch import Elasticsearch, ElasticsearchException
import smtplib
from email.mime.text import MIMEText
import pytz
import re
from logging.handlers import RotatingFileHandler
import os
import argparse

# ============================
# Configuration Loader
# ============================

def load_config(config_path='config.yaml'):
    """Load configuration from a YAML file."""
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)

        # Replace environment variables in config if any (optional)
        def replace_env_vars(obj):
            if isinstance(obj, dict):
                return {k: replace_env_vars(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_env_vars(item) for item in obj]
            elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
                return os.getenv(obj[2:-1], obj)
            else:
                return obj

        config = replace_env_vars(config)

        # Validate essential keys
        required_keys = [
            'elasticsearch', 'logging', 'alerting', 'business_hours',
            'events', 'sleep_interval', 'allowed_logon_types', 'smtp',
            'alert_cooldowns', 'dos_detection', 'monitoring'
        ]
        for key in required_keys:
            if key not in config:
                raise KeyError(f"Missing required configuration section: '{key}'")

        return config
    except FileNotFoundError:
        print(f"Configuration file '{config_path}' not found.")
        sys.exit(1)
    except KeyError as e:
        print(f"Configuration error: {e}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"YAML parsing error in '{config_path}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Failed to load configuration file: {e}")
        sys.exit(1)

# ============================
# Logging Setup
# ============================

def setup_logging(logging_config):
    """Set up logging based on configuration."""
    logger = logging.getLogger('LogMonitor')
    logger.setLevel(getattr(logging, logging_config.get('level', 'INFO').upper()))

    # File handler with rotation
    file_handler = RotatingFileHandler('log_monitoring.log', maxBytes=5*1024*1024, backupCount=5)
    file_formatter = logging.Formatter(
        logging_config.get('format', '%(asctime)s - %(levelname)s - %(message)s'),
        logging_config.get('datefmt', '%Y-%m-%d %H:%M:%S')
    )
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(getattr(logging, logging_config.get('level', 'INFO').upper()))
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        logging_config.get('format', '%(asctime)s - %(levelname)s - %(message)s'),
        logging_config.get('datefmt', '%Y-%m-%d %H:%M:%S')
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(getattr(logging, logging_config.get('level', 'INFO').upper()))
    logger.addHandler(console_handler)

    return logger

# ============================
# Elasticsearch Client Setup
# ============================

def setup_elasticsearch_clients(es_config, logger):
    """Set up Elasticsearch clients for querying and indexing."""
    try:
        # Client for querying logs
        es_query_client = Elasticsearch(
            hosts=es_config['hosts'],
            http_auth=(es_config['http_auth']['user'], es_config['http_auth']['password']),
            timeout=es_config.get('timeout', 30)
        )
        if not es_query_client.ping():
            logger.critical("Cannot connect to Elasticsearch for querying. Exiting.")
            sys.exit(1)
        logger.info("Connected to Elasticsearch for querying.")

        # Client for indexing alerts
        es_index_client = Elasticsearch(
            hosts=es_config['hosts'],
            http_auth=(es_config['http_auth']['user'], es_config['http_auth']['password']),
            timeout=es_config.get('timeout', 30)
        )
        if not es_index_client.ping():
            logger.critical("Cannot connect to Elasticsearch for indexing. Exiting.")
            sys.exit(1)
        logger.info("Connected to Elasticsearch for indexing high-severity alerts.")

        return es_query_client, es_index_client
    except ElasticsearchException as e:
        logger.critical(f"Elasticsearch connection error: {e}")
        sys.exit(1)

# ============================
# Email Alerting Functions
# ============================

def send_email_alert(subject, body, smtp_config, logger):
    """
    Sends an email alert with the specified subject and body.
    Retries up to 3 times with a 5-second wait between attempts on failure.
    """
    sender = smtp_config['sender']
    receivers = smtp_config['receivers']
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ", ".join(receivers)

    try:
        logger.info("Connecting to SMTP server...")
        with smtplib.SMTP(smtp_config['server'], smtp_config['port'], timeout=10) as server:
            server.starttls()  # Secure the connection
            server.login(smtp_config['username'], smtp_config['password'])
            server.sendmail(sender, receivers, msg.as_string())
        logger.info(f"Email alert sent successfully to {receivers}.")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")

# ============================
# Helper Functions
# ============================

def can_send_alert(identifier, alert_type, cooldowns, last_alert_time, logger):
    """
    Checks if an alert can be sent for the given identifier and alert type based on the cooldown period.
    Utilizes separate cooldowns for different alert types.
    """
    current_time = time.time()
    identifier_alerts = last_alert_time.get(identifier, {})
    last_time = identifier_alerts.get(alert_type, 0)

    # Determine cooldown based on alert type
    if alert_type in cooldowns:
        cooldown = cooldowns[alert_type]
    else:
        cooldown = cooldowns.get('default', 300)

    if current_time - last_time >= cooldown:
        logger.debug(f"Alert cooldown passed for identifier {identifier}, alert type {alert_type}.")
        return True
    logger.debug(f"Alert cooldown active for identifier {identifier}, alert type {alert_type}.")
    return False

def update_last_alert_time(identifier, alert_type, last_alert_time, logger):
    """
    Updates the last alert time for the given identifier and alert type.
    """
    if identifier not in last_alert_time:
        last_alert_time[identifier] = {}
    last_alert_time[identifier][alert_type] = time.time()
    logger.debug(f"Updated last alert time for identifier {identifier}, alert type {alert_type}.")

def extract_host_ip(host_info):
    """
    Extracts the primary IP address from the host information.
    """
    host_ips = host_info.get('ip', ['N/A'])
    host_ip = host_ips[0] if host_ips else 'N/A'
    return host_ip

def extract_source_ip(message):
    """
    Extracts the source IP from the log message using regular expressions.
    """
    try:
        # Search for the first IPv4 address in the message
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', message)
        if ip_match:
            return ip_match.group(0)
    except Exception as e:
        logger.error(f"Error extracting source IP: {e}")
    return "N/A"

def is_outside_business_hours(timestamp_str, business_hours, timezone_str, logger):
    """
    Determines if the given UTC timestamp is outside defined business hours.
    """
    try:
        # Parse the timestamp
        log_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        local_timezone = pytz.timezone(timezone_str)
        log_time = log_time.astimezone(local_timezone)
        logger.debug(f"Log time in local timezone: {log_time}")
        start_time = datetime.combine(log_time.date(), dt_time.fromisoformat(business_hours['start']))
        end_time = datetime.combine(log_time.date(), dt_time.fromisoformat(business_hours['end']))
        return not (start_time <= log_time <= end_time)
    except ValueError as ve:
        logger.error(f"Timestamp parsing error: {ve}")
        return False  # Default to False if parsing fails

# ============================
# Alert Processing Functions
# ============================

def generate_alert(log, alert_type, config, es_index_client, logger):
    """
    Generates an alert and indexes it into Elasticsearch.
    """
    severity_mapping = {
        "sudo": "high",
        "ssh_warning": "warning",
        "ssh_high": "high",
        "dos": "critical",
        "logon_success": "critical",
        "logon": "warning"  # Adjust as needed based on thresholds
    }
    severity = severity_mapping.get(alert_type, "medium")  # Default to 'medium' if not defined

    alert_document = {
        "@timestamp": log.get('@timestamp', datetime.now(timezone.utc).isoformat()),
        "alert_type": alert_type,
        "severity": severity.capitalize(),
        "host": log.get('host', {}).get('name', 'Unknown'),
        "host_ip": extract_host_ip(log.get('host', {})),
        "message": log.get('message', ''),
        "raw_log": log  # Include the entire log for reference
    }

    try:
        response = es_index_client.index(index=config['elasticsearch']['alert_index'], body=alert_document)
        logger.debug(f"Indexing response: {response}")
        logger.info(f"Indexed high-severity alert for host: {alert_document['host']} of type: {alert_type} with severity: {severity}.")
    except ElasticsearchException as e:
        logger.error(f"Failed to index high-severity alert: {e}")
    except Exception as e:
        logger.error(f"Unexpected error while indexing high-severity alert: {e}")

def process_log(log, config, last_alert_time, ssh_attempts, last_logon_success_alert_time, es_index_client, logger):
    """
    Process individual log entries and generate alerts based on the log content.
    """
    event_code = log.get('event', {}).get('code', 'N/A')
    host = log.get('host', {}).get('name', 'Unknown')
    timestamp = log.get('@timestamp', '')
    host_ip = extract_host_ip(log.get('host', {}))

    # Determine if the event is during business hours
    outside_business = is_outside_business_hours(timestamp, config['business_hours'], "Africa/Casablanca", logger)

    # Handle different event types
    if event_code in config['events']['logon_event_codes']:
        logon_type = log.get('winlog', {}).get('event_data', {}).get('LogonType', 'Unknown')

        # Check if LogonType is allowed
        if logon_type not in config['allowed_logon_types']['logon']:
            logger.debug(f"Ignoring event with LogonType {logon_type} for event code {event_code}.")
            return

        if event_code == "4624":  # Successful logon
            if outside_business:
                identifier = f"{host}_{host_ip}"
                alert_type = 'logon_success'
                if can_send_alert(identifier, alert_type, config['alert_cooldowns'], last_alert_time, logger):
                    subject = config['smtp']['subjects'].get('sudo', "Security Alert: Unauthorized Sudo Usage")
                    body = (
                        f"Critical: Successful logon outside business hours for {host} (IP: {host_ip}).\n"
                        f"Event Details:\n"
                        f" - Event ID: {event_code}\n"
                        f" - Host IP: {host_ip}\n"
                        f" - Logon Type: {logon_type}\n"
                        f" - Timestamp: {timestamp}"
                    )
                    send_email_alert(subject, body, config['smtp'], logger)
                    generate_alert(log, alert_type, config, es_index_client, logger)
                    update_last_alert_time(identifier, alert_type, last_alert_time, logger)
        elif event_code == "4625":  # Failed logon
            identifier = host_ip
            alert_type = 'logon'
            if can_send_alert(identifier, alert_type, config['alert_cooldowns'], last_alert_time, logger):
                subject = config['smtp']['subjects'].get('ssh', "Security Alert: SSH Login Failure")
                body = (
                    f"Warning: Failed logon attempt detected on the host: {host}\n"
                    f"Event Details:\n"
                    f" - Event ID: {event_code}\n"
                    f" - Host IP: {host_ip}\n"
                    f" - Logon Type: {logon_type}\n"
                    f" - Timestamp: {timestamp}"
                )
                send_email_alert(subject, body, config['smtp'], logger)
                generate_alert(log, alert_type, config, es_index_client, logger)
                update_last_alert_time(identifier, alert_type, last_alert_time, logger)

    # Add additional event processing as needed (e.g., RDP, Windows Defender)

# ============================
# Log Processing and Monitoring
# ============================

class LogMonitor:
    """Class to monitor logs from Elasticsearch and generate alerts."""

    def __init__(self, config, es_query_client, es_index_client, logger):
        self.config = config
        self.es_query_client = es_query_client
        self.es_index_client = es_index_client
        self.logger = logger
        self.shutdown_flag = False

        # Tracking variables
        self.last_alert_time = {}
        self.ssh_attempts = {}
        self.last_logon_success_alert_time = {}

    def signal_handler(self, signum, frame):
        """Handle termination signals for graceful shutdown."""
        self.shutdown_flag = True
        self.logger.info("Shutdown signal received. Exiting gracefully...")

    def setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def query_elasticsearch(self):
        """Query Elasticsearch for relevant logs and process them."""
        # Iterate through all specified indices
        for index in self.config['elasticsearch']['indexes']:
            query = {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": [
                                    {"match": {"event.module": "auditd"}},  # Linux SSH logs
                                    {"terms": {"event.code": self.config['events']['logon_event_codes']}}  # Windows logon events
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ],
                    "filter": {
                        "range": {
                            "@timestamp": {"gte": "now-5m"}
                        }
                    }
                }
            }

            try:
                response = self.es_query_client.search(index=index, query=query, size=1000)
                hits = response['hits']['hits']
                if hits:
                    self.logger.info(f"Found {len(hits)} logs in index '{index}' matching the query.")
                    for hit in hits:
                        log = hit["_source"]
                        process_log(
                            log=log,
                            config=self.config,
                            last_alert_time=self.last_alert_time,
                            ssh_attempts=self.ssh_attempts,
                            last_logon_success_alert_time=self.last_logon_success_alert_time,
                            es_index_client=self.es_index_client,
                            logger=self.logger
                        )
                else:
                    self.logger.info(f"No logs found in index '{index}' matching the query.")
            except ElasticsearchException as e:
                self.logger.error(f"Error fetching logs from Elasticsearch index '{index}': {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error while querying Elasticsearch index '{index}': {e}")

    def run(self):
        """Run the log monitoring loop."""
        self.logger.info("Starting log monitoring service.")
        while not self.shutdown_flag:
            self.query_elasticsearch()
            time.sleep(self.config['sleep_interval'])
        self.logger.info("Log monitoring service stopped.")

# ============================
# Argument Parsing
# ============================

def parse_arguments():
    """
    Parses command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Log Monitoring Script")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Subparser for 'scan' command
    scan_parser = subparsers.add_parser('scan', help='Perform a one-time scan of logs from the last N minutes')
    scan_parser.add_argument('--duration', type=int, default=5,
                             help='Duration in minutes for scanning logs (default: 5 minutes)')

    # Subparser for 'monitor' command
    monitor_parser = subparsers.add_parser('monitor', help='Start continuous monitoring of logs')
    monitor_parser.add_argument('--duration', type=int, default=5,
                                help='Duration in minutes for monitoring (default: 5 minutes)')

    return parser.parse_args()

# ============================
# Main Execution
# ============================

def main():
    # Load configuration
    config = load_config()

    # Set up logging
    logger = setup_logging(config['logging'])

    # Set up Elasticsearch clients
    es_query_client, es_index_client = setup_elasticsearch_clients(config['elasticsearch'], logger)

    # Initialize LogMonitor
    monitor = LogMonitor(config, es_query_client, es_index_client, logger)

    # Set up signal handlers for graceful shutdown
    monitor.setup_signal_handlers()

    # Parse command-line arguments
    args = parse_arguments()

    if args.command == 'scan':
        logger.info(f"Starting one-time scan for the last {args.duration} minute(s).")
        # Define the timeframe for the scan
        timeframe = f"now-{args.duration}m"
        # Modify the query to fetch logs within the specified duration
        for index in config['elasticsearch']['indexes']:
            scan_query = {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": [
                                    {"match": {"event.module": "auditd"}},
                                    {"terms": {"event.code": config['events']['logon_event_codes']}}
                                ],
                                "minimum_should_match": 1
                            }
                        }
                    ],
                    "filter": {
                        "range": {
                            "@timestamp": {"gte": timeframe}
                        }
                    }
                }
            }

            try:
                response = es_query_client.search(index=index, query=scan_query, size=1000)
                hits = response['hits']['hits']
                if hits:
                    logger.info(f"Found {len(hits)} logs in index '{index}' matching the scan query.")
                    for hit in hits:
                        log = hit["_source"]
                        process_log(
                            log=log,
                            config=config,
                            last_alert_time=monitor.last_alert_time,
                            ssh_attempts=monitor.ssh_attempts,
                            last_logon_success_alert_time=monitor.last_logon_success_alert_time,
                            es_index_client=es_index_client,
                            logger=logger
                        )
                else:
                    logger.info(f"No logs found in index '{index}' matching the scan query.")
            except ElasticsearchException as e:
                logger.error(f"Elasticsearch query error during scan for index '{index}': {e}")
            except Exception as e:
                logger.error(f"Unexpected error during scan for index '{index}': {e}")

        logger.info("One-time scan completed.")

    elif args.command == 'monitor':
        logger.info(f"Starting continuous monitoring for {args.duration} minute(s).")
        # Define the end time based on duration
        end_time = time.time() + args.duration * 60
        try:
            while time.time() < end_time and not monitor.shutdown_flag:
                monitor.query_elasticsearch()
                time.sleep(config['sleep_interval'])
        except KeyboardInterrupt:
            logger.info("Interrupted by user.")
        finally:
            monitor.shutdown_flag = True
            logger.info("Monitoring stopped.")
    else:
        print("No valid command provided. Use 'scan' or 'monitor'.")
        print("Example usage:")
        print("  python log_monitoring.py scan --duration 10")
        print("  python log_monitoring.py monitor --duration 60")

if __name__ == "__main__":
    main()

import os

# Path to the file containing domains to scan (one per line)
DOMAINS_FILE = os.getenv("DOMAINS_FILE", "domains.txt")

# Score threshold below which to trigger Slack alerts
ALERT_SCORE_THRESHOLD = int(os.getenv("ALERT_SCORE_THRESHOLD", "70"))

# Toggles for integrations
ENABLE_SLACK = os.getenv("ENABLE_SLACK", "False").lower() in ("true", "1", "yes")
ENABLE_S3 = os.getenv("ENABLE_S3", "False").lower() in ("true", "1", "yes")

# Slack webhook URL (for sending alerts)
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# S3 bucket configuration for uploading scan results
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "90097qivrscore")
# Prefix (folder) under which to store versioned results
S3_KEY_PREFIX = os.getenv("S3_KEY_PREFIX", "versioned-results/")


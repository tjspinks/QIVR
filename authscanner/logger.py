import os
import csv
import json
from datetime import datetime, timezone

import boto3
import requests

from authscanner.config import (
    DOMAINS_FILE,
    ENABLE_S3,
    ENABLE_SLACK,
    SLACK_WEBHOOK_URL,
    ALERT_SCORE_THRESHOLD,
    S3_BUCKET_NAME,
    S3_KEY_PREFIX
)

# Local filenames for logs
RESULTS_CSV = "results.csv"
RESULTS_JSON = "results.json"

def log_to_csv(domain, checks, score, reason):
    """Append a row to results.csv with detailed check flags."""
    timestamp = datetime.now(timezone.utc).isoformat()
    file_exists = os.path.isfile(RESULTS_CSV)

    headers = ["Timestamp", "Domain"] + list(checks.keys()) + ["Score", "Reason"]
    row = [timestamp, domain] + list(checks.values()) + [score, reason]

    with open(RESULTS_CSV, mode="a", newline="") as fp:
        writer = csv.writer(fp)
        if not file_exists:
            writer.writerow(headers)
        writer.writerow(row)

    print(f"📦 CSV logged: {domain} (score: {score})")

def log_to_json(domain, checks, score, reason):
    """Write or append a JSON structure for detailed results."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "checks": checks,
        "score": score,
        "reason": reason,
    }

    data = []
    if os.path.isfile(RESULTS_JSON):
        with open(RESULTS_JSON) as fp:
            try:
                data = json.load(fp)
            except json.JSONDecodeError:
                data = []

    data.append(entry)
    with open(RESULTS_JSON, "w") as fp:
        json.dump(data, fp, indent=2)

    print(f"📄 JSON logged: {domain}")

def send_slack_alert(domain, score, reason):
    """Post a message to Slack if ENABLE_SLACK is true."""
    if not ENABLE_SLACK:
        return
    if not SLACK_WEBHOOK_URL:
        print("⚠️ SLACK_WEBHOOK_URL not set; skipping Slack alert.")
        return

    payload = {
        "text": (
            f"🚨 *AuthScanner Alert*\n"
            f"> *Domain:* `{domain}`\n"
            f"> *Score:* *{score}*\n"
            f"> *Reason:* {reason}"
        )
    }

    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        if resp.status_code == 200:
            print(f"📣 Slack alert sent for {domain}")
        else:
            print(f"⚠️ Slack alert failed ({resp.status_code}): {resp.text}")
    except requests.RequestException as e:
        print(f"❌ Slack request error: {e}")

def upload_to_s3(json_data=None):
    """Upload both CSV and JSON to S3 if ENABLE_S3 is true."""
    if not ENABLE_S3:
        return

    s3 = boto3.client("s3")
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    # Upload CSV
    if os.path.isfile(RESULTS_CSV):
        key_csv = f"{S3_KEY_PREFIX}results-{timestamp}.csv"
        try:
            s3.upload_file(RESULTS_CSV, S3_BUCKET_NAME, key_csv)
            print(f"☁️ Uploaded CSV to s3://{S3_BUCKET_NAME}/{key_csv}")
        except Exception as e:
            print(f"❌ CSV upload failed: {e}")

    # Upload JSON (inline or file)
    if json_data is not None:
        key_json = f"{S3_KEY_PREFIX}results-{timestamp}.json"
        try:
            s3.put_object(
                Bucket=S3_BUCKET_NAME,
                Key=key_json,
                Body=json_data,
                ContentType="application/json"
            )
            print(f"☁️ Uploaded JSON to s3://{S3_BUCKET_NAME}/{key_json}")
        except Exception as e:
            print(f"❌ JSON upload failed: {e}")
    elif os.path.isfile(RESULTS_JSON):
        key_json = f"{S3_KEY_PREFIX}results-{timestamp}.json"
        try:
            s3.upload_file(RESULTS_JSON, S3_BUCKET_NAME, key_json)
            print(f"☁️ Uploaded JSON to s3://{S3_BUCKET_NAME}/{key_json}")
        except Exception as e:
            print(f"❌ JSON upload failed: {e}")

def list_versions(bucket=S3_BUCKET_NAME, key_prefix=S3_KEY_PREFIX):
    """List object versions under the given prefix."""
    s3 = boto3.client("s3")
    try:
        resp = s3.list_object_versions(Bucket=bucket, Prefix=key_prefix)
        versions = resp.get("Versions", [])
        for v in versions:
            print(
                f"Key: {v['Key']}, VersionId: {v['VersionId']}, "
                f"LastModified: {v['LastModified']}, Size: {v['Size']}"
            )
    except Exception as e:
        print(f"❌ Error listing versions: {e}")

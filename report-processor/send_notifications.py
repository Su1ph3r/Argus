#!/usr/bin/env python3
"""Send notifications to Slack or other channels"""

import os
import json
import requests
import logging

logger = logging.getLogger(__name__)

def send_slack_notification(webhook_url, summary):
    """Send audit summary to Slack"""
    
    message = {
        "text": "🔒 Cloud Security Audit Complete",
        "attachments": [{
            "color": "warning" if summary.get('critical', 0) > 0 else "good",
            "fields": [
                {"title": "Critical", "value": summary.get('critical', 0), "short": True},
                {"title": "High", "value": summary.get('high', 0), "short": True},
                {"title": "Medium", "value": summary.get('medium', 0), "short": True},
                {"title": "Low", "value": summary.get('low', 0), "short": True}
            ]
        }]
    }
    
    try:
        response = requests.post(webhook_url, json=message)
        response.raise_for_status()
        logger.info("Slack notification sent successfully")
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {e}")

if __name__ == "__main__":
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    if webhook_url:
        # Load summary from database or file
        summary = {"critical": 5, "high": 12, "medium": 34, "low": 89}
        send_slack_notification(webhook_url, summary)

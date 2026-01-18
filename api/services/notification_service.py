"""
Notification Service for Scan Completions.

This module provides notification dispatch for scan completion events.
It integrates with the user settings system to determine which channels
are enabled and sends notifications accordingly.

Usage:
    from services.notification_service import send_scan_notification

    await send_scan_notification(db, scan_id, "scan_complete", summary)
"""

import logging
from datetime import datetime

import requests
from sqlalchemy.orm import Session

from models.database import UserSetting

logger = logging.getLogger(__name__)


def _get_setting_value(db: Session, key: str, default=None):
    """Get a setting value from the database."""
    setting = db.query(UserSetting).filter(UserSetting.setting_key == key).first()
    if setting and setting.setting_value:
        value = setting.setting_value
        # Handle JSON null values
        if value in ("null", None, "None"):
            return default
        return value
    return default


def _send_slack_notification(webhook_url: str, summary: dict, scan_id: str = None) -> bool:
    """Send notification to Slack."""
    if not webhook_url or webhook_url in ("null", "None", ""):
        return False

    # Calculate total
    total = sum([
        summary.get("critical", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
    ])

    message = {
        "text": f"Cloud Security Audit Complete - {total} findings",
        "attachments": [
            {
                "color": "danger" if summary.get("critical", 0) > 0 else (
                    "warning" if summary.get("high", 0) > 0 else "good"
                ),
                "fields": [
                    {"title": "Critical", "value": str(summary.get("critical", 0)), "short": True},
                    {"title": "High", "value": str(summary.get("high", 0)), "short": True},
                    {"title": "Medium", "value": str(summary.get("medium", 0)), "short": True},
                    {"title": "Low", "value": str(summary.get("low", 0)), "short": True},
                ],
                "footer": f"Scan ID: {scan_id}" if scan_id else "Nubicustos",
                "ts": int(datetime.utcnow().timestamp()),
            }
        ],
    }

    try:
        response = requests.post(webhook_url, json=message, timeout=10)
        response.raise_for_status()
        logger.info(f"Slack notification sent for scan {scan_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {e}")
        return False


def _send_teams_notification(webhook_url: str, summary: dict, scan_id: str = None) -> bool:
    """Send notification to Microsoft Teams."""
    if not webhook_url or webhook_url in ("null", "None", ""):
        return False

    # Calculate total
    total = sum([
        summary.get("critical", 0),
        summary.get("high", 0),
        summary.get("medium", 0),
        summary.get("low", 0),
    ])

    # Determine card color based on severity
    if summary.get("critical", 0) > 0:
        theme_color = "FF0000"
    elif summary.get("high", 0) > 0:
        theme_color = "FFA500"
    elif summary.get("medium", 0) > 0:
        theme_color = "FFFF00"
    else:
        theme_color = "00FF00"

    message = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"Cloud Security Audit Complete - {total} findings",
        "sections": [
            {
                "activityTitle": "Cloud Security Audit Complete",
                "activitySubtitle": f"Scan ID: {scan_id}" if scan_id else "Security audit completed",
                "facts": [
                    {"name": "Critical", "value": str(summary.get("critical", 0))},
                    {"name": "High", "value": str(summary.get("high", 0))},
                    {"name": "Medium", "value": str(summary.get("medium", 0))},
                    {"name": "Low", "value": str(summary.get("low", 0))},
                    {"name": "Total", "value": str(total)},
                ],
                "markdown": True,
            }
        ],
    }

    try:
        response = requests.post(webhook_url, json=message, timeout=10)
        response.raise_for_status()
        logger.info(f"Teams notification sent for scan {scan_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to send Teams notification: {e}")
        return False


async def send_scan_notification(
    db: Session,
    scan_id: str,
    event: str,
    summary: dict,
) -> dict:
    """
    Send notifications for scan events based on user settings.

    Args:
        db: Database session
        scan_id: The scan ID
        event: Event type (e.g., "scan_complete")
        summary: Finding summary with critical, high, medium, low counts

    Returns:
        dict: Results of notification attempts
    """
    results = {
        "notifications_enabled": False,
        "slack_sent": False,
        "teams_sent": False,
        "errors": [],
    }

    try:
        # Check if notifications are enabled
        notifications_enabled = _get_setting_value(db, "notifications_enabled", False)
        if not notifications_enabled or notifications_enabled in ("false", False):
            logger.debug(f"Notifications disabled, skipping for scan {scan_id}")
            return results

        results["notifications_enabled"] = True

        # Send Slack notification if configured
        slack_url = _get_setting_value(db, "slack_webhook_url")
        if slack_url and slack_url not in ("null", "None", ""):
            try:
                results["slack_sent"] = _send_slack_notification(slack_url, summary, scan_id)
            except Exception as e:
                results["errors"].append(f"Slack: {e}")

        # Send Teams notification if configured
        teams_url = _get_setting_value(db, "teams_webhook_url")
        if teams_url and teams_url not in ("null", "None", ""):
            try:
                results["teams_sent"] = _send_teams_notification(teams_url, summary, scan_id)
            except Exception as e:
                results["errors"].append(f"Teams: {e}")

        logger.info(f"Notification results for scan {scan_id}: {results}")

    except Exception as e:
        logger.error(f"Error sending notifications for scan {scan_id}: {e}")
        results["errors"].append(str(e))

    return results

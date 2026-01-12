"""Settings API endpoints for user preferences."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from models.database import UserSetting, get_db
from models.schemas import (
    SettingsResetResponse,
    UserSettingListResponse,
    UserSettingResponse,
    UserSettingsByCategory,
    UserSettingUpdate,
)

router = APIRouter(prefix="/settings", tags=["Settings"])

# Default settings to reset to
DEFAULT_SETTINGS = {
    "default_scan_profile": {
        "value": "quick",
        "category": "scans",
        "description": "Default scan profile to use",
    },
    "default_regions": {
        "value": ["us-east-1", "us-west-2"],
        "category": "scans",
        "description": "Default AWS regions to scan",
    },
    "default_severity_filter": {
        "value": ["critical", "high"],
        "category": "scans",
        "description": "Default severity levels to include",
    },
    "auto_cleanup_days": {
        "value": 90,
        "category": "data",
        "description": "Auto-delete scan results older than N days",
    },
    "export_format": {
        "value": "json",
        "category": "data",
        "description": "Default export format (json, csv)",
    },
    "max_concurrent_scans": {
        "value": 3,
        "category": "scans",
        "description": "Maximum concurrent scan executions",
    },
    "notifications_enabled": {
        "value": False,
        "category": "notifications",
        "description": "Enable notification system",
    },
    "webhook_url": {
        "value": None,
        "category": "notifications",
        "description": "Webhook URL for notifications",
    },
    "webhook_events": {
        "value": ["scan_complete", "critical_finding"],
        "category": "notifications",
        "description": "Events that trigger webhooks",
    },
    "email_alerts_enabled": {
        "value": False,
        "category": "notifications",
        "description": "Enable email alerts",
    },
    "email_alert_address": {
        "value": None,
        "category": "notifications",
        "description": "Email address for alerts",
    },
    "email_alert_threshold": {
        "value": "critical",
        "category": "notifications",
        "description": "Minimum severity for email alerts",
    },
    "theme": {"value": "dark", "category": "display", "description": "UI theme (dark, light)"},
    "findings_per_page": {
        "value": 50,
        "category": "display",
        "description": "Default items per page in findings list",
    },
}


@router.get("", response_model=UserSettingListResponse)
@router.get("/", response_model=UserSettingListResponse)
async def list_settings(
    db: Session = Depends(get_db),
    category: str | None = Query(None, description="Filter by category"),
):
    """List all user settings, optionally filtered by category."""
    query = db.query(UserSetting)

    if category:
        query = query.filter(UserSetting.category == category)

    settings = query.order_by(UserSetting.category, UserSetting.setting_key).all()

    return UserSettingListResponse(
        settings=[UserSettingResponse.model_validate(s) for s in settings], total=len(settings)
    )


@router.get("/grouped", response_model=UserSettingsByCategory)
async def get_settings_grouped(db: Session = Depends(get_db)):
    """Get all settings grouped by category."""
    settings = db.query(UserSetting).all()

    result = UserSettingsByCategory()

    for setting in settings:
        category_dict = getattr(result, setting.category, None)
        if category_dict is not None:
            category_dict[setting.setting_key] = setting.setting_value

    return result


@router.get("/{setting_key}", response_model=UserSettingResponse)
async def get_setting(setting_key: str, db: Session = Depends(get_db)):
    """Get a specific setting by key."""
    setting = db.query(UserSetting).filter(UserSetting.setting_key == setting_key).first()

    if not setting:
        raise HTTPException(status_code=404, detail=f"Setting '{setting_key}' not found")

    return UserSettingResponse.model_validate(setting)


@router.put("/{setting_key}", response_model=UserSettingResponse)
async def update_setting(
    setting_key: str, update: UserSettingUpdate, db: Session = Depends(get_db)
):
    """Update a specific setting."""
    setting = db.query(UserSetting).filter(UserSetting.setting_key == setting_key).first()

    if not setting:
        raise HTTPException(status_code=404, detail=f"Setting '{setting_key}' not found")

    # Validate setting value based on key
    if setting_key == "default_scan_profile":
        valid_profiles = ["quick", "comprehensive", "compliance-only"]
        if update.value not in valid_profiles:
            raise HTTPException(
                status_code=400, detail=f"Invalid profile. Must be one of: {valid_profiles}"
            )

    if setting_key == "default_severity_filter":
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if not isinstance(update.value, list):
            raise HTTPException(status_code=400, detail="Severity filter must be a list")
        for sev in update.value:
            if sev not in valid_severities:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid severity '{sev}'. Must be one of: {valid_severities}",
                )

    if setting_key == "auto_cleanup_days":
        if not isinstance(update.value, int) or update.value < 1 or update.value > 365:
            raise HTTPException(
                status_code=400, detail="Auto cleanup days must be an integer between 1 and 365"
            )

    if setting_key == "max_concurrent_scans":
        if not isinstance(update.value, int) or update.value < 1 or update.value > 10:
            raise HTTPException(
                status_code=400, detail="Max concurrent scans must be an integer between 1 and 10"
            )

    if setting_key == "export_format":
        valid_formats = ["json", "csv", "markdown"]
        if update.value not in valid_formats:
            raise HTTPException(
                status_code=400, detail=f"Invalid format. Must be one of: {valid_formats}"
            )

    if setting_key == "theme":
        valid_themes = ["dark", "light"]
        if update.value not in valid_themes:
            raise HTTPException(
                status_code=400, detail=f"Invalid theme. Must be one of: {valid_themes}"
            )

    if setting_key == "email_alert_threshold":
        valid_thresholds = ["critical", "high", "medium", "low"]
        if update.value not in valid_thresholds:
            raise HTTPException(
                status_code=400, detail=f"Invalid threshold. Must be one of: {valid_thresholds}"
            )

    # Update the setting
    setting.setting_value = update.value
    setting.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(setting)

    return UserSettingResponse.model_validate(setting)


@router.post("/reset", response_model=SettingsResetResponse)
async def reset_settings(
    db: Session = Depends(get_db),
    category: str | None = Query(None, description="Reset only settings in this category"),
):
    """Reset settings to default values."""
    reset_count = 0

    for key, config in DEFAULT_SETTINGS.items():
        # Skip if filtering by category and doesn't match
        if category and config["category"] != category:
            continue

        setting = db.query(UserSetting).filter(UserSetting.setting_key == key).first()

        if setting:
            setting.setting_value = config["value"]
            setting.updated_at = datetime.utcnow()
            reset_count += 1
        else:
            # Create the setting if it doesn't exist
            new_setting = UserSetting(
                setting_key=key,
                setting_value=config["value"],
                category=config["category"],
                description=config.get("description"),
            )
            db.add(new_setting)
            reset_count += 1

    db.commit()

    category_msg = f" in category '{category}'" if category else ""
    return SettingsResetResponse(
        message=f"Settings{category_msg} reset to defaults", settings_reset=reset_count
    )


@router.get("/category/{category}", response_model=UserSettingListResponse)
async def get_settings_by_category(category: str, db: Session = Depends(get_db)):
    """Get all settings in a specific category."""
    valid_categories = ["scans", "data", "notifications", "display"]
    if category not in valid_categories:
        raise HTTPException(
            status_code=400, detail=f"Invalid category. Must be one of: {valid_categories}"
        )

    settings = (
        db.query(UserSetting)
        .filter(UserSetting.category == category)
        .order_by(UserSetting.setting_key)
        .all()
    )

    return UserSettingListResponse(
        settings=[UserSettingResponse.model_validate(s) for s in settings], total=len(settings)
    )

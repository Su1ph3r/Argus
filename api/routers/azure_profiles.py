"""Azure Profiles API - Manage Azure credential profiles."""

import json
import logging
import os
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/azure-profiles", tags=["Azure Profiles"])

# Path to Azure profiles JSON file
AZURE_PROFILES_PATH = "/app/credentials/azure/profiles.json"


class AzureProfile(BaseModel):
    """Azure profile information."""

    name: str
    tenant_id: str
    client_id: str
    subscription_id: str | None = None
    identity: str | None = None
    subscription_names: list[str] = []
    created_at: datetime | None = None


class AzureProfileCredentials(BaseModel):
    """Azure profile credentials (for internal use)."""

    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str | None = None


class SaveAzureProfileRequest(BaseModel):
    """Request to save a new Azure profile."""

    profile_name: str
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str | None = None


class AzureProfileListResponse(BaseModel):
    """Response for listing Azure profiles."""

    profiles: list[AzureProfile]
    profiles_file_exists: bool
    profiles_path: str


def _read_profiles_file() -> dict:
    """Read Azure profiles from JSON file."""
    if os.path.exists(AZURE_PROFILES_PATH):
        try:
            with open(AZURE_PROFILES_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not read Azure profiles file: {e}")
    return {"profiles": {}}


def _write_profiles_file(data: dict) -> None:
    """Write Azure profiles to JSON file."""
    try:
        os.makedirs(os.path.dirname(AZURE_PROFILES_PATH), exist_ok=True)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Permission denied creating directory {os.path.dirname(AZURE_PROFILES_PATH)}. "
                "On Linux, run: sudo chown -R 1000:1000 ./credentials/azure"
            )
        )

    try:
        with open(AZURE_PROFILES_PATH, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Permission denied writing to {AZURE_PROFILES_PATH}. "
                "On Linux, run: sudo chown -R 1000:1000 ./credentials/azure"
            )
        )


def _verify_azure_credentials(tenant_id: str, client_id: str, client_secret: str):
    """Verify Azure credentials and return subscription info."""
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import SubscriptionClient

        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        if subscriptions:
            return {
                "valid": True,
                "identity": subscriptions[0].display_name,
                "subscription_names": [sub.display_name for sub in subscriptions],
                "subscription_ids": [sub.subscription_id for sub in subscriptions],
            }
        else:
            return {
                "valid": True,
                "identity": f"Azure-{tenant_id[:8]}",
                "subscription_names": [],
                "subscription_ids": [],
            }
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="Azure SDK not installed. Install with: pip install azure-identity azure-mgmt-resource"
        )
    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
        }


@router.get("", response_model=AzureProfileListResponse)
@router.get("/", response_model=AzureProfileListResponse)
async def list_profiles():
    """
    List available Azure profiles from the profiles file.

    The profiles file is stored at /app/credentials/azure/profiles.json
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    profiles = []
    for name, profile_data in profiles_dict.items():
        profile = AzureProfile(
            name=name,
            tenant_id=profile_data.get("tenant_id", ""),
            client_id=profile_data.get("client_id", ""),
            subscription_id=profile_data.get("subscription_id"),
            identity=profile_data.get("identity"),
            subscription_names=profile_data.get("subscription_names", []),
            created_at=profile_data.get("created_at"),
        )
        profiles.append(profile)

    return AzureProfileListResponse(
        profiles=profiles,
        profiles_file_exists=os.path.exists(AZURE_PROFILES_PATH),
        profiles_path=AZURE_PROFILES_PATH,
    )


@router.get("/{profile_name}")
async def get_profile_info(profile_name: str):
    """
    Get information about a specific Azure profile (without exposing secrets).
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    if profile_name not in profiles_dict:
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    profile_data = profiles_dict[profile_name]
    return AzureProfile(
        name=profile_name,
        tenant_id=profile_data.get("tenant_id", ""),
        client_id=profile_data.get("client_id", ""),
        subscription_id=profile_data.get("subscription_id"),
        identity=profile_data.get("identity"),
        subscription_names=profile_data.get("subscription_names", []),
        created_at=profile_data.get("created_at"),
    )


@router.get("/{profile_name}/credentials", include_in_schema=False)
async def get_profile_credentials(profile_name: str) -> AzureProfileCredentials:
    """
    Get credentials for an Azure profile. Internal use only - not exposed in API docs.
    Used by tool execution to get credentials.
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    if profile_name not in profiles_dict:
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    profile_data = profiles_dict[profile_name]

    return AzureProfileCredentials(
        tenant_id=profile_data.get("tenant_id", ""),
        client_id=profile_data.get("client_id", ""),
        client_secret=profile_data.get("client_secret", ""),
        subscription_id=profile_data.get("subscription_id"),
    )


@router.post("/{profile_name}/verify")
async def verify_profile(profile_name: str):
    """
    Verify that an Azure profile's credentials are valid.
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    if profile_name not in profiles_dict:
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    profile_data = profiles_dict[profile_name]

    result = _verify_azure_credentials(
        tenant_id=profile_data.get("tenant_id", ""),
        client_id=profile_data.get("client_id", ""),
        client_secret=profile_data.get("client_secret", ""),
    )

    return {
        "profile": profile_name,
        "valid": result.get("valid", False),
        "identity": result.get("identity"),
        "subscription_names": result.get("subscription_names", []),
        "error": result.get("error"),
    }


@router.post("")
@router.post("/")
async def save_profile(request: SaveAzureProfileRequest):
    """
    Save credentials as a new Azure profile.

    This validates the credentials first, then stores them securely.
    """
    profile_name = request.profile_name.strip()
    if not profile_name:
        raise HTTPException(status_code=400, detail="Profile name is required")

    # Verify credentials first
    result = _verify_azure_credentials(
        tenant_id=request.tenant_id,
        client_id=request.client_id,
        client_secret=request.client_secret,
    )

    if not result.get("valid"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid Azure credentials: {result.get('error', 'Unknown error')}"
        )

    # Read existing profiles
    data = _read_profiles_file()
    if "profiles" not in data:
        data["profiles"] = {}

    # Add or update the profile
    data["profiles"][profile_name] = {
        "tenant_id": request.tenant_id,
        "client_id": request.client_id,
        "client_secret": request.client_secret,
        "subscription_id": request.subscription_id,
        "identity": result.get("identity"),
        "subscription_names": result.get("subscription_names", []),
        "created_at": datetime.utcnow().isoformat(),
    }

    # Write profiles file
    _write_profiles_file(data)

    return {
        "success": True,
        "profile": profile_name,
        "identity": result.get("identity"),
        "subscription_names": result.get("subscription_names", []),
        "message": f"Profile '{profile_name}' saved successfully",
    }


@router.delete("/{profile_name}")
async def delete_profile(profile_name: str):
    """
    Delete an Azure profile.
    """
    data = _read_profiles_file()
    profiles_dict = data.get("profiles", {})

    if profile_name not in profiles_dict:
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    del profiles_dict[profile_name]
    data["profiles"] = profiles_dict
    _write_profiles_file(data)

    return {
        "success": True,
        "message": f"Profile '{profile_name}' deleted",
    }

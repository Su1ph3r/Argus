"""AWS Profiles API - Read profiles from mounted credentials file."""

import configparser
import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/aws-profiles", tags=["AWS Profiles"])

# Path to mounted AWS credentials
AWS_CREDENTIALS_PATH = "/app/credentials/aws/credentials"
AWS_CONFIG_PATH = "/app/credentials/aws/config"


class AWSProfile(BaseModel):
    """AWS profile information."""

    name: str
    has_access_key: bool
    has_secret_key: bool
    has_session_token: bool
    region: str | None = None


class AWSProfileCredentials(BaseModel):
    """AWS profile credentials (for internal use)."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None
    region: str | None = None


class SaveProfileRequest(BaseModel):
    """Request to save a new profile."""

    profile_name: str
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None
    region: str | None = None


class ProfileListResponse(BaseModel):
    """Response for listing profiles."""

    profiles: list[AWSProfile]
    credentials_file_exists: bool
    credentials_path: str


def _read_credentials_file() -> configparser.ConfigParser:
    """Read AWS credentials file."""
    config = configparser.ConfigParser()
    if os.path.exists(AWS_CREDENTIALS_PATH):
        config.read(AWS_CREDENTIALS_PATH)
    return config


def _read_config_file() -> configparser.ConfigParser:
    """Read AWS config file for regions."""
    config = configparser.ConfigParser()
    if os.path.exists(AWS_CONFIG_PATH):
        config.read(AWS_CONFIG_PATH)
    return config


def _get_region_for_profile(profile_name: str) -> str | None:
    """Get region from config file for a profile."""
    config = _read_config_file()

    # Config file uses "profile xyz" for non-default profiles
    section_name = "default" if profile_name == "default" else f"profile {profile_name}"

    if config.has_section(section_name):
        return config.get(section_name, "region", fallback=None)

    # Also check without "profile " prefix
    if config.has_section(profile_name):
        return config.get(profile_name, "region", fallback=None)

    return None


@router.get("", response_model=ProfileListResponse)
@router.get("/", response_model=ProfileListResponse)
async def list_profiles():
    """
    List available AWS profiles from the mounted credentials file.

    The credentials file should be mounted at /app/credentials/aws/credentials
    following the standard AWS credentials file format.
    """
    credentials = _read_credentials_file()

    profiles = []
    for section in credentials.sections():
        profile = AWSProfile(
            name=section,
            has_access_key=credentials.has_option(section, "aws_access_key_id"),
            has_secret_key=credentials.has_option(section, "aws_secret_access_key"),
            has_session_token=credentials.has_option(section, "aws_session_token"),
            region=_get_region_for_profile(section),
        )
        profiles.append(profile)

    return ProfileListResponse(
        profiles=profiles,
        credentials_file_exists=os.path.exists(AWS_CREDENTIALS_PATH),
        credentials_path=AWS_CREDENTIALS_PATH,
    )


@router.get("/{profile_name}")
async def get_profile_info(profile_name: str):
    """
    Get information about a specific profile (without exposing credentials).
    """
    credentials = _read_credentials_file()

    if not credentials.has_section(profile_name):
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    return AWSProfile(
        name=profile_name,
        has_access_key=credentials.has_option(profile_name, "aws_access_key_id"),
        has_secret_key=credentials.has_option(profile_name, "aws_secret_access_key"),
        has_session_token=credentials.has_option(profile_name, "aws_session_token"),
        region=_get_region_for_profile(profile_name),
    )


@router.get("/{profile_name}/credentials", include_in_schema=False)
async def get_profile_credentials(profile_name: str) -> AWSProfileCredentials:
    """
    Get credentials for a profile. Internal use only - not exposed in API docs.
    Used by tool execution to get credentials from the file.
    """
    credentials = _read_credentials_file()

    if not credentials.has_section(profile_name):
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    try:
        access_key = credentials.get(profile_name, "aws_access_key_id")
        secret_key = credentials.get(profile_name, "aws_secret_access_key")
    except configparser.NoOptionError as e:
        raise HTTPException(status_code=400, detail=f"Profile missing required credentials: {e}")

    session_token = None
    if credentials.has_option(profile_name, "aws_session_token"):
        session_token = credentials.get(profile_name, "aws_session_token")

    region = _get_region_for_profile(profile_name)

    return AWSProfileCredentials(
        access_key_id=access_key,
        secret_access_key=secret_key,
        session_token=session_token,
        region=region,
    )


@router.post("/{profile_name}/verify")
async def verify_profile(profile_name: str):
    """
    Verify that a profile's credentials are valid by calling STS GetCallerIdentity.
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    credentials = _read_credentials_file()

    if not credentials.has_section(profile_name):
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    try:
        access_key = credentials.get(profile_name, "aws_access_key_id")
        secret_key = credentials.get(profile_name, "aws_secret_access_key")
        session_token = None
        if credentials.has_option(profile_name, "aws_session_token"):
            session_token = credentials.get(profile_name, "aws_session_token")

        region = _get_region_for_profile(profile_name) or "us-east-1"

        # Create boto3 session with credentials
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
        )

        sts = session.client("sts")
        identity = sts.get_caller_identity()

        return {
            "valid": True,
            "profile": profile_name,
            "account": identity.get("Account"),
            "arn": identity.get("Arn"),
            "user_id": identity.get("UserId"),
            "region": region,
        }

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))
        return {
            "valid": False,
            "profile": profile_name,
            "error": error_code,
            "message": error_message,
        }
    except NoCredentialsError:
        return {
            "valid": False,
            "profile": profile_name,
            "error": "NoCredentials",
            "message": "Could not find credentials for profile",
        }
    except Exception as e:
        return {"valid": False, "profile": profile_name, "error": "Unknown", "message": str(e)}


def _write_credentials_file(config: configparser.ConfigParser) -> None:
    """Write AWS credentials file."""
    # Ensure directory exists
    try:
        os.makedirs(os.path.dirname(AWS_CREDENTIALS_PATH), exist_ok=True)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Permission denied creating directory {os.path.dirname(AWS_CREDENTIALS_PATH)}. "
                "On Linux, run: sudo chown -R 1000:1000 ./credentials/aws"
            )
        )

    try:
        with open(AWS_CREDENTIALS_PATH, "w") as f:
            config.write(f)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Permission denied writing to {AWS_CREDENTIALS_PATH}. "
                "On Linux, run: sudo chown -R 1000:1000 ./credentials/aws"
            )
        )


def _write_config_file(config: configparser.ConfigParser) -> None:
    """Write AWS config file."""
    try:
        os.makedirs(os.path.dirname(AWS_CONFIG_PATH), exist_ok=True)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Permission denied creating directory {os.path.dirname(AWS_CONFIG_PATH)}. "
                "On Linux, run: sudo chown -R 1000:1000 ./credentials/aws"
            )
        )

    try:
        with open(AWS_CONFIG_PATH, "w") as f:
            config.write(f)
    except PermissionError:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Permission denied writing to {AWS_CONFIG_PATH}. "
                "On Linux, run: sudo chown -R 1000:1000 ./credentials/aws"
            )
        )


@router.post("")
@router.post("/")
async def save_profile(request: SaveProfileRequest):
    """
    Save credentials as a new AWS profile.

    This writes the credentials to the AWS credentials file so they persist
    and can be selected as a profile for future scans.
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    profile_name = request.profile_name.strip()
    if not profile_name:
        raise HTTPException(status_code=400, detail="Profile name is required")

    # Validate the credentials first
    try:
        session = boto3.Session(
            aws_access_key_id=request.access_key_id,
            aws_secret_access_key=request.secret_access_key,
            aws_session_token=request.session_token,
            region_name=request.region or "us-east-1",
        )
        sts = session.client("sts")
        identity = sts.get_caller_identity()
    except (ClientError, NoCredentialsError) as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid credentials: {str(e)}"
        )

    # Read existing credentials file
    credentials = _read_credentials_file()

    # Add or update the profile
    if not credentials.has_section(profile_name):
        credentials.add_section(profile_name)

    credentials.set(profile_name, "aws_access_key_id", request.access_key_id)
    credentials.set(profile_name, "aws_secret_access_key", request.secret_access_key)

    if request.session_token:
        credentials.set(profile_name, "aws_session_token", request.session_token)
    elif credentials.has_option(profile_name, "aws_session_token"):
        credentials.remove_option(profile_name, "aws_session_token")

    # Write credentials file
    _write_credentials_file(credentials)

    # If region is specified, write to config file
    if request.region:
        config = _read_config_file()
        section_name = "default" if profile_name == "default" else f"profile {profile_name}"

        if not config.has_section(section_name):
            config.add_section(section_name)

        config.set(section_name, "region", request.region)
        _write_config_file(config)

    return {
        "success": True,
        "profile": profile_name,
        "account": identity.get("Account"),
        "arn": identity.get("Arn"),
        "message": f"Profile '{profile_name}' saved successfully",
    }


@router.delete("/{profile_name}")
async def delete_profile(profile_name: str):
    """
    Delete an AWS profile from the credentials file.
    """
    credentials = _read_credentials_file()

    if not credentials.has_section(profile_name):
        raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")

    credentials.remove_section(profile_name)
    _write_credentials_file(credentials)

    # Also remove from config file if present
    config = _read_config_file()
    section_name = "default" if profile_name == "default" else f"profile {profile_name}"
    if config.has_section(section_name):
        config.remove_section(section_name)
        _write_config_file(config)

    return {
        "success": True,
        "message": f"Profile '{profile_name}' deleted",
    }

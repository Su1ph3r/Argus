"""Routers package."""

from .assumed_roles import router as assumed_roles_router
from .attack_paths import router as attack_paths_router
from .cloudfox import router as cloudfox_router
from .compliance import router as compliance_router
from .credentials import router as credentials_router
from .enumerate_iam import router as enumerate_iam_router
from .executions import router as executions_router
from .exports import router as exports_router
from .exposed_credentials import router as exposed_credentials_router
from .findings import router as findings_router
from .health import router as health_router
from .imds_checks import router as imds_checks_router
from .lambda_analysis import router as lambda_analysis_router
from .pacu import router as pacu_router
from .privesc_paths import router as privesc_paths_router
from .public_exposures import router as public_exposures_router
from .scans import router as scans_router
from .settings import router as settings_router
from .severity_overrides import router as severity_overrides_router
from .sync import router as sync_router

__all__ = [
    "health_router",
    "scans_router",
    "findings_router",
    "exports_router",
    "attack_paths_router",
    "sync_router",
    "public_exposures_router",
    "exposed_credentials_router",
    "severity_overrides_router",
    "privesc_paths_router",
    "imds_checks_router",
    "cloudfox_router",
    "pacu_router",
    "enumerate_iam_router",
    "assumed_roles_router",
    "lambda_analysis_router",
    "executions_router",
    "credentials_router",
    "settings_router",
    "compliance_router",
]

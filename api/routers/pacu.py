"""Pacu Integration API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import PacuResult, ToolExecution, get_db
from models.schemas import (
    PacuResultListResponse,
    PacuResultResponse,
    PacuRunRequest,
    PacuSummary,
    ToolExecutionStartResponse,
)
from routers.executions import start_tool_execution
from services.docker_executor import ToolType

router = APIRouter(prefix="/pacu", tags=["Pacu"])


@router.get("", response_model=PacuResultListResponse)
@router.get("/", response_model=PacuResultListResponse)
async def list_pacu_results(
    db: Session = Depends(get_db),
    module_name: str | None = Query(None, description="Filter by module name"),
    module_category: str | None = Query(None, description="Filter by module category"),
    execution_status: str | None = Query(None, description="Filter by execution status"),
    session_name: str | None = Query(None, description="Filter by session name"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List Pacu execution results with optional filters."""
    query = db.query(PacuResult)

    if module_name:
        query = query.filter(PacuResult.module_name == module_name)

    if module_category:
        query = query.filter(PacuResult.module_category == module_category)

    if execution_status:
        query = query.filter(PacuResult.execution_status == execution_status.lower())

    if session_name:
        query = query.filter(PacuResult.session_name == session_name)

    total = query.count()

    results = (
        query.order_by(desc(PacuResult.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PacuResultListResponse(
        results=[PacuResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/backfill-results")
async def backfill_pacu_results(db: Session = Depends(get_db)):
    """
    Backfill PacuResult records from completed ToolExecution records.
    Use this once to populate results for past executions.
    """
    from routers.executions import _create_pacu_result
    from services.docker_executor import get_docker_executor

    # Get all Pacu executions that don't have results yet
    executions = (
        db.query(ToolExecution)
        .filter(
            ToolExecution.tool_name == "pacu", ToolExecution.status.in_(["completed", "failed"])
        )
        .all()
    )

    created = 0
    skipped = 0

    for execution in executions:
        # Check if result already exists
        existing = (
            db.query(PacuResult).filter(PacuResult.result_id == execution.execution_id).first()
        )

        if existing:
            skipped += 1
            continue

        # Try to get logs from container
        logs = ""
        if execution.container_id:
            try:
                executor = get_docker_executor()
                logs = await executor.get_execution_logs(execution.container_id, tail=500)
            except Exception:
                logs = execution.error_message or ""

        # Create result
        _create_pacu_result(db, execution, logs)
        created += 1

    return {"message": "Backfill complete", "created": created, "skipped": skipped}


@router.get("/summary", response_model=PacuSummary)
async def get_pacu_summary(db: Session = Depends(get_db)):
    """Get summary statistics of Pacu executions."""
    total = db.query(PacuResult).count()
    successful = db.query(PacuResult).filter(PacuResult.execution_status == "success").count()
    failed = db.query(PacuResult).filter(PacuResult.execution_status == "failed").count()

    module_counts = dict(
        db.query(PacuResult.module_name, func.count(PacuResult.id))
        .group_by(PacuResult.module_name)
        .all()
    )

    category_counts = dict(
        db.query(PacuResult.module_category, func.count(PacuResult.id))
        .group_by(PacuResult.module_category)
        .all()
    )

    return PacuSummary(
        total_executions=total,
        successful=successful,
        failed=failed,
        by_module={k: v for k, v in module_counts.items() if k},
        by_category={k: v for k, v in category_counts.items() if k},
    )


@router.get("/modules")
async def list_available_modules():
    """List available Pacu modules by category."""
    # Actual module names from Pacu --list-modules
    modules = {
        "ENUM": [
            "iam__enum_permissions",
            "iam__enum_users_roles_policies_groups",
            "iam__bruteforce_permissions",
            "iam__enum_roles",
            "iam__enum_users",
            "iam__get_credential_report",
            "ec2__enum",
            "lambda__enum",
            "rds__enum",
            "rds__enum_snapshots",
            "ecs__enum",
            "ecs__enum_task_def",
            "eks__enum",
            "sns__enum",
            "secrets__enum",
            "dynamodb__enum",
            "ebs__enum_volumes_snapshots",
            "aws__enum_account",
            "aws__enum_spend",
            "acm__enum",
            "apigateway__enum",
            "codebuild__enum",
            "cognito__enum",
            "ecr__enum",
            "elasticbeanstalk__enum",
            "glue__enum",
            "lightsail__enum",
            "organizations__enum",
            "route53__enum",
            "transfer_family__enum",
        ],
        "ESCALATE": [
            "iam__privesc_scan",
            "cfn__resource_injection",
        ],
        "PERSIST": [
            "iam__backdoor_users_keys",
            "iam__backdoor_users_password",
            "iam__backdoor_assume_role",
            "lambda__backdoor_new_sec_groups",
            "lambda__backdoor_new_roles",
            "lambda__backdoor_new_users",
            "ec2__backdoor_ec2_sec_groups",
            "ecs__backdoor_task_def",
        ],
        "EXFIL": [
            "s3__download_bucket",
            "ebs__download_snapshots",
            "rds__explore_snapshots",
            "ebs__explore_snapshots",
        ],
        "EXPLOIT": [
            "ec2__startup_shell_script",
            "systemsmanager__rce_ec2",
            "cognito__attack",
            "api_gateway__create_api_keys",
            "eks__collect_tokens",
            "lightsail__download_ssh_keys",
            "lightsail__generate_ssh_keys",
            "lightsail__generate_temp_access",
        ],
        "EVADE": [
            "detection__enum_services",
            "detection__disruption",
            "cloudtrail__download_event_history",
            "cloudwatch__download_logs",
            "guardduty__list_findings",
            "guardduty__list_accounts",
            "guardduty__whitelist_ip",
            "elb__enum_logging",
            "waf__enum",
        ],
        "RECON_UNAUTH": [
            "ebs__enum_snapshots_unauth",
            "iam__enum_roles",
            "iam__enum_users",
        ],
    }

    return modules


@router.get("/{result_id}", response_model=PacuResultResponse)
async def get_pacu_result(result_id: int, db: Session = Depends(get_db)):
    """Get a specific Pacu result by ID."""
    result = db.query(PacuResult).filter(PacuResult.id == result_id).first()

    if not result:
        raise HTTPException(status_code=404, detail="Pacu result not found")

    return PacuResultResponse.model_validate(result)


@router.get("/session/{session_name}", response_model=PacuResultListResponse)
async def get_results_by_session(
    session_name: str,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """Get all Pacu results for a specific session."""
    query = db.query(PacuResult).filter(PacuResult.session_name == session_name)

    total = query.count()

    results = (
        query.order_by(desc(PacuResult.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PacuResultListResponse(
        results=[PacuResultResponse.model_validate(r) for r in results],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/run", response_model=ToolExecutionStartResponse)
async def run_pacu_module(request: PacuRunRequest, db: Session = Depends(get_db)):
    """
    Trigger Pacu module execution.

    Starts a Pacu container to run the specified module.
    Results will be stored asynchronously after execution.

    Use GET /api/executions/{execution_id} to check status.
    """
    # Build environment with credentials if provided
    environment = {}
    if request.access_key:
        environment["AWS_ACCESS_KEY_ID"] = request.access_key
    if request.secret_key:
        environment["AWS_SECRET_ACCESS_KEY"] = request.secret_key
    if request.session_token:
        environment["AWS_SESSION_TOKEN"] = request.session_token
    if request.region:
        environment["AWS_DEFAULT_REGION"] = request.region

    # Build the Pacu command
    # Pacu picks up AWS creds from environment variables (AWS_ACCESS_KEY_ID, etc.)
    # We pipe multiple "y" answers for various prompts (regions, credentials, etc.)
    session_name = request.session_name or "api-session"

    # Use --module-name and --exec flags (not --exec "run module")
    # Use yes command to auto-answer all prompts with "y"
    command = [
        "-c",
        f"yes y | pacu --new-session {session_name} --module-name {request.module} --exec",
    ]

    # Build config for tracking
    config = {
        "module": request.module,
        "session_name": request.session_name,
        "args": request.args,
        "has_credentials": bool(request.access_key),
    }

    # Start the execution with shell entrypoint to handle quoting
    result = await start_tool_execution(
        tool_name="pacu",
        tool_type=ToolType.PACU,
        config=config,
        command=command,
        environment=environment if environment else None,
        entrypoint="/bin/sh",
        db=db,
    )

    return result

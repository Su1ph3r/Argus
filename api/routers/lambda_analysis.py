"""Lambda Code Analysis API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from models.database import LambdaAnalysis, get_db
from models.schemas import (
    LambdaAnalysisListResponse,
    LambdaAnalysisResponse,
    LambdaAnalysisSummary,
    LambdaAnalyzeRequest,
)

router = APIRouter(prefix="/lambda-analysis", tags=["Lambda Analysis"])


@router.get("", response_model=LambdaAnalysisListResponse)
@router.get("/", response_model=LambdaAnalysisListResponse)
async def list_lambda_analyses(
    db: Session = Depends(get_db),
    region: str | None = Query(None, description="Filter by region"),
    runtime: str | None = Query(None, description="Filter by runtime"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    analysis_status: str | None = Query(None, description="Filter by analysis status"),
    has_secrets: bool | None = Query(None, description="Filter functions with secrets"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List Lambda analysis results with optional filters."""
    query = db.query(LambdaAnalysis)

    if region:
        query = query.filter(LambdaAnalysis.region == region)

    if runtime:
        query = query.filter(LambdaAnalysis.runtime == runtime)

    if risk_level:
        query = query.filter(LambdaAnalysis.risk_level == risk_level.lower())

    if analysis_status:
        query = query.filter(LambdaAnalysis.analysis_status == analysis_status.lower())

    if has_secrets is not None:
        if has_secrets:
            query = query.filter(func.jsonb_array_length(LambdaAnalysis.secrets_found) > 0)
        else:
            query = query.filter(
                (LambdaAnalysis.secrets_found == None)
                | (func.jsonb_array_length(LambdaAnalysis.secrets_found) == 0)
            )

    total = query.count()

    analyses = (
        query.order_by(desc(LambdaAnalysis.risk_score), desc(LambdaAnalysis.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return LambdaAnalysisListResponse(
        analyses=[LambdaAnalysisResponse.model_validate(a) for a in analyses],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/summary", response_model=LambdaAnalysisSummary)
async def get_lambda_summary(db: Session = Depends(get_db)):
    """Get summary statistics of Lambda analyses."""
    total = db.query(LambdaAnalysis).count()

    # Count functions with secrets
    with_secrets = (
        db.query(LambdaAnalysis)
        .filter(func.jsonb_array_length(LambdaAnalysis.secrets_found) > 0)
        .count()
    )

    # Count functions with vulnerable dependencies
    with_vulns = (
        db.query(LambdaAnalysis)
        .filter(func.jsonb_array_length(LambdaAnalysis.vulnerable_dependencies) > 0)
        .count()
    )

    # High risk functions
    high_risk = db.query(LambdaAnalysis).filter(LambdaAnalysis.risk_score >= 70).count()

    # By runtime
    runtime_counts = dict(
        db.query(LambdaAnalysis.runtime, func.count(LambdaAnalysis.id))
        .group_by(LambdaAnalysis.runtime)
        .all()
    )

    # By region
    region_counts = dict(
        db.query(LambdaAnalysis.region, func.count(LambdaAnalysis.id))
        .group_by(LambdaAnalysis.region)
        .all()
    )

    return LambdaAnalysisSummary(
        total_functions=total,
        functions_with_secrets=with_secrets,
        functions_with_vulns=with_vulns,
        high_risk=high_risk,
        by_runtime={k: v for k, v in runtime_counts.items() if k},
        by_region={k: v for k, v in region_counts.items() if k},
    )


@router.get("/risky", response_model=LambdaAnalysisListResponse)
async def list_risky_functions(
    db: Session = Depends(get_db),
    min_risk_score: int = Query(50, ge=0, le=100, description="Minimum risk score"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List Lambda functions with security issues."""
    query = db.query(LambdaAnalysis).filter(LambdaAnalysis.risk_score >= min_risk_score)

    total = query.count()

    analyses = (
        query.order_by(desc(LambdaAnalysis.risk_score))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return LambdaAnalysisListResponse(
        analyses=[LambdaAnalysisResponse.model_validate(a) for a in analyses],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/with-secrets", response_model=LambdaAnalysisListResponse)
async def list_functions_with_secrets(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
):
    """List Lambda functions with exposed secrets."""
    query = db.query(LambdaAnalysis).filter(
        func.jsonb_array_length(LambdaAnalysis.secrets_found) > 0
    )

    total = query.count()

    analyses = (
        query.order_by(desc(LambdaAnalysis.risk_score))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return LambdaAnalysisListResponse(
        analyses=[LambdaAnalysisResponse.model_validate(a) for a in analyses],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{analysis_id}", response_model=LambdaAnalysisResponse)
async def get_lambda_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Get a specific Lambda analysis by ID."""
    analysis = db.query(LambdaAnalysis).filter(LambdaAnalysis.id == analysis_id).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Lambda analysis not found")

    return LambdaAnalysisResponse.model_validate(analysis)


@router.get("/function/{function_arn:path}", response_model=LambdaAnalysisResponse)
async def get_analysis_by_function(function_arn: str, db: Session = Depends(get_db)):
    """Get Lambda analysis for a specific function ARN."""
    analysis = db.query(LambdaAnalysis).filter(LambdaAnalysis.function_arn == function_arn).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="No analysis found for this function")

    return LambdaAnalysisResponse.model_validate(analysis)


@router.get("/{analysis_id}/findings")
async def get_analysis_findings(analysis_id: int, db: Session = Depends(get_db)):
    """Get detailed security findings for a Lambda analysis."""
    analysis = db.query(LambdaAnalysis).filter(LambdaAnalysis.id == analysis_id).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Lambda analysis not found")

    findings = {
        "function_name": analysis.function_name,
        "function_arn": analysis.function_arn,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "findings": {
            "secrets": analysis.secrets_found or [],
            "hardcoded_credentials": analysis.hardcoded_credentials or [],
            "vulnerable_dependencies": analysis.vulnerable_dependencies or [],
            "insecure_patterns": analysis.insecure_patterns or [],
            "api_keys": analysis.api_keys_exposed or [],
            "database_connections": analysis.database_connections or [],
            "external_urls": analysis.external_urls or [],
        },
        "environment_analysis": {
            "has_vpc_config": analysis.has_vpc_config,
            "layers_count": len(analysis.layers or []),
            "env_vars_count": len(analysis.environment_variables or {}),
        },
    }

    return findings


@router.get("/{analysis_id}/export")
async def export_lambda_analysis(
    analysis_id: int,
    format: str = Query("markdown", description="Export format: markdown, json"),
    db: Session = Depends(get_db),
):
    """Export Lambda analysis for reporting."""
    analysis = db.query(LambdaAnalysis).filter(LambdaAnalysis.id == analysis_id).first()

    if not analysis:
        raise HTTPException(status_code=404, detail="Lambda analysis not found")

    if format == "json":
        return LambdaAnalysisResponse.model_validate(analysis)

    # Markdown format
    secrets = analysis.secrets_found or []
    vulns = analysis.vulnerable_dependencies or []
    patterns = analysis.insecure_patterns or []

    md_lines = [
        f"# Lambda Security Analysis: {analysis.function_name}",
        "",
        f"**Function ARN:** `{analysis.function_arn}`",
        f"**Risk Score:** {analysis.risk_score}/100 ({analysis.risk_level})",
        f"**Runtime:** {analysis.runtime}",
        f"**Region:** {analysis.region}",
        "",
        "## Configuration",
        "",
        f"- **Memory:** {analysis.memory_size} MB",
        f"- **Timeout:** {analysis.timeout_seconds} seconds",
        f"- **Code Size:** {(analysis.code_size_bytes or 0) / 1024:.1f} KB",
        f"- **VPC Config:** {'Yes' if analysis.has_vpc_config else 'No'}",
        "",
    ]

    if secrets:
        md_lines.extend(
            [
                "## Exposed Secrets",
                "",
            ]
        )
        for s in secrets:
            md_lines.append(
                f"- **{s.get('type', 'Unknown')}**: `{s.get('value_preview', '***')}` at {s.get('location', 'Unknown')}"
            )
        md_lines.append("")

    if vulns:
        md_lines.extend(
            [
                "## Vulnerable Dependencies",
                "",
            ]
        )
        for v in vulns:
            md_lines.append(
                f"- **{v.get('package', 'Unknown')}** {v.get('version', '')}: {v.get('vulnerability', 'Unknown')} ({v.get('severity', 'Unknown')})"
            )
        md_lines.append("")

    if patterns:
        md_lines.extend(
            [
                "## Insecure Code Patterns",
                "",
            ]
        )
        for p in patterns:
            md_lines.append(f"### {p.get('pattern_type', 'Unknown')}")
            md_lines.append(f"{p.get('description', '')}")
            md_lines.append(f"- Location: {p.get('location', 'Unknown')}")
            md_lines.append(f"- Recommendation: {p.get('recommendation', 'N/A')}")
            md_lines.append("")

    md_lines.extend(["---", "*Generated by Nubicustos Lambda Code Analysis*"])

    return {"format": "markdown", "content": "\n".join(md_lines)}


@router.post("/analyze")
async def analyze_lambda_functions(request: LambdaAnalyzeRequest, db: Session = Depends(get_db)):
    """
    Trigger Lambda function code analysis.

    This downloads function code and analyzes it for secrets,
    vulnerable dependencies, and insecure patterns.
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

    # Build config for tracking
    config = {
        "function_arns": request.function_arns,
        "regions": request.regions,
        "analyze_all": request.analyze_all,
        "has_credentials": bool(request.access_key),
    }

    return {
        "status": "queued",
        "message": "Lambda analysis queued for execution",
        "function_arns": request.function_arns,
        "regions": request.regions,
        "analyze_all": request.analyze_all,
        "credentials_provided": bool(request.access_key),
        "note": "Check /api/lambda-analysis for results after analysis completes",
    }

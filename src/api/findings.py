"""
FastAPI router for compliance findings.
"""
from __future__ import annotations
import logging
from datetime import date, datetime
from typing import Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel

log = logging.getLogger(__name__)
router = APIRouter(prefix="/findings", tags=["findings"])


class FindingOut(BaseModel):
    id: str
    rule_name: str
    resource_id: str
    resource_type: str
    severity: str
    control_ids: list[str]
    account_id: str
    region: str
    status: str
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    discovered_at: datetime


class SuppressionRequest(BaseModel):
    reason: str
    expiry_date: Optional[date] = None
    ticket_ref: Optional[str] = None


class ComplianceScore(BaseModel):
    framework: str
    score: float
    total: int
    passed: int
    failed: int
    suppressed: int
    by_severity: dict[str, dict[str, int]]


# In-memory store — replace with DB in production
_findings: dict[str, dict] = {}
_suppressions: dict[str, dict] = {}


@router.get("/", response_model=list[FindingOut])
async def list_findings(
    severity: Optional[str] = Query(None, enum=["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    framework: Optional[str] = None,
    status: Optional[str] = Query(None, enum=["PASS", "FAIL", "SUPPRESSED"]),
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> list[FindingOut]:
    results = list(_findings.values())
    if severity:
        results = [f for f in results if f["severity"] == severity]
    if account_id:
        results = [f for f in results if f["account_id"] == account_id]
    if region:
        results = [f for f in results if f["region"] == region]
    if status == "SUPPRESSED":
        results = [f for f in results if f["id"] in _suppressions]
    elif status:
        results = [f for f in results if f["status"] == status and f["id"] not in _suppressions]
    start = (page - 1) * size
    return [FindingOut(**f, suppressed=f["id"] in _suppressions) for f in results[start : start + size]]


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str) -> FindingOut:
    f = _findings.get(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    supp = _suppressions.get(finding_id)
    return FindingOut(**f, suppressed=bool(supp), suppression_reason=supp["reason"] if supp else None)


@router.post("/{finding_id}/suppress", status_code=201)
async def suppress_finding(finding_id: str, body: SuppressionRequest) -> dict:
    if finding_id not in _findings:
        raise HTTPException(status_code=404, detail="Finding not found")
    _suppressions[finding_id] = {
        "reason": body.reason,
        "expiry_date": body.expiry_date.isoformat() if body.expiry_date else None,
        "ticket_ref": body.ticket_ref,
        "suppressed_at": datetime.utcnow().isoformat(),
    }
    log.info("Finding %s suppressed: %s", finding_id, body.reason)
    return {"id": finding_id, "suppressed": True}


@router.delete("/{finding_id}/suppress", status_code=204)
async def unsuppress_finding(finding_id: str) -> None:
    if finding_id not in _suppressions:
        raise HTTPException(status_code=404, detail="Suppression not found")
    del _suppressions[finding_id]


@router.get("/compliance-score/{framework}", response_model=ComplianceScore)
async def compliance_score(framework: str) -> ComplianceScore:
    findings = list(_findings.values())
    total = len(findings)
    if total == 0:
        return ComplianceScore(framework=framework, score=100.0, total=0, passed=0, failed=0, suppressed=0, by_severity={})
    suppressed = len([f for f in findings if f["id"] in _suppressions])
    passed = len([f for f in findings if f["status"] == "PASS"])
    failed = total - passed - suppressed
    score = round((passed / total) * 100, 1)
    by_sev: dict[str, dict[str, int]] = {}
    for f in findings:
        s = f["severity"]
        by_sev.setdefault(s, {"passed": 0, "failed": 0})
        if f["status"] == "PASS":
            by_sev[s]["passed"] += 1
        else:
            by_sev[s]["failed"] += 1
    return ComplianceScore(
        framework=framework, score=score, total=total,
        passed=passed, failed=failed, suppressed=suppressed, by_severity=by_sev,
    )

# _r 20260707091410-449fb0c3

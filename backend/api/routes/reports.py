"""
AI Shield — Reports Route (Enterprise tier)
=============================================
GET  /reports/summary    — detection summary for date range
POST /reports/compliance — trigger NIS2/DORA report via KalevioAI

Enterprise feature. NIS2/DORA reporting via KalevioAI integration.
"""
from fastapi import APIRouter

router = APIRouter()


@router.get("/summary")
async def detection_summary(days: int = 7):
    """Return detection summary for the last N days."""
    # TODO Sprint 3: query PostgreSQL for tenant's detection events
    return {"days": days, "total": 0, "blocked": 0, "alerted": 0}


@router.post("/compliance")
async def trigger_compliance_report(incident_id: str):
    """
    Trigger a NIS2/DORA compliance report via KalevioAI.
    Enterprise tier only.

    Posts to KalevioAI /incidents endpoint which auto-generates
    the report and files with CSIRT if threshold exceeded.
    """
    # TODO Sprint 3: POST to KalevioAI API
    return {"incident_id": incident_id, "status": "queued", "destination": "kalevioai"}

from dataclasses import asdict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.email_analyzer import analyze

router = APIRouter()


class EmailAnalysisRequest(BaseModel):
    raw_email: str = Field(..., min_length=1, max_length=500_000,
                            description="Raw email source: headers + body")


@router.post("/analyze-email")
async def analyze_email(payload: EmailAnalysisRequest):
    result = analyze(payload.raw_email)
    return asdict(result)

from dataclasses import asdict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.header_checker import fetch_and_check

router = APIRouter()


class HeaderCheckRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Domain or URL to check")


@router.post("/check-headers")
async def check_headers(payload: HeaderCheckRequest):
    result = await fetch_and_check(payload.url)
    return asdict(result)

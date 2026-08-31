from dataclasses import asdict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.code_scanner import scan_code

router = APIRouter()


class CodeScanRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=200_000, description="Source code to scan")


@router.post("/scan-code")
async def scan_code_route(payload: CodeScanRequest):
    result = scan_code(payload.code)
    return asdict(result)

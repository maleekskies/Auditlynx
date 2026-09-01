from dataclasses import asdict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.breach_checker import check_email

router = APIRouter()


class BreachCheckRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254, description="Email to check")


@router.post("/check-breach")
async def check_breach_route(payload: BreachCheckRequest):
    result = await check_email(payload.email)
    return asdict(result)

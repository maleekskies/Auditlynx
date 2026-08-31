from dataclasses import asdict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.dns_recon import recon_domain

router = APIRouter()


class DomainReconRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253, description="Domain to look up")


@router.post("/recon-domain")
async def recon_domain_route(payload: DomainReconRequest):
    result = await recon_domain(payload.domain)
    return asdict(result)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import code_scanner, dns_recon, headers, phishing

app = FastAPI(
    title="SecOps Toolkit API",
    description="Backend API for the security headers checker and phishing email analyzer.",
    version="1.0.0",
)

# CORS: open by default for local/dev use. Lock this down to your actual
# frontend origin(s) before deploying somewhere public.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://secops-toolkit-ecru.vercel.app",
        "https://cybertriage.vercel.app",
        "https://auditlynx.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(headers.router, prefix="/api", tags=["headers"])
app.include_router(phishing.router, prefix="/api", tags=["phishing"])
app.include_router(dns_recon.router, prefix="/api", tags=["dns_recon"])
app.include_router(code_scanner.router, prefix="/api", tags=["code_scanner"])


@app.get("/api/health")
def health_check():
    return {"status": "ok"}

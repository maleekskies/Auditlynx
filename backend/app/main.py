from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import headers, phishing

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

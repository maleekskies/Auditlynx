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
    allow_origins=["https://secops-toolkit-ecru.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(headers.router, prefix="/api", tags=["headers"])
app.include_router(phishing.router, prefix="/api", tags=["phishing"])


@app.get("/api/health")
def health_check():
    return {"status": "ok"}

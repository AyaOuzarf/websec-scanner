"""
WebSec Scanner API — main FastAPI application entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.models.database import init_db
from api.routes import scans

from api.routes import scans, targets


app = FastAPI(
    title="WebSec Scanner API",
    description="Automated website security assessment platform",
    version="0.1.0",
)

# Allow the dashboard (running on a different port) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in Week 4 once auth is added
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"status": "ok", "service": "WebSec Scanner API"}


app.include_router(scans.router)
app.include_router(targets.router)
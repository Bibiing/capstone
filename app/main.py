from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router

app = FastAPI(
    title="Jrisk",
    openapi_url="/api-jrisk/openapi.json",
    docs_url="/api-jrisk/docs",
    redoc_url="/api-jrisk/redoc")

app.include_router(auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
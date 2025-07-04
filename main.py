from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import health, system, vmess, config

# Create FastAPI app
app = FastAPI(
    title="BadProxy API",
    description="VMess Management API for v2ray-agent with domain fronting support",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(system.router, prefix="/system", tags=["System"])
app.include_router(vmess.router, prefix="/vmess", tags=["VMess Management"])
app.include_router(config.router, prefix="/config", tags=["Configuration"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
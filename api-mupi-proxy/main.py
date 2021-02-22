from fastapi import FastAPI
import uvicorn
from motor.motor_asyncio import AsyncIOMotorClient
from config import settings
from app.mupiproxy.routers import router as mupi_proxy_router

app = FastAPI()

@app.on_event("startup")
async def startup_db_client():
    app.mongodb_client = AsyncIOMotorClient(settings.DB_URL)
    app.mongodb = app.mongodb_client[settings.DB_NAME]


@app.on_event("shutdown")
async def shutdown_db_client():
    app.mongodb_client.close()

app.include_router(mupi_proxy_router, tags=["mupi-proxy"], prefix="/mupi-proxy")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        reload=settings.DEBUG_MODE,
        port=settings.PORT,
    )
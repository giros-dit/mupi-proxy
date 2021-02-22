from fastapi import FastAPI

#ROUTES
from .routes.provider import router as ProviderRouter
from .routes.murtentry import router as MURTEntryRouter
from .routes.sdncontroller import router as SDNControllerRouter

app = FastAPI()
app.include_router(ProviderRouter, tags=["Provider"], prefix="/mupi-proxy/provider")
app.include_router(MURTEntryRouter, tags=["MURT"], prefix="/mupi-proxy/murtentry")
app.include_router(SDNControllerRouter, tags=["SDNController"], prefix="/mupi-proxy/sdncontroller")


@app.get("/", tags=["Root"])
async def read_root():
    return {"Welcome to":"MUPI-PROXY"}

@app.get("/mupi-proxy", tags=["Root"])
async def read_root2():
    return {"Welcome to":"MUPI-PROXY"}
from fastapi import APIRouter, Body, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from typing import Optional, List
from .models import MurtEntry, UpdateMurtEntry, Provider, UpdateProvider, SDNController, UpdateSDNController

router = APIRouter()

"""
Main
"""
@router.get("/", response_description="Ejemplo")
async def get_root(request: Request):
    return {"Welcome to":"MUPI-PROXY"}





###############################################
#PROVIDER
###############################################

"""
Add content provider: adds an IP multicast content provider
"""
@router.post("/provider", tags=["Provider"], response_description="Add new provider", response_model=Provider)
async def create_provider(request: Request, provider: Provider = Body(...)):
    provider = jsonable_encoder(provider)
    new_provider = await request.app.mongodb["providers"].insert_one(provider)
    created_provider = await request.app.mongodb["providers"].find_one(
        {"_id": new_provider.inserted_id}
    )

    return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_provider)


"""
List content providers: lists the content providers added to the multicast proxy.
"""
@router.get("/provider", tags=["Provider"], response_description="List all providers", response_model=List[Provider])
async def get_all_providers(request: Request):
    providers = await request.app.mongodb["providers"].find().to_list(1000)
    return providers


"""
Show content provider: shows detailed information about a content provider such as IP address, upstream interface, among others.
"""
@router.get("/provider/{provider_id}", tags=["Provider"], response_description="Get a single provider", response_model=Provider)
async def get_provider(provider_id: str, request: Request):
    if (provider := await request.app.mongodb["providers"].find_one({"_id": provider_id})) is not None:
        return provider

    raise HTTPException(status_code=404, detail=f"Provider {provider_id} not found")


"""
Update content provider: updates functional parameters of a content provider.
"""
@router.put("/provider/{provider_id}", tags=["Provider"], response_description="Update a provider", response_model=Provider)
async def update_provider(provider_id: str, request: Request, provider: UpdateProvider = Body(...)):
    provider = {k: v for k, v in provider.dict().items() if v is not None}

    if len(provider) >= 1:
        update_result = await request.app.mongodb["providers"].update_one(
            {"_id": provider_id}, {"$set": provider}
        )


        if update_result.modified_count == 1:
            if (
                updated_provider := await request.app.mongodb["providers"].find_one({"_id": provider_id})
            ) is not None:
                return updated_provider

    if (
        existing_provider := await request.app.mongodb["providers"].find_one({"_id": provider_id})
    ) is not None:
        return existing_provider

    raise HTTPException(status_code=404, detail=f"Provider {provider_id} not found")


"""
Delete content provider: deletes a content provider from the multicast proxy. 
"""
@router.delete("/provider/{provider_id}", tags=["Provider"], response_description="Delete Provider")
async def delete_provider(provider_id: str, request: Request):
    delete_result = await request.app.mongodb["providers"].delete_one({"_id": provider_id})

    if delete_result.deleted_count == 1:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)

    raise HTTPException(status_code=404, detail=f"Provider {provider_id} not found")


"""
Clear content providers: deletes all the content providers from the multicast proxy.
"""
@router.delete("/provider", tags=["Provider"], response_description="Delete All providers")
async def delete_all_providers(request: Request):
    delete_result = await request.app.mongodb["providers"].delete_many({})
    if delete_result.deleted_count >= 0:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)
    raise HTTPException(status_code=404, detail=f"Providers not found")





###############################################
#MURT ENTRY
###############################################

"""
Add murt entry: adds a new entry in MURT. 
"""
@router.post("/murtentry", tags=["MURT"], response_description="Add new MURT Entry", response_model=MurtEntry)
async def create_murt_entry(request: Request, murtentry: MurtEntry = Body(...)):
    murt_entry = jsonable_encoder(murtentry)
    new_entry = await request.app.mongodb["murtentries"].insert_one(murt_entry)
    created_entry = await request.app.mongodb["murtentries"].find_one(
        {"_id": new_entry.inserted_id}
    )

    return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_entry)


"""
List murt entries: lists the current entries in MURT
"""
@router.get("/murtentry", tags=["MURT"], response_description="List all MURT Entries", response_model=List[MurtEntry])
async def get_all_murt_entries(request: Request):
    murt = await request.app.mongodb["murtentries"].find().to_list(1000)
    return murt


"""
Show murt entry: shows a MURT entry in detail.
"""
@router.get("/murtentry/{murtentry_id}", tags=["MURT"], response_description="Get a single MURT Entry", response_model=MurtEntry)
async def get_murt_entry(murtentry_id: str, request: Request):
    if (murtentry := await request.app.mongodb["murtentries"].find_one({"_id": murtentry_id})) is not None:
        return murtentry

    raise HTTPException(status_code=404, detail=f"MURT Entry {murtentry_id} not found")


"""
Update murt entry: updates a MURT entry, reconfiguring the switch flow tables according to the modification. 
"""
@router.put("/murtentry/{murtentry_id}", tags=["MURT"], response_description="Update a MURT Entry", response_model=MurtEntry)
async def update_murt_entry(murtentry_id: str, request: Request, murtentry: UpdateMurtEntry = Body(...)):
    murtentry = {k: v for k, v in murtentry.dict().items() if v is not None}

    if len(murtentry) >= 1:
        update_result = await request.app.mongodb["murtentries"].update_one(
            {"_id": murtentry_id}, {"$set": murtentry}
        )

        if update_result.modified_count == 1:
            if (
                updated_murtentry := await request.app.mongodb["murtentries"].find_one({"_id": murtentry_id})
            ) is not None:
                return updated_murtentry

    if (
        existing_murtentry := await request.app.mongodb["murtentries"].find_one({"_id": murtentry_id})
    ) is not None:
        return existing_murtentry

    raise HTTPException(status_code=404, detail=f"MURT Entry {murtentry_id} not found")


"""
Delete murt entry: deletes an entry from MURT.
"""
@router.delete("/murtentry/{murtentry_id}", tags=["MURT"], response_description="Delete MURT Entry")
async def delete_murt_entry(murtentry_id: str, request: Request):
    delete_result = await request.app.mongodb["murtentries"].delete_one({"_id": murtentry_id})

    if delete_result.deleted_count == 1:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)

    raise HTTPException(status_code=404, detail=f"MURT Entry {murtentry_id} not found")


"""
Clear murt entries: deletes all entries from MURT. 
"""
@router.delete("/murtentry", tags=["MURT"], response_description="Delete All MURT Entries")
async def delete_all_murt_entries(request: Request):
    delete_result = await request.app.mongodb["murtentries"].delete_many({})
    if delete_result.deleted_count >= 0:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)
    raise HTTPException(status_code=404, detail=f"MURT Entries not found")





###############################################
#SDN CONTROLLER
###############################################

"""
Add main SDN controller: adds a main SDN controller. The
local SDN controller of the multicast proxy is configured
as secondary controller. In this light, a hierarchical
multicast proxy structure is created
"""
@router.post("/sdncontroller", tags=["SDNController"], response_description="Add new SDN Controller", response_model=SDNController)
async def create_sdn_controller(request: Request, sdncontroller: SDNController = Body(...)):
    sdn_controller = jsonable_encoder(sdncontroller)
    new_entry = await request.app.mongodb["sdncontrollers"].insert_one(sdn_controller)
    created_entry = await request.app.mongodb["sdncontrollers"].find_one(
        {"_id": new_entry.inserted_id}
    )

    return JSONResponse(status_code=status.HTTP_201_CREATED, content=created_entry)


"""
List SDN Controllers: lists all SDN Controllers
"""
@router.get("/sdncontroller", tags=["SDNController"], response_description="List all SDN Controllers Entries", response_model=List[SDNController])
async def get_all_sdn_controllers(request: Request):
    sdncontrollers = await request.app.mongodb["sdncontrollers"].find().to_list(1000)
    return sdncontrollers


"""
Show main SDN controller: shows detailed information
about the main SDN controller such as openflow version,
TCP port, IP address, among others. 
"""
@router.get("/sdncontroller/{sdn_controller_id}", tags=["SDNController"], response_description="Show Main SDN Controller", response_model=SDNController)
async def get_main_sdn_controller(sdn_controller_id: str, request: Request):
    if (sdncontroller := await request.app.mongodb["sdncontrollers"].find_one({"_id": sdn_controller_id})) is not None:
        return sdncontroller
    raise HTTPException(status_code=404, detail=f"SDN Controller {sdn_controller_id} not found")


"""
Update main SDN controller: updates functional
parameters of the controller.
"""
@router.put("/sdncontroller/{sdn_controller_id}", tags=["SDNController"], response_description="Update a SDN Controller", response_model=SDNController)
async def update_sdn_controller(sdn_controller_id: str, request: Request, sdncontroller: UpdateSDNController = Body(...)):
    sdncontroller = {k: v for k, v in sdncontroller.dict().items() if v is not None}

    if len(sdncontroller) >= 1:
        update_result = await request.app.mongodb["sdncontrollers"].update_one(
            {"_id": sdn_controller_id}, {"$set": sdncontroller}
        )

        if update_result.modified_count == 1:
            if (
                updated_sdncontroller := await request.app.mongodb["sdncontrollers"].find_one({"_id": sdn_controller_id})
            ) is not None:
                return updated_sdncontroller

    if (
        existing_sdncontroller := await request.app.mongodb["sdncontrollers"].find_one({"_id": sdn_controller_id})
    ) is not None:
        return existing_sdncontroller

    raise HTTPException(status_code=404, detail=f"SDN Controller {sdn_controller_id} not found")

"""
Delete main SDN controller: deletes the main SDN
controller. In this light, the hierarchical structure is also
deleted. 
"""
@router.delete("/sdncontroller/{sdn_controller_id}", tags=["SDNController"], response_description="Delete Main SDN Controller")
async def delete_main_sdn_controller(sdn_controller_id: str, request: Request):
    delete_result = await request.app.mongodb["sdncontrollers"].delete_one({"_id": sdn_controller_id})
    if delete_result.deleted_count >= 0:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)
    raise HTTPException(status_code=404, detail=f"SDN Controller not found")


"""
Clear SDN Controllers: delete all SDN Controllers from the database
"""
@router.delete("/sdncontroller", tags=["SDNController"], response_description="Delete All SDN Controllers")
async def delete_all_sdn_controllers(request: Request):
    delete_result = await request.app.mongodb["sdncontrollers"].delete_many({})
    if delete_result.deleted_count >= 0:
        return JSONResponse(status_code=status.HTTP_204_NO_CONTENT)
    raise HTTPException(status_code=404, detail=f"SDN Controllers not found")
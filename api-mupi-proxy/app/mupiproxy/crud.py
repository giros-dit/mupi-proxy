from bson.objectid import ObjectId
from fastapi import APIRouter, Body, Request, HTTPException, status

#HELPER FUNCTIONS:
#For parsing the results from a database query into a Python dict
def provider_helper(provider) -> dict:
    return {
        "id": str(provider["_id"]),
        "mcast_src_ip": provider["mcast_src_ip"],
        "upstream_if": provider["upstream_if"],
        "mcast_groups": provider["mcast_groups"],
        "description": provider["description"],
    }


def murtentry_helper(murtentry) -> dict:
    return {
        "id": str(murtentry["_id"]),
        "client_ip": murtentry["client_ip"],
        "mcast_group": murtentry["mcast_group"],
        "mcast_src_ip": murtentry["mcast_src_ip"],
        "upstream_if": murtentry["upstream_if"],
        "priority": murtentry["priority"],
    }


def sdncontroller_helper(sdncontroller) -> dict:
    return {
        "id": str(sdncontroller["_id"]),
        "openflow_version": sdncontroller["openflow_version"],
        "tcp_port": sdncontroller["tcp_port"],
        "ip_address": sdncontroller["ip_address"],
        "description": sdncontroller["description"],
    }




###############################################
#PROVIDER
###############################################

# Retrieve all Providers present in the database
async def retrieve_providers(request: Request):
    providers = []
    async for provider in request.app.mongodb["providers"].find():
        providers.append(provider_helper(provider))
    return providers


# Add a new provider into to the database
async def add_provider(request: Request, provider_data: dict) -> dict:
    provider = await request.app.mongodb["providers"].insert_one(provider_data)
    new_provider = await request.app.mongodb["providers"].find_one({"_id": provider.inserted_id})
    return provider_helper(new_provider)


# Retrieve a provider with a matching ID
async def retrieve_provider(request: Request, id: str) -> dict:
    provider = await request.app.mongodb["providers"].find_one({"_id": ObjectId(id)})
    if provider:
        return provider_helper(provider)


# Update a provider with a matching ID
async def update_provider(request: Request, id: str, data: dict):
    # Return false if an empty request body is sent.
    if len(data) < 1:
        return False
    provider = await request.app.mongodb["providers"].find_one({"_id": ObjectId(id)})
    if provider:
        updated_provider = await request.app.mongodb["providers"].update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if updated_provider:
            return True
        return False


# Delete a provider from the database
async def delete_provider(request: Request, id: str):
    provider = await request.app.mongodb["providers"].find_one({"_id": ObjectId(id)})
    if provider:
        await request.app.mongodb["providers"].delete_one({"_id": ObjectId(id)})
        return True


# Delete all providers from the database
async def delete_providers(request: Request):
    delete_result = await request.app.mongodb["providers"].delete_many({})
    if delete_result.deleted_count >= 0::
        return True
    else:
        raise HTTPException(status_code=404, detail=f"Providers not found")   




###############################################
#MURT ENTRY
###############################################

# Retrieve all MURT Entries present in the database
async def retrieve_murtentries(request: Request):
    murtentries = []
    async for entry in request.app.mongodb["murtentries"].find():
        murtentries.append(murtentry_helper(entry))
    return murtentries


# Add a new MURT Entry into to the database
async def add_murtentry(request: Request, murtentry_data: dict) -> dict:
    murtentry = await request.app.mongodb["murtentries"].insert_one(murtentry_data)
    new_murtentry = await request.app.mongodb["murtentries"].find_one({"_id": murtentry.inserted_id})
    return murtentry_helper(new_murtentry)


# Retrieve a MURT Entry with a matching ID
async def retrieve_murtentry(request: Request, id: str) -> dict:
    murtentry = await request.app.mongodb["murtentries"].find_one({"_id": ObjectId(id)})
    if murtentry:
        return murtentry_helper(murtentry)


# Update a MURT Entry with a matching ID
async def update_murtentry(request: Request, id: str, data: dict):
    # Return false if an empty request body is sent.
    if len(data) < 1:
        return False
    murtentry = await request.app.mongodb["murtentries"].find_one({"_id": ObjectId(id)})
    if murtentry:
        updated_murtentry = await request.app.mongodb["murtentries"].update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if updated_murtentry:
            return True
        return False


# Delete a MURT Entry from the database
async def delete_murtentry(request: Request, id: str):
    murtentry = await request.app.mongodb["murtentries"].find_one({"_id": ObjectId(id)})
    if murtentry:
        await request.app.mongodb["murtentries"].delete_one({"_id": ObjectId(id)})
        return True


# Delete all MURT Entries from the database
async def delete_murtentries(request: Request):
    delete_result = await request.app.mongodb["murtentries"].delete_many({})
    if delete_result.deleted_count >= 0::
        return True
    else:
        raise HTTPException(status_code=404, detail=f"MURT Entries not found")





###############################################
#SDN CONTROLLER
###############################################

# Retrieve all SDN Contollers present in the database
async def retrieve_sdncontrollers(request: Request):
    sdncontrollers = []
    async for controller in request.app.mongodb["sdncontrollers"].find():
        sdncontrollers.append(sdncontroller_helper(controller))
    return sdncontrollers


# Add a new SDN Controller into to the database
async def add_sdncontroller(request: Request, controller_data: dict) -> dict:
    sdncontroller = await request.app.mongodb["sdncontrollers"].insert_one(controller_data)
    new_sdncontroller = await request.app.mongodb["sdncontrollers"].find_one({"_id": sdncontroller.inserted_id})
    return sdncontroller_helper(new_sdncontroller)


# Retrieve a SDN Controller with a matching ID
async def retrieve_sdncontroller(request: Request, id: str) -> dict:
    sdncontroller = await request.app.mongodb["sdncontrollers"].find_one({"_id": ObjectId(id)})
    if sdncontroller:
        return sdncontroller_helper(sdncontroller)


# Update a SDN Controller with a matching ID
async def update_sdncontroller(request: Request, id: str, data: dict):
    # Return false if an empty request body is sent.
    if len(data) < 1:
        return False
    sdncontroller = await request.app.mongodb["sdncontrollers"].find_one({"_id": ObjectId(id)})
    if sdncontroller:
        updated_sdncontroller = await request.app.mongodb["sdncontrollers"].update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if updated_sdncontroller:
            return True
        return False


# Delete a SDN Controller Entry from the database
async def delete_sdncontroller(request: Request, id: str):
    sdncontroller = await request.app.mongodb["sdncontrollers"].find_one({"_id": ObjectId(id)})
    if sdncontroller:
        await request.app.mongodb["sdncontrollers"].delete_one({"_id": ObjectId(id)})
        return True


# Delete all SDN Controllers from the database
async def delete_sdncontrollers(request: Request):
    delete_result = await request.app.mongodb["sdncontrollers"].delete_many({})
    if delete_result.deleted_count >= 0::
        return True
    else:
        raise HTTPException(status_code=404, detail=f"SDN Controllers not found")   
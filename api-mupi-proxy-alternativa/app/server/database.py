import motor.motor_asyncio
from bson.objectid import ObjectId


#DATABASE CONNECTION

MONGO_DETAILS = "mongodb://localhost:27017"

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DETAILS)

database = client.mupiproxy

providers_collection = database.get_collection("providers")
murtentries_collection = database.get_collection("murtentries")
sdncontrollers_collection = database.get_collection("sdncontrollers")



#HELPER FUNCTIONS
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

#CRUD OPERATIONS


###############################################
#PROVIDER
###############################################

# Retrieve all Providers present in the database
async def retrieve_providers():
    providers = []
    async for provider in providers_collection.find():
        providers.append(provider_helper(provider))
    return providers


# Add a new provider into to the database
async def add_provider(provider_data: dict) -> dict:
    provider = await providers_collection.insert_one(provider_data)
    new_provider = await providers_collection.find_one({"_id": provider.inserted_id})
    return provider_helper(new_provider)


# Retrieve a provider with a matching ID
async def retrieve_provider(id: str) -> dict:
    provider = await providers_collection.find_one({"_id": ObjectId(id)})
    if provider:
        return provider_helper(provider)


# Update a provider with a matching ID
async def update_provider(id: str, data: dict):
    # Return false if an empty request body is sent.
    if len(data) < 1:
        return False
    provider = await providers_collection.find_one({"_id": ObjectId(id)})
    if provider:
        updated_provider = await providers_collection.update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if updated_provider:
            return True
        return False


# Delete a provider from the database
async def delete_provider(id: str):
    provider = await providers_collection.find_one({"_id": ObjectId(id)})
    if provider:
        await providers_collection.delete_one({"_id": ObjectId(id)})
        return True


# Delete all providers from the database
async def delete_providers():
    delete_result = await providers_collection.delete_many({})
    if delete_result.deleted_count >= 0:
        return True
    else:
        raise HTTPException(status_code=404, detail=f"Providers not found")   




###############################################
#MURT ENTRY
###############################################

# Retrieve all MURT Entries present in the database
async def retrieve_murtentries():
    murtentries = []
    async for entry in murtentries_collection.find():
        murtentries.append(murtentry_helper(entry))
    return murtentries


# Add a new MURT Entry into to the database
async def add_murtentry(murtentry_data: dict) -> dict:
    murtentry = await murtentries_collection.insert_one(murtentry_data)
    new_murtentry = await murtentries_collection.find_one({"_id": murtentry.inserted_id})
    return murtentry_helper(new_murtentry)


# Retrieve a MURT Entry with a matching ID
async def retrieve_murtentry(id: str) -> dict:
    murtentry = await murtentries_collection.find_one({"_id": ObjectId(id)})
    if murtentry:
        return murtentry_helper(murtentry)


# Update a MURT Entry with a matching ID
async def update_murtentry(id: str, data: dict):
    # Return false if an empty request body is sent.
    if len(data) < 1:
        return False
    murtentry = await murtentries_collection.find_one({"_id": ObjectId(id)})
    if murtentry:
        updated_murtentry = await murtentries_collection.update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if updated_murtentry:
            return True
        return False


# Delete a MURT Entry from the database
async def delete_murtentry(id: str):
    murtentry = await murtentries_collection.find_one({"_id": ObjectId(id)})
    if murtentry:
        await murtentries_collection.delete_one({"_id": ObjectId(id)})
        return True


# Delete all MURT Entries from the database
async def delete_murtentries():
    delete_result = await murtentries_collection.delete_many({})
    if delete_result.deleted_count >= 0:
        return True
    else:
        raise HTTPException(status_code=404, detail=f"MURT Entries not found")





###############################################
#SDN CONTROLLER
###############################################

# Retrieve all SDN Contollers present in the database
async def retrieve_sdncontrollers():
    sdncontrollers = []
    async for controller in sdncontrollers_collection.find():
        sdncontrollers.append(sdncontroller_helper(controller))
    return sdncontrollers


# Add a new SDN Controller into to the database
async def add_sdncontroller(controller_data: dict) -> dict:
    sdncontroller = await sdncontrollers_collection.insert_one(controller_data)
    new_sdncontroller = await sdncontrollers_collection.find_one({"_id": sdncontroller.inserted_id})
    return sdncontroller_helper(new_sdncontroller)


# Retrieve a SDN Controller with a matching ID
async def retrieve_sdncontroller(id: str) -> dict:
    sdncontroller = await sdncontrollers_collection.find_one({"_id": ObjectId(id)})
    if sdncontroller:
        return sdncontroller_helper(sdncontroller)


# Update a SDN Controller with a matching ID
async def update_sdncontroller(id: str, data: dict):
    # Return false if an empty request body is sent.
    if len(data) < 1:
        return False
    sdncontroller = await sdncontrollers_collection.find_one({"_id": ObjectId(id)})
    if sdncontroller:
        updated_sdncontroller = await sdncontrollers_collection.update_one(
            {"_id": ObjectId(id)}, {"$set": data}
        )
        if updated_sdncontroller:
            return True
        return False


# Delete a SDN Controller Entry from the database
async def delete_sdncontroller(id: str):
    sdncontroller = await sdncontrollers_collection.find_one({"_id": ObjectId(id)})
    if sdncontroller:
        await sdncontrollers_collection.delete_one({"_id": ObjectId(id)})
        return True


# Delete all SDN Controllers from the database
async def delete_sdncontrollers():
    delete_result = await sdncontrollers_collection.delete_many({})
    if delete_result.deleted_count >= 0:
        return True
    else:
        raise HTTPException(status_code=404, detail=f"SDN Controllers not found")   
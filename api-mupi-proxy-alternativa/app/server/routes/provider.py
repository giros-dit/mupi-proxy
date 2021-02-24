from fastapi import APIRouter, Body
from fastapi.encoders import jsonable_encoder

from ..database import (
    add_provider,
    delete_provider,
    delete_providers,
    retrieve_provider,
    retrieve_providers,
    update_provider,
)
from ..models.provider import (
    ErrorResponseModel,
    ResponseModel,
    Provider,
    UpdateProvider,
)

router = APIRouter()

@router.post("/", response_description="Provider data added into the database", summary="Create a provider")
async def add_provider_data(provider: Provider = Body(...)):
    """
    Create a provider with all the information:

    - **mcast_src_ip**: source ip address
    - **upstream_if**: upstream interface
    - **mcast_groups**: multicast ip address
    - **description**: Name of the provider
    """
    provider = jsonable_encoder(provider)
    new_provider = await add_provider(provider)
    return ResponseModel(new_provider, "Provider added successfully.")

@router.get("/", response_description="Providers retrieved", summary="Get all providers", description="Get all providers stored in the database",
)
async def get_providers():
    providers = await retrieve_providers()
    if providers:
        return ResponseModel(providers, "Providers data retrieved successfully")
    return ResponseModel(providers, "Empty list returned")

@router.get("/{id}", response_description="Provider data retrieved")
async def get_provider_data(id):
    provider = await retrieve_provider(id)
    if provider:
        return ResponseModel(provider, "Provider data retrieved successfully")
    return ErrorResponseModel("An error occurred.", 404, "Provider doesn't exist.")

@router.put("/{id}")
async def update_provider_data(id: str, req: UpdateProvider = Body(...)):
    req = {k: v for k, v in req.dict().items() if v is not None}
    updated_provider = await update_provider(id, req)
    if updated_provider:
        return ResponseModel(
            "Provider with ID: {} update is successful".format(id),
            "Provider updated successfully",
        )
    return ErrorResponseModel(
        "An error occurred",
        404,
        "There was an error updating the provider data.",
    )

@router.delete("/{id}", response_description="Provider data deleted from the database")
async def delete_provider_data(id: str):
    deleted_provider = await delete_provider(id)
    if deleted_provider:
        return ResponseModel(
            "Provider with ID: {} removed".format(id), "Provider deleted successfully"
        )
    return ErrorResponseModel(
        "An error occurred", 404, "Provider with id {0} doesn't exist".format(id)
    )

@router.delete("/", response_description="Providers data deleted from the database")
async def delete_providers_data():
    deleted_data = await delete_providers()
    if deleted_data:
        return ResponseModel(deleted_data, "Providers data deleted successfully")
    return ResponseModel(deleted_data, "Empty list returned")
from fastapi import APIRouter, Body
from fastapi.encoders import jsonable_encoder

from ..database import (
    add_sdncontroller,
    delete_sdncontroller,
    delete_sdncontrollers,
    retrieve_sdncontroller,
    retrieve_sdncontrollers,
    update_sdncontroller,
)
from ..models.sdncontroller import (
    ErrorResponseModel,
    ResponseModel,
    SDNController,
    UpdateSDNController,
)

router = APIRouter()

@router.post("/", response_description="SDN Controller data added into the database")
async def add_sdncontroller_data(sdncontroller: SDNController = Body(...)):
    sdncontroller = jsonable_encoder(sdncontroller)
    new_sdncontroller = await add_sdncontroller(sdncontroller)
    return ResponseModel(new_sdncontroller, "SDN Controller added successfully.")

@router.get("/", response_description="SDN Controllers retrieved")
async def get_sdncontrollers():
    sdncontrollers = await retrieve_sdncontrollers()
    if sdncontrollers:
        return ResponseModel(sdncontrollers, "SDN Controllers data retrieved successfully")
    return ResponseModel(sdncontrollers, "Empty list returned")

@router.get("/{id}", response_description="SDN Controller data retrieved")
async def get_sdncontroller_data(id):
    sdncontroller = await retrieve_sdncontroller(id)
    if sdncontroller:
        return ResponseModel(sdncontroller, "SDN Controller data retrieved successfully")
    return ErrorResponseModel("An error occurred.", 404, "SDN Controller doesn't exist.")

@router.put("/{id}")
async def update_sdncontroller_data(id: str, req: UpdateSDNController = Body(...)):
    req = {k: v for k, v in req.dict().items() if v is not None}
    updated_sdncontroller = await update_sdncontroller(id, req)
    if updated_sdncontroller:
        return ResponseModel(
            "SDN Controller with ID: {} update is successful".format(id),
            "SDN Controller updated successfully",
        )
    return ErrorResponseModel(
        "An error occurred",
        404,
        "There was an error updating the SDN Controller data.",
    )

@router.delete("/{id}", response_description="SDN Controller data deleted from the database")
async def delete_sdncontroller_data(id: str):
    deleted_sdncontroller= await delete_sdncontroller(id)
    if deleted_sdncontroller:
        return ResponseModel(
            "SDN Controller with ID: {} removed".format(id), "SDN Controller deleted successfully"
        )
    return ErrorResponseModel(
        "An error occurred", 404, "SDN Controller with id {0} doesn't exist".format(id)
    )

@router.delete("/", response_description="SDN Controllers data deleted from the database")
async def delete_sdncontrollers_data():
    deleted_data = await delete_sdncontrollers()
    if deleted_data:
        return ResponseModel(deleted_data, "SDN Controllers data deleted successfully")
    return ResponseModel(deleted_data, "Empty list returned")
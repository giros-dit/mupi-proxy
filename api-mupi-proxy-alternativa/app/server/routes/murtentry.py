from fastapi import APIRouter, Body
from fastapi.encoders import jsonable_encoder

from ..database import (
    add_murtentry,
    delete_murtentry,
    delete_murtentries,
    retrieve_murtentry,
    retrieve_murtentries,
    update_murtentry,
)
from ..models.murtentry import (
    ErrorResponseModel,
    ResponseModel,
    MurtEntry,
    UpdateMurtEntry,
)

router = APIRouter()


@router.post("/", response_description="MURT Entry data added into the database")
async def add_murtentry_data(murtentry: MurtEntry = Body(...)):
    murtentry = jsonable_encoder(murtentry)
    new_murtentry = await add_murtentry(murtentry)
    return ResponseModel(new_murtentry, "MURT Entry added successfully.")

@router.get("/", response_description="MURT Entries retrieved")
async def get_murtentries():
    murtentries = await retrieve_murtentries()
    if murtentries:
        return ResponseModel(murtentries, "MURT Entries data retrieved successfully")
    return ResponseModel(murtentries, "Empty list returned")

@router.get("/{id}", response_description="MURT Entry data retrieved")
async def get_murtentry_data(id):
    murtentry = await retrieve_murtentry(id)
    if murtentry:
        return ResponseModel(murtentry, "MURT Entry data retrieved successfully")
    return ErrorResponseModel("An error occurred.", 404, "MURT Entry doesn't exist.")

@router.put("/{id}")
async def update_murtentry_data(id: str, req: UpdateMurtEntry = Body(...)):
    req = {k: v for k, v in req.dict().items() if v is not None}
    updated_murtentry = await update_murtentry(id, req)
    if updated_murtentry:
        return ResponseModel(
            "MURT Entry with ID: {} update is successful".format(id),
            "MURT Entry updated successfully",
        )
    return ErrorResponseModel(
        "An error occurred",
        404,
        "There was an error updating the MURT Entry data.",
    )

@router.delete("/{id}", response_description="MURT Entry data deleted from the database")
async def delete_murtentry_data(id: str):
    deleted_murtentry = await delete_murtentry(id)
    if deleted_murtentry:
        return ResponseModel(
            "MURT Entry with ID: {} removed".format(id), "MURT Entry deleted successfully"
        )
    return ErrorResponseModel(
        "An error occurred", 404, "MURT Entry with id {0} doesn't exist".format(id)
    )

@router.delete("/", response_description="MURT Entries data deleted from the database")
async def delete_murtentries_data():
    deleted_data = await delete_murtentries()
    if deleted_data:
        return ResponseModel(deleted_data, "MURT Entries data deleted successfully")
    return ResponseModel(deleted_data, "Empty list returned")
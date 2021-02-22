from typing import Optional

from pydantic import BaseModel, Field


#MURT ENTRY
class MurtEntry(BaseModel):
    client_ip: str = Field(...)
    mcast_group: str = Field(...)
    mcast_src_ip: str = Field(...)
    upstream_if: str = Field(...)
    priority: int = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "client_ip": "10.100.0.70",
                "mcast_group": "224.0.122.5",
                "mcast_src_ip": "10.100.0.21",
                "upstream_if": "eth7", 
                "priority": 30,
            }
        }

class UpdateMurtEntry(BaseModel):
    client_ip: Optional[str]
    mcast_group: Optional[str]
    mcast_src_ip: Optional[str]
    upstream_if: Optional[str]
    priority: Optional[int]

    class Config:
        schema_extra = {
            "example": {
                "client_ip": "10.100.0.70",
                "mcast_group": "224.0.122.5",
                "mcast_src_ip": "10.100.0.21",
                "upstream_if": "eth7", 
                "priority": 30,
            }
        }

def ResponseModel(data, message):
    return {
        "data": [data],
        "code": 200,
        "message": message,
    }


def ErrorResponseModel(error, code, message):
    return {"error": error, "code": code, "message": message}
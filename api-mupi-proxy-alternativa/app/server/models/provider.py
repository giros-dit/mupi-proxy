from typing import Optional

from pydantic import BaseModel, Field


#PROVIDER
class Provider(BaseModel):
    mcast_src_ip: str = Field(...)
    upstream_if: str = Field(...)
    mcast_groups: list = Field(...)
    description: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "mcast_src_ip": "10.100.0.21",
                "upstream_if": "eth7", 
                "mcast_groups": ["224.0.122.5", "224.0.122.6"],
                "description": "MovistarTV",
            }
        }


class UpdateProvider(BaseModel):
    mcast_src_ip: Optional[str]
    upstream_if: Optional[str]
    mcast_groups: Optional[list]
    description: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "mcast_src_ip": "10.100.0.21",
                "upstream_if": "eth7", 
                "mcast_groups": ["224.0.122.5", "224.0.122.6"],
                "description": "MovistarTV",
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

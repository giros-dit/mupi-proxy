from typing import Optional

from pydantic import BaseModel, Field


#SDN CONTROLLER
class SDNController(BaseModel):
    openflow_version: str = Field(...)
    tcp_port: int = Field(...)
    ip_address: str = Field(...)
    description: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "openflow_version": "OpenFlow13",
                "tcp_port": "6633", 
                "ip_address": "10.200.0.2",
                "description": "Main SDN Controller",
            }
        }

class UpdateSDNController(BaseModel):
    openflow_version: Optional[str]
    tcp_port: Optional[int]
    ip_address: Optional[str]
    description: Optional[str] = None

    class Config:
        schema_extra = {
            "example": {
                "openflow_version": "OpenFlow13",
                "tcp_port": "6633", 
                "ip_address": "10.200.0.2",
                "description": "Main SDN Controller",
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
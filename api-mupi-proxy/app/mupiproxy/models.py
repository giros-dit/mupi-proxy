from typing import Optional, List
from pydantic import BaseModel, Field
from bson import ObjectId


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")

#MURT ENTRY
class MurtEntry(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    client_ip: str = Field(...)
    mcast_group: str = Field(...)
    mcast_src_ip: str = Field(...)
    upstream_if: str = Field(...)
    priority: int = Field(...)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
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
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "client_ip": "10.100.0.70",
                "mcast_group": "224.0.122.5",
                "mcast_src_ip": "10.100.0.21",
                "upstream_if": "eth7", 
                "priority": 30,
            }
        }



#PROVIDER
class Provider(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    mcast_src_ip: str = Field(...)
    upstream_if: str = Field(...)
    mcast_groups: list = Field(...)
    description: Optional[str] = None

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
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
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "mcast_src_ip": "10.100.0.21",
                "upstream_if": "eth7", 
                "mcast_groups": ["224.0.122.5", "224.0.122.6"],
                "description": "MovistarTV",
            }
        }


#SDN CONTROLLER
class SDNController(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    openflow_version: str = Field(...)
    tcp_port: int = Field(...)
    ip_address: str = Field(...)
    description: Optional[str] = None

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
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
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
        schema_extra = {
            "example": {
                "openflow_version": "OpenFlow13",
                "tcp_port": "6633", 
                "ip_address": "10.200.0.2",
                "description": "Main SDN Controller",
            }
        }

#ADDITIONAL MODELS
def ResponseModel(data, message):
    return {
        "data": [data],
        "code": 200,
        "message": message,
    }


def ErrorResponseModel(error, code, message):
    return {"error": error, "code": code, "message": message}
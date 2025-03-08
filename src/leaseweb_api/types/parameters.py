from typing import Optional
from enum import Enum
from pydantic import BaseModel

from .enums import NetworkType


class QueryParameters(BaseModel):
    limit: Optional[int] = None
    offset: Optional[int] = None


class ListDedicatedServersQueryParameters(BaseModel):
    limit: Optional[int] = None
    offset: Optional[int] = None
    reference: Optional[str] = None
    ip: Optional[str] = None
    macAddress: Optional[str] = None
    site: Optional[str] = None
    privateRackId: Optional[str] = None
    privateNetworkCapable: Optional[bool] = None
    privateNetworkEnabled: Optional[bool] = None


class ListIpsQueryParameters(BaseModel):
    networkType: Optional[NetworkType] = None
    version: Optional[str] = None
    nullRouted: Optional[str] = None
    ips: Optional[str] = None
    limit: Optional[int] = None
    offset: Optional[int] = None


class NetworkTypeParameter(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    REMOTE_MANAGEMENT = "remoteManagement"

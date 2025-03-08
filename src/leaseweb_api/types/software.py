from pydantic import BaseModel
from typing import Optional

from .enums import RackType


class Port(BaseModel):
    name: Optional[str] = None
    port: Optional[str] = None


class Rack(BaseModel):
    id: Optional[str] = None
    capacity: Optional[str] = None
    type: Optional[RackType] = None

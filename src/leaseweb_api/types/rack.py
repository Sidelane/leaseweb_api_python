from pydantic import BaseModel
from typing import Optional

from .enums import RackType


class Port(BaseModel):
    name: str
    port: str


class Rack(BaseModel):
    id: str
    capacity: Optional[str] = None
    type: RackType

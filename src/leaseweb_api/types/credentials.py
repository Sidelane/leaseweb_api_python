from typing import Optional
from pydantic import BaseModel

from .enums import CredentialType


class CredentialWithoutPassword(BaseModel):
    type: Optional[CredentialType] = None
    username: Optional[str] = None


class Credential(BaseModel):
    type: Optional[CredentialType] = None
    username: Optional[str] = None
    password: Optional[str] = None

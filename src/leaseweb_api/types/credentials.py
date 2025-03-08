from typing import Optional
from pydantic import BaseModel

from .enums import CredentialType


class CredentialWithoutPassword(BaseModel):
    type: CredentialType
    username: str


class Credential(BaseModel):
    type: CredentialType
    username: str
    password: str

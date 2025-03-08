from pydantic import BaseModel

from .enums import CredentialType


class CredentialWithoutPassword(BaseModel):
    type: CredentialType
    username: str

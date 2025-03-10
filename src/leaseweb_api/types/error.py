from pydantic import BaseModel
from typing import Optional


class APIError(BaseModel):
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    correlation_id: Optional[str] = None
    user_message: Optional[str] = None
    reference: Optional[str] = None

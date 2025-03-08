from pydantic import BaseModel


class APIError(BaseModel):
    error_code: str
    error_message: str
    correlation_id: str = None
    user_message: str = None
    reference: str = None

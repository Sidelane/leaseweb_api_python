from pydantic import BaseModel
from typing import Optional


class Action(BaseModel):
    last_triggered_at: Optional[str] = None
    type: str


class NotificationSetting(BaseModel):
    actions: Optional[list[Action]] = None
    frequency: str
    id: str
    last_checked_at: Optional[str] = None
    threshold: str
    threshold_exceeded_at: Optional[str] = None
    unit: str


class DataTrafficNotificationSetting(NotificationSetting): ...

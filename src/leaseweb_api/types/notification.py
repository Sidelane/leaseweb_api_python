from pydantic import BaseModel
from typing import Optional


class Action(BaseModel):
    last_triggered_at: Optional[str] = None
    type: Optional[str] = None


class NotificationSetting(BaseModel):
    actions: Optional[list[Action]] = None
    frequency: Optional[str] = None
    id: Optional[str] = None
    last_checked_at: Optional[str] = None
    threshold: Optional[str] = None
    threshold_exceeded_at: Optional[str] = None
    unit: Optional[str] = None


class DataTrafficNotificationSetting(NotificationSetting):
    pass

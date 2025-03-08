from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class Values(BaseModel):
    timestamp: Optional[datetime] = None
    value: Optional[float] = None


class Metric(BaseModel):
    unit: Optional[str] = None
    values: Optional[list[Values]] = None


class MetricValues(BaseModel):
    UP_PUBLIC: Optional[Metric] = None
    DOWN_PUBLIC: Optional[Metric] = None

from pydantic import BaseModel
from datetime import datetime


class Values(BaseModel):
    timestamp: datetime
    value: float


class Metric(BaseModel):
    unit: str
    values: list[Values]


class MetricValues(BaseModel):
    UP_PUBLIC: Metric
    DOWN_PUBLIC: Metric

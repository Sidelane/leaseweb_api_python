from typing import Optional
from enum import Enum
from datetime import datetime
from pydantic import BaseModel

from .enums import NetworkType
from .jobs import Os, Partition


class QueryParameters(BaseModel):
    limit: Optional[int] = None
    offset: Optional[int] = None


class ListDedicatedServersQueryParameters(BaseModel):
    limit: Optional[int] = None
    offset: Optional[int] = None
    reference: Optional[str] = None
    ip: Optional[str] = None
    macAddress: Optional[str] = None
    site: Optional[str] = None
    privateRackId: Optional[str] = None
    privateNetworkCapable: Optional[bool] = None
    privateNetworkEnabled: Optional[bool] = None


class ListIpsQueryParameters(BaseModel):
    networkType: Optional[NetworkType] = None
    version: Optional[str] = None
    nullRouted: Optional[str] = None
    ips: Optional[str] = None
    limit: Optional[int] = None
    offset: Optional[int] = None


class NetworkTypeParameter(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    REMOTE_MANAGEMENT = "remoteManagement"


class Granularity(str, Enum):
    FIVE_MIN = "5MIN"
    HOUR = "HOUR"
    DAY = "DAY"
    WEEK = "WEEK"
    MONTH = "MONTH"
    YEAR = "YEAR"


class Aggregation(str, Enum):
    AVG = "AVG"
    PERC_95 = "95TH"
    SUM = "SUM"


class ShowMetricsParameter(BaseModel):
    start: Optional[datetime] = None
    to: Optional[datetime] = None
    granularity: Optional[Granularity] = None
    aggregation: Optional[Aggregation] = None


class ListJobsParameter(BaseModel):
    type: Optional[str] = None
    status: Optional[str] = None
    isRunning: Optional[bool] = None


class Frequency(str, Enum):
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"


class Unit(str, Enum):
    MBPS = "Mbps"
    GBPS = "Gbps"


class RaidType(str, Enum):
    HW = "HW"
    SW = "SW"
    NONE = "NONE"


class Raid(BaseModel):
    level: str
    numberOfDisks: int
    type: RaidType


class Installation(BaseModel):
    callbackUrl: Optional[str] = None
    controlPanelId: Optional[str] = None
    device: Optional[str] = None
    hostname: Optional[str] = None
    operatingSystemId: str
    partitions: Optional[Partition] = None
    password: Optional[str] = None
    postInstallScript: Optional[str] = None
    powerCycle: Optional[bool] = None
    raid: Optional[Raid] = None
    sshKeys: Optional[str] = None
    timezone: Optional[str] = None

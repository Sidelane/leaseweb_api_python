from typing import Optional
from pydantic import BaseModel
from datetime import datetime


class Os(BaseModel):
    architecture: str
    family: str
    name: str
    type: str
    version: str


class Partition(BaseModel):
    filesystem: str
    mountpoint: Optional[str] = None
    size: str


class ServerJobPayload(BaseModel):
    fileserver_base_url: str
    pop: Optional[str] = None
    power_cycle: bool
    is_unassigned_server: Optional[bool] = None
    server_id: Optional[str] = None
    job_type: Optional[str] = None
    configurable: Optional[bool] = None
    device: Optional[str] = None
    number_of_disks: Optional[int] = None
    operating_system_id: Optional[str] = None
    os: Optional[Os] = None
    partitions: Optional[list[Partition]] = None
    raid_level: Optional[int] = None
    timezone: Optional[str] = None


class Progress(BaseModel):
    canceled: int
    expired: int
    failed: int
    finished: int
    inprogress: int
    pending: int
    percentage: int
    total: int
    waiting: int


class Task(BaseModel):
    description: str
    error_message: Optional[str] = None
    flow: str
    on_error: str
    status: str
    status_timestamps: str
    uuid: str


class Job(BaseModel):
    server_id: str
    created_at: datetime
    flow: str
    is_running: bool
    node: str
    payload: ServerJobPayload
    progress: Progress
    status: str
    tasks: Optional[list[Task]] = None
    type: str
    updated_at: datetime
    uuid: str

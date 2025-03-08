from typing import Optional, Any
from pydantic import BaseModel
from datetime import datetime


class Os(BaseModel):
    architecture: Optional[str] = None
    family: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    version: Optional[str] = None


class Partition(BaseModel):
    filesystem: Optional[str] = None
    mountpoint: Optional[str] = None
    size: Optional[str] = None


class ServerJobPayload(BaseModel):
    fileserver_base_url: Optional[str] = None
    pop: Optional[str] = None
    power_cycle: Optional[bool] = None
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
    canceled: Optional[int] = None
    expired: Optional[int] = None
    failed: Optional[int] = None
    finished: Optional[int] = None
    inprogress: Optional[int] = None
    pending: Optional[int] = None
    percentage: Optional[int] = None
    total: Optional[int] = None
    waiting: Optional[int] = None


class Task(BaseModel):
    description: Optional[str] = None
    error_message: Optional[str] = None
    flow: Optional[str] = None
    on_error: Optional[str] = None
    status: Optional[str] = None
    status_timestamps: Optional[dict[Any, Any]] = None
    uuid: Optional[str] = None


class Job(BaseModel):
    server_id: Optional[str] = None
    created_at: Optional[datetime] = None
    flow: Optional[str] = None
    is_running: Optional[bool] = None
    node: Optional[str] = None
    payload: Optional[ServerJobPayload] = None
    progress: Optional[Progress] = None
    status: Optional[str] = None
    tasks: Optional[list[Task]] = None
    type: Optional[str] = None
    updated_at: Optional[datetime] = None
    uuid: Optional[str] = None


class LastClientRequest(BaseModel):
    relay_agent: Optional[str] = None
    type: Optional[str] = None
    user_agent: Optional[str] = None


class Lease(BaseModel):
    bootfile: Optional[str] = None
    created_at: Optional[str] = None
    gateway: Optional[str] = None
    hostname: Optional[str] = None
    ip: Optional[str] = None
    last_client_request: Optional[LastClientRequest] = None
    mac: Optional[str] = None
    netmask: Optional[str] = None
    site: Optional[str] = None
    updated_at: Optional[str] = None

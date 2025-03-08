from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class Firmware(BaseModel):
    date: Optional[datetime] = None
    description: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None


class Motherboard(BaseModel):
    product: Optional[str] = None
    serial: Optional[str] = None
    vendor: Optional[str] = None


class Chassis(BaseModel):
    description: Optional[str] = None
    firmware: Optional[Firmware] = None
    motherboard: Optional[Motherboard] = None
    product: Optional[str] = None
    serial: Optional[str] = None
    vendor: Optional[str] = None


class Capabilities(BaseModel):
    cpufreq: Optional[str] = None
    ht: Optional[str] = None
    vmx: Optional[bool] = None
    x86_64: Optional[str] = None


class CpuSettings(BaseModel):
    cores: Optional[str] = None
    enabled_cores: Optional[str] = None
    threads: Optional[str] = None


class HardwareCpu(BaseModel):
    capabilities: Optional[list[Capabilities]] = None
    description: Optional[str] = None
    hz: Optional[str] = None

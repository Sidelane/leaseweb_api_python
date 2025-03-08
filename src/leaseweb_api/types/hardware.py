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
    serial_number: Optional[str] = None
    settings: Optional[CpuSettings] = None
    slot: Optional[str] = None
    vendor: Optional[str] = None


class Attribute(BaseModel):
    flag: Optional[str] = None
    id: Optional[str] = None
    raw_value: Optional[str] = None
    thresh: Optional[str] = None
    type: Optional[str] = None
    updated: Optional[str] = None
    value: Optional[str] = None
    when_failed: Optional[str] = None
    worst: Optional[str] = None


class Attributes(BaseModel):
    power_on_hours: Optional[Attribute] = None
    reallocated_sector_ct: Optional[Attribute] = None


class SmartSupport(BaseModel):
    available: Optional[bool] = None
    enabled: Optional[bool] = None


class Smartctl(BaseModel):
    ata_version: Optional[str] = None
    attributes: Optional[Attributes] = None
    device_model: Optional[str] = None
    execution_status: Optional[str] = None
    firmware_version: Optional[str] = None
    is_sas: Optional[bool] = None
    overall_health: Optional[str] = None
    rpm: Optional[str] = None
    sata_version: Optional[str] = None
    sector_size: Optional[str] = None
    serial_number: Optional[str] = None
    smart_error_log: Optional[str] = None
    smart_support: Optional[SmartSupport] = None
    smartctl_version: Optional[str] = None
    user_capacity: Optional[str] = None


class Disk(BaseModel):
    description: Optional[str] = None
    id: Optional[str] = None
    product: Optional[str] = None
    serial_number: Optional[str] = None
    size: Optional[str] = None
    smartctl: Optional[Smartctl] = None
    vendor: Optional[str] = None


class HardwareIpmi(BaseModel):
    defgateway: Optional[str] = None
    firmware: Optional[str] = None
    ipaddress: Optional[str] = None
    ipsource: Optional[str] = None
    macaddress: Optional[str] = None
    subnetmask: Optional[str] = None
    vendor: Optional[str] = None


class MemoryBank(BaseModel):
    description: Optional[str] = None
    id: Optional[str] = None
    clock_hz: Optional[str] = None
    serial_number: Optional[str] = None
    size_bytes: Optional[str] = None


class NetworkCapabilities(BaseModel):
    autonegotiation: Optional[str] = None
    bus_master: Optional[str] = None
    cap_list: Optional[str] = None
    ethernet: Optional[str] = None
    link_speeds: Optional[str] = None
    msi: Optional[str] = None
    msix: Optional[str] = None
    pciexpress: Optional[str] = None
    physical: Optional[str] = None
    pm: Optional[str] = None
    tp: Optional[str] = None


class LldpChassis(BaseModel):
    description: Optional[str] = None
    mac_address: Optional[str] = None
    name: Optional[str] = None


class AutoNegotiation(BaseModel):
    enabled: Optional[str] = None
    supported: Optional[str] = None


class LldpPort(BaseModel):
    auto_negotiation: Optional[AutoNegotiation] = None
    description: Optional[str] = None


class Vlan(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    label: Optional[str] = None


class Lldp(BaseModel):
    chassis: Optional[LldpChassis] = None
    port: Optional[LldpPort] = None
    vlan: Optional[Vlan] = None


class NetworkSettings(BaseModel):
    autonegotiation: Optional[str] = None
    broadcast: Optional[str] = None
    driver: Optional[str] = None
    driverversion: Optional[str] = None
    duplex: Optional[str] = None
    firmware: Optional[str] = None
    ip: Optional[str] = None
    latency: Optional[str] = None
    link: Optional[str] = None
    multicast: Optional[str] = None
    port: Optional[str] = None
    speed: Optional[str] = None


class Network(BaseModel):
    capabilities: Optional[NetworkCapabilities] = None
    lldp: Optional[Lldp] = None
    logical_name: Optional[str] = None
    mac_address: Optional[str] = None
    product: Optional[str] = None
    settings: Optional[NetworkSettings] = None
    vendor: Optional[str] = None


class Result(BaseModel):
    chassis: Optional[Chassis] = None
    cpu: Optional[list[HardwareCpu]] = None
    disks: Optional[list[Disk]] = None
    ipmi: Optional[HardwareIpmi] = None
    memory: Optional[list[MemoryBank]] = None
    network: Optional[list[Network]] = None


class HardwareInformation(BaseModel):
    id: Optional[str] = None
    parser_version: Optional[str] = None
    result: Optional[Result] = None
    scanned_at: Optional[datetime] = None
    server_id: Optional[str] = None

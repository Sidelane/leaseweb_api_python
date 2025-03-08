from pydantic import BaseModel
from datetime import datetime


class Firmware(BaseModel):
    date: datetime
    description: str
    vendor: str
    version: str


class Motherboard(BaseModel):
    product: str
    serial: str
    vendor: str


class Chassis(BaseModel):
    description: str
    firmware: Firmware
    motherboard: Motherboard
    product: str
    serial: str
    vendor: str


class Capabilities(BaseModel):
    cpufreq: str
    ht: str
    vmx: bool
    x86_64: str


class CpuSettings(BaseModel):
    cores: str
    enabled_cores: str
    threads: str


class HardwareCpu(BaseModel):
    capabilities: list[Capabilities]
    description: str
    hz: str
    serial_number: str
    settings: CpuSettings
    slot: str
    vendor: str


class Attribute(BaseModel):
    flag: str
    id: str
    raw_value: str
    thresh: str
    type: str
    updated: str
    value: str
    when_failed: str
    worst: str


class Attributes(BaseModel):
    power_on_hours: Attribute
    reallocated_sector_ct: Attribute


class SmartSupport(BaseModel):
    available: bool
    enabled: bool


class Smartctl(BaseModel):
    ata_version: str
    attributes: Attributes
    device_model: str
    execution_status: str
    firmware_version: str
    is_sas: bool
    overall_health: str
    rpm: str
    sata_version: str
    sector_size: str
    serial_number: str
    smart_error_log: str
    smart_support: SmartSupport
    smartctl_version: str
    user_capacity: str


class Disk(BaseModel):
    description: str
    id: str
    product: str
    serial_number: str
    size: str
    smartctl: Smartctl
    vendor: str


class HardwareIpmi(BaseModel):
    defgateway: str
    firmware: str
    ipaddress: str
    ipsource: str
    macaddress: str
    subnetmask: str
    vendor: str


class MemoryBank(BaseModel):
    description: str
    id: str
    clock_hz: str
    serial_number: str
    size_bytes: str


class NetworkCapabilities(BaseModel):
    autonegotiation: str
    bus_master: str
    cap_list: str
    ethernet: str
    link_speeds: str
    msi: str
    msix: str
    pciexpress: str
    physical: str
    pm: str
    tp: str


class LldpChassis(BaseModel):
    description: str
    mac_address: str
    name: str


class AutoNegotiation(BaseModel):
    enabled: str
    supported: str


class LldpPort(BaseModel):
    auto_negotiation: AutoNegotiation
    description: str


class Vlan(BaseModel):
    id: str
    name: str
    label: str


class Lldp(BaseModel):
    chassis: LldpChassis
    port: LldpPort
    vlan: Vlan


class NetworkSettings(BaseModel):
    autonegotiation: str
    broadcast: str
    driver: str
    driverversion: str
    duplex: str
    firmware: str
    ip: str
    latency: str
    link: str
    multicast: str
    port: str
    speed: str


class Network(BaseModel):
    capabilities: NetworkCapabilities
    lldp: Lldp
    logical_name: str
    mac_address: str
    product: str
    settings: NetworkSettings
    vendor: str


class Result(BaseModel):
    chassis: Chassis
    cpu: list[HardwareCpu]
    disks: list[Disk]
    ipmi: HardwareIpmi
    memory: list[MemoryBank]
    network: list[Network]


class HardwareInformation(BaseModel):
    id: str
    parser_version: str
    result: Result
    scanned_at: datetime
    server_id: str

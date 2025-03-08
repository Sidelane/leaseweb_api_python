from pydantic import BaseModel


class Partition(BaseModel):
    filesystem: str
    mountpoint: str
    size: str


class Defaults(BaseModel):
    device: str
    partitions: Partition


class OperatingSystem(BaseModel):
    architecture: str
    configurable: bool
    defaults: Defaults
    family: str
    id: str
    name: str
    type: str
    version: str
    features: list[str]
    supported_file_systems: list[str]
    supported_boot_devices: list[str]

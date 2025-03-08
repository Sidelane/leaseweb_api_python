from pydantic import BaseModel
from typing import Optional

from .network import NetworkInterfaces, PrivateNetwork
from .rack import Port, Rack
from .contract import Contract


class Location(BaseModel):
    site: str
    suite: str
    rack: str
    unit: str


class FeatureAvailability(BaseModel):
    automation: bool
    power_cycle: bool
    ipmi_reboot: bool
    private_network: bool
    remote_management: bool


class Cpu(BaseModel):
    quantity: int
    type: str


class Hdd(BaseModel):
    id: str
    amount: int
    size: int
    type: str
    unit: str
    performance_type: str = None


class PciCard(BaseModel):
    description: str


class Ram(BaseModel):
    size: int
    unit: str


class ServerSpecs(BaseModel):
    brand: str
    chassis: str
    cpu: Cpu
    hardware_raid_capable: bool
    hdd: list[Hdd]
    pci_cards: list[PciCard]
    ram: Ram


class DedicatedServer(BaseModel):
    asset_id: str
    contract: Contract
    feature_availability: FeatureAvailability
    id: str
    is_private_network_enabled: Optional[bool] = None
    is_private_network_capable: Optional[bool] = None
    is_redundant_private_network_capable: Optional[bool] = None
    location: Location
    network_interfaces: NetworkInterfaces
    power_ports: Optional[list[Port]] = None
    privateNetworks: Optional[list[PrivateNetwork]] = None
    rack: Rack
    serial_number: str
    specs: ServerSpecs


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

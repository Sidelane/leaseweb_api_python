from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from .network import NetworkInterfaces, PrivateNetwork
from .rack import Port, Rack
from .contract import Contract


class Location(BaseModel):
    site: Optional[str] = None
    suite: Optional[str] = None
    rack: Optional[str] = None
    unit: Optional[str] = None


class FeatureAvailability(BaseModel):
    automation: Optional[bool] = None
    power_cycle: Optional[bool] = None
    ipmi_reboot: Optional[bool] = None
    private_network: Optional[bool] = None
    remote_management: Optional[bool] = None


class Cpu(BaseModel):
    quantity: Optional[int] = None
    type: Optional[str] = None


class Hdd(BaseModel):
    id: Optional[str] = None
    amount: Optional[int] = None
    size: Optional[int] = None
    type: Optional[str] = None
    unit: Optional[str] = None
    performance_type: Optional[str] = None


class PciCard(BaseModel):
    description: Optional[str] = None


class Ram(BaseModel):
    size: Optional[int] = None
    unit: Optional[str] = None


class ServerSpecs(BaseModel):
    brand: Optional[str] = None
    chassis: Optional[str] = None
    cpu: Optional[Cpu] = None
    hardware_raid_capable: Optional[bool] = None
    hdd: Optional[list[Hdd]] = None
    pci_cards: Optional[list[PciCard]] = None
    ram: Optional[Ram] = None


class DedicatedServer(BaseModel):
    asset_id: Optional[str] = None
    contract: Optional[Contract] = None
    feature_availability: Optional[FeatureAvailability] = None
    id: Optional[str] = None
    is_private_network_enabled: Optional[bool] = None
    is_private_network_capable: Optional[bool] = None
    is_redundant_private_network_capable: Optional[bool] = None
    location: Optional[Location] = None
    network_interfaces: NetworkInterfaces
    power_ports: Optional[list[Port]] = None
    privateNetworks: Optional[list[PrivateNetwork]] = None
    rack: Optional[Rack] = None
    serial_number: Optional[str] = None
    specs: Optional[ServerSpecs] = None

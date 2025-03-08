from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from .enums import NetworkType, DetectionProfile, ProtectionType
from .rack import Port


class NetworkInterface(BaseModel):
    mac: Optional[str] = None
    ip: Optional[str] = None
    null_routed: Optional[bool] = None
    gateway: Optional[str] = None
    ports: Optional[list[Port]] = None
    location_id: Optional[str] = None


class NetworkInterfaces(BaseModel):
    public: NetworkInterface
    internal: NetworkInterface
    remote_management: NetworkInterface


class PrivateNetwork(BaseModel):
    id: str
    link_speed: int
    status: str
    dhcp: str
    subnet: str
    vlan_id: str


class Subnet(BaseModel):
    quantity: int
    subnet_size: str
    network_type: NetworkType


class NetworkTraffic(BaseModel):
    type: str = None
    connectivity_type: str = None
    traffic_type: str = None
    datatraffic_unit: str = None
    datatraffic_limit: int = None


class Ddos(BaseModel):
    detection_profile: DetectionProfile
    protection_type: ProtectionType


class Ip4(BaseModel):
    ddos: Optional[Ddos] = None
    floating_ip: bool
    gateway: str
    ip: str
    main_ip: bool
    network_type: NetworkType
    null_routed: Optional[bool] = None
    reverse_lookup: Optional[str] = None
    version: int


class Nullroute(BaseModel):
    automated_unnulling_at: datetime = None
    comment: str
    null_level: int
    nulled_at: datetime
    ticket_id: Optional[str] = None

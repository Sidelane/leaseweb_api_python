from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from .enums import NetworkType, DetectionProfile, ProtectionType
from .rack import Port


class OperationNetworkInterface(BaseModel):
    link_speed: Optional[str] = None
    oper_status: Optional[str] = None
    status: Optional[str] = None
    switch_interface: Optional[str] = None
    switch_name: Optional[str] = None
    type: Optional[str] = None


class NetworkInterface(BaseModel):
    mac: Optional[str] = None
    ip: Optional[str] = None
    null_routed: Optional[bool] = None
    gateway: Optional[str] = None
    ports: Optional[list[Port]] = None
    location_id: Optional[str] = None


class NetworkInterfaces(BaseModel):
    public: Optional[NetworkInterface] = None
    internal: Optional[NetworkInterface] = None
    remote_management: Optional[NetworkInterface] = None


class PrivateNetwork(BaseModel):
    id: Optional[str] = None
    link_speed: Optional[int] = None
    status: Optional[str] = None
    dhcp: Optional[str] = None
    subnet: Optional[str] = None
    vlan_id: Optional[str] = None


class Subnet(BaseModel):
    quantity: Optional[int] = None
    subnet_size: Optional[str] = None
    network_type: Optional[NetworkType] = None


class NetworkTraffic(BaseModel):
    type: Optional[str] = None
    connectivity_type: Optional[str] = None
    traffic_type: Optional[str] = None
    datatraffic_unit: Optional[str] = None
    datatraffic_limit: Optional[int] = None


class Ddos(BaseModel):
    detection_profile: Optional[DetectionProfile] = None
    protection_type: Optional[ProtectionType] = None


class Ip4(BaseModel):
    ddos: Optional[Ddos] = None
    floating_ip: Optional[bool] = None
    gateway: Optional[str] = None
    ip: Optional[str] = None
    main_ip: Optional[bool] = None
    network_type: Optional[NetworkType] = None
    null_routed: Optional[bool] = None
    reverse_lookup: Optional[str] = None
    version: Optional[int] = None


class Nullroute(BaseModel):
    automated_unnulling_at: Optional[datetime] = None
    comment: Optional[str] = None
    null_level: Optional[int] = None
    nulled_at: Optional[datetime] = None
    ticket_id: Optional[str] = None


class IPUpdate(BaseModel):
    ddos: Optional[Ddos] = None
    floating_ip: Optional[bool] = None
    gateway: Optional[str] = None
    ip: Optional[str] = None
    main_ip: Optional[bool] = None
    network_type: Optional[str] = None
    null_routed: Optional[bool] = None
    reverse_lookup: Optional[str] = None
    version: Optional[int] = None

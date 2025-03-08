from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from .network import Subnet, NetworkTraffic


class SoftwareLicense(BaseModel):
    name: Optional[str] = None
    price: Optional[int] = None
    currency: Optional[str] = None
    type: Optional[str] = None


class Contract(BaseModel):
    id: Optional[str] = None
    customer_id: Optional[str] = None
    sales_org_id: Optional[str] = None
    delivery_status: Optional[str] = None
    reference: Optional[str] = None
    private_network_port_speed: Optional[float] = None
    subnets: list[Subnet] = []
    status: Optional[str] = None
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
    sla: Optional[str] = None
    contract_term: Optional[int] = None
    contract_type: Optional[str] = None
    billing_cycle: Optional[int] = None
    billing_frequency: Optional[str] = None
    price_per_frequency: Optional[str] = None
    currency: Optional[str] = None
    network_traffic: Optional[NetworkTraffic] = None
    software_licenses: list[SoftwareLicense] = []
    managed_services: Optional[list[str]] = None
    aggregation_pack_id: Optional[str] = None
    ipv4_quantity: Optional[int] = None

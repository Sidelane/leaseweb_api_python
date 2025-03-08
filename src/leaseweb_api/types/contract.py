from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from .network import Subnet, NetworkTraffic


class SoftwareLicense(BaseModel):
    name: str
    price: Optional[int] = None
    currency: str
    type: str


class Contract(BaseModel):
    id: str
    customer_id: str
    sales_org_id: str
    delivery_status: str
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
    managed_services: list[str] = []
    aggregation_pack_id: Optional[str] = None
    ipv4_quantity: Optional[int] = None

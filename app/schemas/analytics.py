from pydantic import BaseModel, ConfigDict, Field


class ScanStatusMetric(BaseModel):
    status: str
    count: int


class AssetDistributionMetric(BaseModel):
    asset_type: str
    count: int


class PortDistributionMetric(BaseModel):
    port: int = Field(ge=1, le=65535)
    count: int = Field(ge=0)


class ServiceDistributionMetric(BaseModel):
    service_name: str = Field(min_length=1)
    count: int = Field(ge=0)


class AnalyticsOverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_scans: int
    scan_status_distribution: list[ScanStatusMetric]
    total_subdomains: int
    total_exposed_ports: int
    total_discovered_emails: int
    asset_distribution: list[AssetDistributionMetric]
    port_distribution: list[PortDistributionMetric] = Field(default_factory=list)
    service_distribution: list[ServiceDistributionMetric] = Field(default_factory=list)

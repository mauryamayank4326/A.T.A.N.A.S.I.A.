from pydantic import BaseModel, ConfigDict


class ScanStatusMetric(BaseModel):
    status: str
    count: int


class AssetDistributionMetric(BaseModel):
    asset_type: str
    count: int


class AnalyticsOverviewResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_scans: int
    scan_status_distribution: list[ScanStatusMetric]
    total_subdomains: int
    total_exposed_ports: int
    total_discovered_emails: int
    asset_distribution: list[AssetDistributionMetric]

from typing import Literal
from pydantic import BaseModel

ReportType = Literal["Daily Analysis", "Threat Assessment", "Incident Forensics", "Executive Audit"]
ReportStatus = Literal["Ready", "Processing", "Archived"]

class SecurityReport(BaseModel):
    id: str
    name: str
    type: ReportType = "Daily Analysis"
    generatedDate: str
    threats: int
    criticalCount: int
    status: ReportStatus = "Ready"
    fileSize: str
    author: str = "NetScope AI Detection Engine"
    summary: str
    highlights: list[str]

class ReportGenerateRequest(BaseModel):
    type: ReportType = "Daily Analysis"
    includePayloads: bool = False

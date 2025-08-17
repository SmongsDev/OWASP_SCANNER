"""
Data models for OWASP Static Analysis Scanner
"""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OwaspCategory(Enum):
    A03 = "A03"
    A06 = "A06"
    A07 = "A07"


@dataclass
class Vulnerability:
    id: str
    owasp_category: str
    type: str
    severity: str
    confidence: float
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    description: str
    recommendation: str
    cwe_id: str
    detection_method: str
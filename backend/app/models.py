from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class LogEvent:
    timestamp: Optional[datetime]
    ip: Optional[str]
    username: Optional[str]
    action: str
    status: str
    raw: str

from typing import Any, List, Optional

class Match:
    rule: str
    tags: List[str]
    meta: dict[str, Any]

class Rules:
    def match(self, data: Optional[bytes] = None, **kwargs: Any) -> List[Match]: ...

def compile(filepath: Optional[str] = None, source: Optional[str] = None, **kwargs: Any) -> Rules: ...

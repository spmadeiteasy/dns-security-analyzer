from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .analyzer import RECORD_TYPES, analyze_domain, reverse_lookup

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="DNS Lookup & Domain Security Analyzer", version="1.0.0",
              description="Educational DNS, email-authentication and RDAP inspection API.")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class LookupRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    include_records: bool = True
    include_email: bool = True
    include_rdap: bool = True
    record_types: list[Literal["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]] = Field(default_factory=lambda: list(RECORD_TYPES))
    dns_server: str | None = Field(default=None, max_length=45)

    @field_validator("dns_server")
    @classmethod
    def validate_dns_server(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("DNS server must be an IP address") from exc
        return value


class BatchRequest(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=20)
    include_records: bool = True
    include_email: bool = True
    include_rdap: bool = True
    record_types: list[Literal["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]] = Field(default_factory=lambda: list(RECORD_TYPES))
    dns_server: str | None = Field(default=None, max_length=45)


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "DNS Security Analyzer", "version": app.version}


@app.post("/api/lookup")
def lookup(request: LookupRequest):
    try:
        try:
            ip = ipaddress.ip_address(request.target.strip())
            return reverse_lookup(str(ip), request.dns_server)
        except ValueError:
            pass
        return analyze_domain(request.target, request.include_records, request.include_email,
                              request.include_rdap, request.record_types, request.dns_server)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Lookup failed: {type(exc).__name__}") from exc


@app.post("/api/batch")
def batch_lookup(request: BatchRequest):
    results = []
    for target in request.targets:
        try:
            try:
                ip = ipaddress.ip_address(target.strip())
                results.append(reverse_lookup(str(ip), request.dns_server))
            except ValueError:
                results.append(analyze_domain(target, request.include_records, request.include_email,
                                              request.include_rdap, request.record_types, request.dns_server))
        except ValueError as exc:
            results.append({"target": target, "error": str(exc)})
        except Exception as exc:
            results.append({"target": target, "error": f"Lookup failed: {type(exc).__name__}"})
    return {"count": len(results), "results": results}

"""Shared transaction schema (agreed with Khanak; see docs/data-contract.md)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class Transaction(BaseModel):
    transaction_id: str
    rail: str
    timestamp: datetime
    source_institution: str
    destination_institution: str
    source_token: str
    destination_token: str
    amount_bucket: str
    reference_token: str
    device_token: str | None = None
    merchant_category: str | None = None
    transaction_type: str  # P2P, P2M, WALLET_LOAD, ATM, ...

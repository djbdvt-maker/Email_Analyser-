"""
Protected Brand Dataset v1 (Curated, Versioned, Static)

Used by Domain and Links analyzers for lookalike/homoglyph/impersonation checks.
"""
from dataclasses import dataclass
from typing import Tuple, Dict

PROTECTED_BRANDS_VERSION = "protected_brands_v1"

@dataclass(frozen=True)
class ProtectedBrand:
    brand_id: str
    canonical_name: str
    protected_domains: Tuple[str, ...]
    legitimate_alternates: Tuple[str, ...]
    display_names: Tuple[str, ...]
    executives: Tuple[str, ...]

PROTECTED_BRANDS: Dict[str, ProtectedBrand] = {
    "google": ProtectedBrand(
        brand_id="google",
        canonical_name="Google",
        protected_domains=("google.com", "gmail.com", "googlemail.com", "google.co.in"),
        legitimate_alternates=("google.co.uk", "youtube.com", "google-analytics.com"),
        display_names=("Google", "Google Support", "Google Security", "Gmail Team"),
        executives=("Sundar Pichai", "Ruth Porat"),
    ),
    "microsoft": ProtectedBrand(
        brand_id="microsoft",
        canonical_name="Microsoft",
        protected_domains=("microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"),
        legitimate_alternates=("microsoftonline.com", "sharepoint.com", "azure.com"),
        display_names=("Microsoft", "Microsoft 365", "Office 365", "Microsoft Security"),
        executives=("Satya Nadella", "Amy Hood"),
    ),
    "apple": ProtectedBrand(
        brand_id="apple",
        canonical_name="Apple",
        protected_domains=("apple.com", "icloud.com"),
        legitimate_alternates=("appleid.apple.com",),
        display_names=("Apple", "Apple Support", "iCloud Security"),
        executives=("Tim Cook", "Luca Maestri"),
    ),
    "amazon": ProtectedBrand(
        brand_id="amazon",
        canonical_name="Amazon",
        protected_domains=("amazon.com", "aws.amazon.com"),
        legitimate_alternates=("amazon.co.uk", "amazon.in", "amazonaws.com"),
        display_names=("Amazon", "Amazon Support", "AWS Security"),
        executives=("Andy Jassy", "Brian Olsavsky"),
    ),
    "paypal": ProtectedBrand(
        brand_id="paypal",
        canonical_name="PayPal",
        protected_domains=("paypal.com",),
        legitimate_alternates=("paypal-communication.com",),
        display_names=("PayPal", "PayPal Service", "PayPal Security"),
        executives=("Alex Chriss",),
    ),
    "acme": ProtectedBrand(
        brand_id="acme",
        canonical_name="Acme Corporation",
        protected_domains=("acme.com", "acmecorp.com"),
        legitimate_alternates=("acme-support.com",),
        display_names=("Acme Corp", "Acme Executive Office"),
        executives=("Ken Whitfield", "Alice Smith", "John Doe"),
    ),
}
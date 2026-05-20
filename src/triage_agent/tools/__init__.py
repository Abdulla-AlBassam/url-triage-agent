"""
The tools package.

Importing this module imports every individual tool module, which causes each
one's @register_tool decorator to run, which fills the tool registry.

If you add a new tool file, add it to the imports below.
"""
from . import (
    brand_impersonation,
    dns_lookup,
    favicon_hasher,
    ioc_extractor,
    sandbox_fetch,
    tls_certificate,
    urlhaus_lookup,
    urlscan_lookup,
    virustotal_lookup,
    whois_lookup,
    write_report,
)

__all__ = [
    "brand_impersonation",
    "dns_lookup",
    "favicon_hasher",
    "ioc_extractor",
    "sandbox_fetch",
    "tls_certificate",
    "urlhaus_lookup",
    "urlscan_lookup",
    "virustotal_lookup",
    "whois_lookup",
    "write_report",
]

import shodan
from typing import Dict, Any


class ShodanClient:
    """Wrapper around Shodan API."""

    def __init__(self, api_key: str):
        self.client = shodan.Shodan(api_key)

    def scan_host(self, ip: str) -> Dict[str, Any]:
        """Fetch host information from Shodan."""
        return self.client.host(ip)

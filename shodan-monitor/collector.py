from datetime import datetime
from typing import Iterable
from psycopg2.extras import Json

from shodan_monitor.db import get_connection
from shodan_monitor.shodan_client import ShodanClient


class ShodanCollector:
    """Batch collector that queries Shodan and stores results in PostgreSQL."""

    def __init__(self, shodan_client: ShodanClient):
        self.shodan_client = shodan_client

    def run(self, targets: Iterable[str]) -> None:
        """Execute a single collection cycle."""
        conn = get_connection()
        cur = conn.cursor()
        try:
            for ip in targets:
                self._process_target(cur, ip)
            conn.commit()
        finally:
            cur.close()
            conn.close()

    def _process_target(self, cursor, ip: str) -> None:
        """Fetch Shodan data and insert into DB."""
        result = self.shodan_client.scan_host(ip)
        for item in result.get("data", []):
            port = item.get("port")
            product = item.get("product", "unknown")
            vulns = item.get("vulns", [])
            risk_score = len(vulns) + 1

            cursor.execute(
                """
                INSERT INTO scan_results (
                    ip, port, product, vulns, risk_score, timestamp
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (ip, port, product, Json(vulns), risk_score, datetime.utcnow())
            )

import time
from datetime import datetime
from psycopg2.extras import Json

from shodan_monitor.db import get_connection, init_db
from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.config import Config


class ShodanCollector:
    def __init__(self, client: ShodanClient):
        self.client = client
        init_db()

    def run(self, targets: list[str]) -> None:
        interval = Config.INTERVAL_SECONDS
        request_delay = Config.REQUEST_DELAY

        while True:
            self._run_once(targets)
            print(
                f"Batch completed at {datetime.utcnow()}. "
                f"Sleeping {interval} seconds..."
            )
            time.sleep(interval)

    def _run_once(self, targets: list[str]) -> None:
        conn = get_connection()
        cur = conn.cursor()

        for ip in targets:
            ip = ip.strip()
            if not ip:
                continue

            try:
                result = self.client.host(ip)

                for item in result.get("data", []):
                    port = item.get("port")
                    product = item.get("product", "unknown")
                    vulns = item.get("vulns", [])
                    risk_score = len(vulns) + 1

                    cur.execute(
                        """
                        INSERT INTO scan_results
                        (ip, port, product, vulns, risk_score, timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            ip,
                            port,
                            product,
                            Json(vulns),
                            risk_score,
                            datetime.utcnow(),
                        ),
                    )

                conn.commit()
                time.sleep(Config.REQUEST_DELAY)

            except Exception as e:
                print(f"Error scanning {ip}: {e}")

        cur.close()
        conn.close()



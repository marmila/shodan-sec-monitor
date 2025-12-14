import os
import time
import shodan
from datetime import datetime
from app.db import get_connection, init_db
from psycopg2.extras import Json

# Environment variables
API_KEY = os.getenv("SHODAN_API_KEY")
TARGETS = os.getenv("TARGETS", "").split(",")
INTERVAL = int(os.getenv("INTERVAL_SECONDS", 6*3600))  # default: 6 hours
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", 1.0))  # seconds between requests

# Initialize DB once
init_db()

while True:
    conn = get_connection()
    cur = conn.cursor()
    api = shodan.Shodan(API_KEY)

    for ip in TARGETS:
        ip = ip.strip()
        if not ip:
            continue
        try:
            result = api.host(ip)
            for item in result.get("data", []):
                port = item.get("port")
                product = item.get("product", "unknown")
                vulns = item.get("vulns", [])
                risk_score = len(vulns) + 1
                cur.execute("""
                    INSERT INTO scan_results (ip, port, product, vulns, risk_score, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (ip, port, product, Json(vulns), risk_score, datetime.utcnow()))
            conn.commit()
            time.sleep(REQUEST_DELAY)
        except shodan.APIError as e:
            print(f"Shodan API error for {ip}: {e}")
        except Exception as e:
            print(f"Error scanning {ip}: {e}")

    cur.close()
    conn.close()
    print(f"Batch completed at {datetime.utcnow()}. Sleeping {INTERVAL} seconds...")
    time.sleep(INTERVAL)


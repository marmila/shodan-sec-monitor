import os
import shodan
from datetime import datetime
from app.db import get_connection, init_db
from psycopg2.extras import Json

# Environment variables
API_KEY = os.getenv("SHODAN_API_KEY")
TARGETS = os.getenv("TARGETS", "").split(",")

# Initialize DB
init_db()
conn = get_connection()
cur = conn.cursor()

# Initialize Shodan
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
    except Exception as e:
        print(f"Error scanning {ip}: {e}")

cur.close()
conn.close()

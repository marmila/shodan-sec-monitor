import os
import psycopg2
from psycopg2.extras import Json

DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

def get_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id SERIAL PRIMARY KEY,
            ip VARCHAR(64),
            port INT,
            product TEXT,
            vulns JSONB,
            risk_score INT,
            timestamp TIMESTAMP
        );
    """)
    conn.commit()
    cur.close()
    conn.close()

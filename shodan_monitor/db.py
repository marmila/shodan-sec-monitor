import os
import uuid
import logging
from contextlib import contextmanager
from typing import Generator, List, Optional, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

import psycopg2
from psycopg2.extras import DictCursor, Json
from psycopg2.pool import SimpleConnectionPool

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logger = logging.getLogger("shodan.db")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")

# -------------------------------------------------------------------
# Enums and Constants
# -------------------------------------------------------------------
class ScanStatus(Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"

VALID_STATUSES = [status.value for status in ScanStatus]

# -------------------------------------------------------------------
# DB config with connection pooling
# -------------------------------------------------------------------
DB_HOST = os.getenv("DB_HOST", "shodan-postgres.shodan-monitor.svc.cluster.local")
DB_NAME = os.getenv("DB_NAME", "shodan")
DB_USER = os.getenv("DB_USER", "shodan")
DB_PASS = os.getenv("DB_PASS", "shodan")
DB_PORT = os.getenv("DB_PORT", "5432")

# Connection pool
_connection_pool = None

def init_connection_pool(minconn=1, maxconn=10):
    """Initialize connection pool"""
    global _connection_pool
    if _connection_pool is None:
        _connection_pool = SimpleConnectionPool(
            minconn=minconn,
            maxconn=maxconn,
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT,
            cursor_factory=DictCursor
        )
        logger.info(f"Initialized connection pool (min={minconn}, max={maxconn})")
    return _connection_pool

def get_connection_pool():
    """Get or initialize connection pool"""
    if _connection_pool is None:
        return init_connection_pool()
    return _connection_pool

def get_connection():
    """Get a connection from the pool"""
    pool = get_connection_pool()
    return pool.getconn()

def return_connection(conn):
    """Return connection to the pool"""
    pool = get_connection_pool()
    pool.putconn(conn)

@contextmanager
def get_cursor(autocommit=False) -> Generator:
    """Context manager for database cursor with automatic cleanup"""
    conn = get_connection()
    try:
        cur = conn.cursor()
        yield cur
        if autocommit:
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        cur.close()
        return_connection(conn)

# -------------------------------------------------------------------
# Schema initialization
# -------------------------------------------------------------------
def init_db() -> None:
    """Initialize database schema with constraints and indexes"""
    logger.info("Initializing database schema")

    with get_cursor(autocommit=True) as cur:
        # ---- scan runs with status constraint
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id UUID PRIMARY KEY,
                started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                finished_at TIMESTAMPTZ,
                status TEXT NOT NULL DEFAULT 'running',
                targets_count INTEGER,
                successful_targets INTEGER DEFAULT 0,
                failed_targets INTEGER DEFAULT 0,
                total_services INTEGER DEFAULT 0,
                CONSTRAINT valid_status CHECK (status IN ('running', 'completed', 'failed', 'timeout'))
            )
        """)

        # ---- targets
        cur.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(45) UNIQUE NOT NULL,
                first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                asn TEXT,
                org TEXT,
                country TEXT,
                total_services INTEGER DEFAULT 0,
                last_scan_run_id UUID REFERENCES scan_runs(id)
            )
        """)

        # ---- services
        cur.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id SERIAL PRIMARY KEY,
                scan_run_id UUID REFERENCES scan_runs(id) ON DELETE CASCADE,
                target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
                port INTEGER NOT NULL,
                transport TEXT DEFAULT 'tcp',
                product TEXT,
                version TEXT,
                cpe TEXT,
                vulns JSONB,
                risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
                timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)

        # ---- indexes for performance
        cur.execute("CREATE INDEX IF NOT EXISTS idx_services_target_port ON services(target_id, port)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_services_risk ON services(risk_score)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_services_vulns ON services USING gin(vulns)")

        # ---- unique constraint (NO DUPLICATES)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS uniq_services_target_port_transport
            ON services (target_id, port, transport)
        """)

        # ---- Update updated_at trigger for services
        cur.execute("""
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = now();
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        """)

        cur.execute("""
            DROP TRIGGER IF EXISTS update_services_updated_at ON services;
            CREATE TRIGGER update_services_updated_at
                BEFORE UPDATE ON services
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
        """)

    logger.info("Database schema ready")

# -------------------------------------------------------------------
# Scan Run Management
# -------------------------------------------------------------------
def create_scan_run(targets_count: Optional[int] = None) -> uuid.UUID:
    """Create a new scan run and return its ID"""
    with get_cursor(autocommit=True) as cur:
        scan_id = uuid.uuid4()
        cur.execute(
            """
            INSERT INTO scan_runs (id, targets_count, status)
            VALUES (%s, %s, %s)
            RETURNING id
            """,
            (str(scan_id), targets_count, ScanStatus.RUNNING.value)
        )
        logger.info(f"Created scan_run id={scan_id}")
        return scan_id

def update_scan_run(
    scan_id: uuid.UUID,
    status: Optional[str] = None,
    successful_targets: Optional[int] = None,
    failed_targets: Optional[int] = None,
    total_services: Optional[int] = None
) -> None:
    """Update scan run with completion status and statistics"""
    with get_cursor(autocommit=True) as cur:
        # Build dynamic update query
        updates = []
        params = []

        if status:
            if status not in VALID_STATUSES:
                raise ValueError(f"Invalid status: {status}. Must be one of {VALID_STATUSES}")
            updates.append("status = %s")
            params.append(status)

            # Auto-set finished_at for terminal states
            if status in [ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.TIMEOUT.value]:
                updates.append("finished_at = now()")

        if successful_targets is not None:
            updates.append("successful_targets = %s")
            params.append(successful_targets)

        if failed_targets is not None:
            updates.append("failed_targets = %s")
            params.append(failed_targets)

        if total_services is not None:
            updates.append("total_services = %s")
            params.append(total_services)

        if not updates:
            return  # Nothing to update

        # Add scan_id to params
        params.append(str(scan_id))

        query = f"""
            UPDATE scan_runs
            SET {', '.join(updates)}
            WHERE id = %s
        """

        cur.execute(query, params)
        logger.debug(f"Updated scan_run id={scan_id}: {updates}")

def get_scan_run(scan_id: uuid.UUID) -> Optional[Dict[str, Any]]:
    """Get scan run details"""
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT id, started_at, finished_at, status, targets_count,
                   successful_targets, failed_targets, total_services,
                   finished_at - started_at as duration
            FROM scan_runs
            WHERE id = %s
            """,
            (str(scan_id),)
        )
        result = cur.fetchone()
        return dict(result) if result else None

def cleanup_stuck_scans(timeout_minutes: int = 30) -> int:
    """Mark stuck scans as timeout and return count cleaned"""
    with get_cursor(autocommit=True) as cur:
        cur.execute(
            """
            UPDATE scan_runs
            SET status = 'timeout', finished_at = now()
            WHERE status = 'running'
            AND started_at < now() - interval '%s minutes'
            RETURNING id
            """,
            (timeout_minutes,)
        )
        stuck_scans = cur.fetchall()
        count = len(stuck_scans)
        if count > 0:
            logger.warning(f"Cleaned up {count} stuck scans: {[s['id'] for s in stuck_scans]}")
        return count

# -------------------------------------------------------------------
# Target Management
# -------------------------------------------------------------------
def upsert_target(
    scan_run_id: uuid.UUID,
    ip: str,
    asn: Optional[str] = None,
    org: Optional[str] = None,
    country: Optional[str] = None
) -> int:
    """Insert or update target, returning target_id"""
    with get_cursor(autocommit=True) as cur:
        cur.execute(
            """
            INSERT INTO targets (ip, asn, org, country, last_scan_run_id)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (ip) DO UPDATE SET
                asn = COALESCE(EXCLUDED.asn, targets.asn),
                org = COALESCE(EXCLUDED.org, targets.org),
                country = COALESCE(EXCLUDED.country, targets.country),
                last_seen = now(),
                last_scan_run_id = EXCLUDED.last_scan_run_id
            RETURNING id
            """,
            (ip, asn, org, country, str(scan_run_id))
        )
        target_id = cur.fetchone()["id"]
        logger.debug(f"Upserted target id={target_id} | ip={ip}")
        return target_id

def update_target_service_count(target_id: int) -> None:
    """Update target's total_services count"""
    with get_cursor(autocommit=True) as cur:
        cur.execute(
            """
            UPDATE targets
            SET total_services = (
                SELECT COUNT(*) FROM services WHERE target_id = %s
            )
            WHERE id = %s
            """,
            (target_id, target_id)
        )

# -------------------------------------------------------------------
# Service Management
# -------------------------------------------------------------------
def insert_service(
    scan_run_id: uuid.UUID,
    target_id: int,
    port: int,
    transport: str,
    product: Optional[str],
    version: Optional[str],
    cpe: Optional[str],
    vulns: List[str],
    risk_score: int
) -> None:
    """Insert or update service with conflict handling"""
    with get_cursor(autocommit=True) as cur:
        # Validate risk_score
        if not (0 <= risk_score <= 100):
            raise ValueError(f"Risk score must be between 0-100, got {risk_score}")

        cur.execute(
            """
            INSERT INTO services
            (scan_run_id, target_id, port, transport, product, version, cpe, vulns, risk_score)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (target_id, port, transport)
            DO UPDATE SET
                product = COALESCE(EXCLUDED.product, services.product),
                version = COALESCE(EXCLUDED.version, services.version),
                cpe = COALESCE(EXCLUDED.cpe, services.cpe),
                vulns = EXCLUDED.vulns,
                risk_score = EXCLUDED.risk_score,
                scan_run_id = EXCLUDED.scan_run_id,
                updated_at = now()
            RETURNING id
            """,
            (
                str(scan_run_id),
                target_id,
                port,
                transport,
                product,
                version,
                cpe,
                Json(vulns),
                risk_score,
            )
        )
        service_id = cur.fetchone()["id"]
        logger.debug(f"Upserted service id={service_id} for target_id={target_id} port={port}")

def batch_insert_services(services_data: List[Dict]) -> int:
    """Insert multiple services efficiently using executemany"""
    if not services_data:
        return 0

    with get_cursor(autocommit=True) as cur:
        # Prepare data for executemany
        values = []
        for svc in services_data:
            values.append((
                str(svc['scan_run_id']),
                svc['target_id'],
                svc['port'],
                svc.get('transport', 'tcp'),
                svc.get('product'),
                svc.get('version'),
                svc.get('cpe'),
                Json(svc.get('vulns', [])),
                svc['risk_score']
            ))

        cur.executemany(
            """
            INSERT INTO services
            (scan_run_id, target_id, port, transport, product, version, cpe, vulns, risk_score)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (target_id, port, transport) DO NOTHING
            """,
            values
        )
        inserted = cur.rowcount
        logger.debug(f"Batch inserted {inserted} services")
        return inserted

# -------------------------------------------------------------------
# Monitoring and Statistics
# -------------------------------------------------------------------
def get_database_stats() -> Dict[str, Any]:
    """Get database statistics for monitoring"""
    with get_cursor() as cur:
        stats = {}

        # Basic counts
        cur.execute("SELECT COUNT(*) as count FROM scan_runs")
        stats['total_scans'] = cur.fetchone()['count']

        cur.execute("SELECT COUNT(*) as count FROM targets")
        stats['total_targets'] = cur.fetchone()['count']

        cur.execute("SELECT COUNT(*) as count FROM services")
        stats['total_services'] = cur.fetchone()['count']

        # Scan status distribution
        cur.execute("""
            SELECT status, COUNT(*) as count
            FROM scan_runs
            GROUP BY status
        """)
        stats['scan_status'] = {row['status']: row['count'] for row in cur.fetchall()}

        # Recent scans
        cur.execute("""
            SELECT id, started_at, status, targets_count,
                   successful_targets, failed_targets
            FROM scan_runs
            ORDER BY started_at DESC
            LIMIT 5
        """)
        stats['recent_scans'] = [dict(row) for row in cur.fetchall()]

        # High risk services
        cur.execute("""
            SELECT COUNT(*) as count
            FROM services
            WHERE risk_score >= 70
        """)
        stats['high_risk_services'] = cur.fetchone()['count']

        return stats

def get_stuck_scans(timeout_minutes: int = 30) -> List[Dict[str, Any]]:
    """Get scans that have been running too long"""
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT id, started_at, targets_count,
                   now() - started_at as running_for
            FROM scan_runs
            WHERE status = 'running'
            AND started_at < now() - interval '%s minutes'
            ORDER BY started_at
            """,
            (timeout_minutes,)
        )
        return [dict(row) for row in cur.fetchall()]

# -------------------------------------------------------------------
# Maintenance Functions
# -------------------------------------------------------------------
def vacuum_analyze() -> None:
    """Run VACUUM ANALYZE for maintenance"""
    with get_cursor(autocommit=True) as cur:
        logger.info("Running VACUUM ANALYZE")
        cur.execute("VACUUM ANALYZE")
        logger.info("VACUUM ANALYZE completed")

def close_all_connections():
    """Close all connections in the pool (call on shutdown)"""
    global _connection_pool
    if _connection_pool:
        _connection_pool.closeall()
        _connection_pool = None
        logger.info("Closed all database connections")










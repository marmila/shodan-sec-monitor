"""
Shodan Intelligence Sentinel - Global threat hunting and exposure monitoring.
"""

__version__ = "2.0.0"
__author__ = "Marco Milano"
__description__ = "Global Shodan intelligence collector with polyglot storage"

from shodan_monitor.shodan_client import ShodanClient
from shodan_monitor.risk_scorer import RiskScorer
from shodan_monitor.db import get_pg_pool, get_mongo_collection

__all__ = ["ShodanClient", "RiskScorer", "get_pg_pool", "get_mongo_collection"]
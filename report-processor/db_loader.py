#!/usr/bin/env python3
"""Database loader utilities"""

import logging

import psycopg2

logger = logging.getLogger(__name__)


class DBLoader:
    def __init__(self, config):
        self.config = config

    def load_findings(self, findings, scan_id):
        """Load findings into database"""
        conn = psycopg2.connect(**self.config)
        try:
            cur = conn.cursor()
            for finding in findings:
                # Insert finding logic here
                pass
            conn.commit()
        finally:
            conn.close()


if __name__ == "__main__":
    logger.info("Database loader utility")

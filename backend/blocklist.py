"""TruthShield – Domain Blocklist Module
SQLite-backed community blocklist for reporting malicious domains.
"""

import sqlite3
import uuid
import re
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = "blocklist.db"

DOMAIN_REGEX = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
)

THREAT_TYPES = ["Phishing", "Job Scam", "Lottery", "Financial Fraud", "Other"]


def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS blocked_domains (
            id TEXT PRIMARY KEY,
            domain VARCHAR(255) UNIQUE NOT NULL,
            threat_type VARCHAR(50),
            report_count INTEGER DEFAULT 1,
            upvotes INTEGER DEFAULT 0,
            downvotes INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS domain_reports (
            id TEXT PRIMARY KEY,
            domain_id TEXT NOT NULL,
            user_id VARCHAR(255) DEFAULT 'anonymous',
            threat_type VARCHAR(50),
            description TEXT,
            proof_link VARCHAR(500),
            upvotes INTEGER DEFAULT 0,
            downvotes INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES blocked_domains(id)
        );

        CREATE TABLE IF NOT EXISTS user_votes (
            id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            user_id VARCHAR(255) DEFAULT 'anonymous',
            vote_type VARCHAR(10),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(report_id, user_id),
            FOREIGN KEY (report_id) REFERENCES domain_reports(id)
        );
    """)
    conn.commit()
    conn.close()


def _clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.rstrip("/").split("/")[0]
    return d


# ── Public API ─────────────────────────────────────────────────────────────────

def add_domain(
    domain: str,
    threat_type: str,
    description: str = "",
    proof_link: str = "",
    user_id: str = "anonymous",
):
    domain = _clean_domain(domain)
    if not DOMAIN_REGEX.match(domain):
        return {"success": False, "message": "Invalid domain format"}
    if threat_type not in THREAT_TYPES:
        threat_type = "Other"

    conn = _get_db()

    # Rate limit: max 5 reports per user per day
    cutoff = (datetime.utcnow() - timedelta(days=1)).isoformat()
    count = conn.execute(
        "SELECT COUNT(*) FROM domain_reports WHERE user_id=? AND created_at > ?",
        (user_id, cutoff),
    ).fetchone()[0]
    if count >= 5:
        conn.close()
        return {"success": False, "message": "Rate limit: max 5 reports per day"}

    # Check existing domain
    existing = conn.execute(
        "SELECT id, report_count FROM blocked_domains WHERE domain=?", (domain,)
    ).fetchone()

    now = datetime.utcnow().isoformat()

    if existing:
        domain_id = existing["id"]
        # Check duplicate from same user within 24h
        dup = conn.execute(
            "SELECT 1 FROM domain_reports WHERE domain_id=? AND user_id=? AND created_at > ?",
            (domain_id, user_id, cutoff),
        ).fetchone()
        if dup:
            conn.close()
            return {"success": False, "message": "You already reported this domain recently"}
        conn.execute(
            "UPDATE blocked_domains SET report_count=report_count+1, updated_at=? WHERE id=?",
            (now, domain_id),
        )
    else:
        domain_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO blocked_domains (id, domain, threat_type, created_at, updated_at) VALUES (?,?,?,?,?)",
            (domain_id, domain, threat_type, now, now),
        )

    report_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO domain_reports (id, domain_id, user_id, threat_type, description, proof_link, created_at) VALUES (?,?,?,?,?,?,?)",
        (report_id, domain_id, user_id, threat_type, description[:500], proof_link, now),
    )
    conn.commit()
    conn.close()
    return {"success": True, "domain": domain, "message": f"Domain '{domain}' reported successfully"}


def get_blocklist(
    limit: int = 20,
    offset: int = 0,
    threat_type: Optional[str] = None,
    sort: str = "recently_added",
    search: Optional[str] = None,
):
    conn = _get_db()
    where_clauses = []
    params: list = []

    if threat_type and threat_type in THREAT_TYPES:
        where_clauses.append("threat_type=?")
        params.append(threat_type)
    if search:
        where_clauses.append("domain LIKE ?")
        params.append(f"%{search.lower()}%")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    order_map = {
        "most_reported": "report_count DESC",
        "recently_added": "created_at DESC",
        "highest_rated": "(upvotes - downvotes) DESC",
    }
    order_sql = order_map.get(sort, "created_at DESC")

    total = conn.execute(f"SELECT COUNT(*) FROM blocked_domains {where_sql}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM blocked_domains {where_sql} ORDER BY {order_sql} LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    conn.close()

    return {
        "total": total,
        "domains": [dict(r) for r in rows],
    }


def get_domain_details(domain: str):
    domain = _clean_domain(domain)
    conn = _get_db()
    row = conn.execute("SELECT * FROM blocked_domains WHERE domain=?", (domain,)).fetchone()
    if not row:
        conn.close()
        return None
    reports = conn.execute(
        "SELECT * FROM domain_reports WHERE domain_id=? ORDER BY created_at DESC", (row["id"],)
    ).fetchall()
    conn.close()
    return {**dict(row), "reports": [dict(r) for r in reports]}


def upvote_domain(domain: str, user_id: str = "anonymous"):
    domain = _clean_domain(domain)
    conn = _get_db()
    row = conn.execute("SELECT id FROM blocked_domains WHERE domain=?", (domain,)).fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": "Domain not found"}
    conn.execute("UPDATE blocked_domains SET upvotes=upvotes+1 WHERE id=?", (row["id"],))
    conn.commit()
    updated = conn.execute("SELECT upvotes FROM blocked_domains WHERE id=?", (row["id"],)).fetchone()
    conn.close()
    return {"success": True, "upvotes": updated["upvotes"]}


def downvote_domain(domain: str, user_id: str = "anonymous"):
    domain = _clean_domain(domain)
    conn = _get_db()
    row = conn.execute("SELECT id FROM blocked_domains WHERE domain=?", (domain,)).fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": "Domain not found"}
    conn.execute("UPDATE blocked_domains SET downvotes=downvotes+1 WHERE id=?", (row["id"],))
    conn.commit()
    updated = conn.execute("SELECT downvotes FROM blocked_domains WHERE id=?", (row["id"],)).fetchone()
    conn.close()
    return {"success": True, "downvotes": updated["downvotes"]}


def get_stats():
    conn = _get_db()
    total_domains = conn.execute("SELECT COUNT(*) FROM blocked_domains").fetchone()[0]
    total_reports = conn.execute("SELECT COUNT(*) FROM domain_reports").fetchone()[0]

    threat_rows = conn.execute(
        "SELECT threat_type, COUNT(*) as count FROM blocked_domains GROUP BY threat_type"
    ).fetchall()
    threat_types = {r["threat_type"]: r["count"] for r in threat_rows}

    top_10 = conn.execute(
        "SELECT domain, report_count, threat_type, upvotes, downvotes FROM blocked_domains ORDER BY report_count DESC LIMIT 10"
    ).fetchall()

    # Reports over time (last 30 days)
    thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat()
    timeline = conn.execute(
        "SELECT DATE(created_at) as date, COUNT(*) as count FROM domain_reports WHERE created_at > ? GROUP BY DATE(created_at) ORDER BY date",
        (thirty_days_ago,),
    ).fetchall()

    conn.close()
    return {
        "total_domains": total_domains,
        "total_reports": total_reports,
        "threat_types": threat_types,
        "top_10": [dict(r) for r in top_10],
        "timeline": [dict(r) for r in timeline],
    }


def seed_demo_data():
    """Seed database with demo data for presentation."""
    demos = [
        ("fakejobs-india.com", "Job Scam", "Asks for ₹999 registration fee for data entry job", "https://reddit.com/r/scams/example1"),
        ("sbi-kyc-update.xyz", "Phishing", "Fake SBI KYC update page stealing credentials", "https://cybercrime.gov.in"),
        ("lottery-winner-intl.com", "Lottery", "International lottery scam demanding wire transfer fees", ""),
        ("paytm-cashback-offer.in", "Financial Fraud", "Fake Paytm cashback stealing UPI PINs", "https://twitter.com/example"),
        ("free-iphone-india.com", "Phishing", "Fake iPhone giveaway collecting personal data", ""),
        ("work-from-home-daily.com", "Job Scam", "Work from home scam with upfront payment", ""),
        ("hdfc-alert-verify.com", "Phishing", "Fake HDFC bank alert page", "https://cybercrime.gov.in"),
        ("crypto-double-btc.net", "Financial Fraud", "Bitcoin doubling scam", ""),
        ("amazon-prize-claim.xyz", "Lottery", "Fake Amazon prize claim page", ""),
        ("govt-subsidy-apply.in", "Phishing", "Fake government subsidy application", ""),
    ]
    for domain, threat, desc, proof in demos:
        add_domain(domain, threat, desc, proof, "demo_user")
    # Add extra reports to some domains
    for domain, threat, desc, proof in demos[:5]:
        for i in range(2, 5):
            add_domain(domain, threat, f"Report #{i}: {desc}", proof, f"user_{i}")


# Initialize DB on import
init_db()

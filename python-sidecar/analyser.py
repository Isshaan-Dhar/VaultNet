import os
import json
import requests
import logging
import schedule
import time
from datetime import datetime, timezone
from collections import defaultdict
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
from models.anomaly import AnomalyAlert

load_dotenv("../.env")
load_dotenv(".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("vaultnet-analyser")

DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB"),
    "user": os.getenv("POSTGRES_USER"),
    "password": os.getenv("POSTGRES_PASSWORD"),
}

ANALYSIS_WINDOW_SECONDS = 300
BRUTE_FORCE_THRESHOLD = 5
RAPID_READ_THRESHOLD = 10
OFF_HOURS_START = 22
OFF_HOURS_END = 6


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def fetch_recent_logs(conn, window_seconds: int) -> list[dict]:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT
                id, user_id, username, action, secret_name, secret_id,
                ip_address, user_agent, status, detail, occurred_at
            FROM audit_log
            WHERE occurred_at >= NOW() - INTERVAL '%s seconds'
            ORDER BY occurred_at ASC
            """,
            (window_seconds,)
        )
        return [dict(row) for row in cur.fetchall()]


def write_anomaly_to_db(conn, alert: AnomalyAlert):
    with conn.cursor() as cur:
        detail_str = json.dumps(alert.evidence)
        cur.execute(
            """
            INSERT INTO audit_log
                (user_id, username, action, ip_address, status, detail)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                alert.user_id,
                alert.username,
                "ANOMALY_DETECTED",
                "sidecar",
                alert.severity,
                f"{alert.alert_type}: {alert.detail} | evidence: {detail_str}"
            )
        )
        conn.commit()


def detect_brute_force(logs: list[dict]) -> list[AnomalyAlert]:
    alerts = []
    failure_map = defaultdict(list)

    for entry in logs:
        if entry["action"] == "LOGIN" and entry["status"] == "FAILURE":
            failure_map[entry["username"]].append(entry)

    for username, failures in failure_map.items():
        if len(failures) >= BRUTE_FORCE_THRESHOLD:
            ips = list({f["ip_address"] for f in failures})
            alerts.append(AnomalyAlert(
                alert_type="BRUTE_FORCE",
                severity="CRITICAL",
                username=username,
                user_id=None,
                detail=f"{len(failures)} failed login attempts within {ANALYSIS_WINDOW_SECONDS}s",
                evidence={
                    "failure_count": len(failures),
                    "source_ips": ips,
                    "window_seconds": ANALYSIS_WINDOW_SECONDS,
                }
            ))

    return alerts


def detect_rapid_reads(logs: list[dict]) -> list[AnomalyAlert]:
    alerts = []
    read_map = defaultdict(list)

    for entry in logs:
        if entry["action"] == "RETRIEVE" and entry["status"] == "SUCCESS":
            read_map[entry["username"]].append(entry)

    for username, reads in read_map.items():
        if len(reads) >= RAPID_READ_THRESHOLD:
            secret_names = list({r["secret_name"] for r in reads if r["secret_name"]})
            user_id = reads[0].get("user_id")
            alerts.append(AnomalyAlert(
                alert_type="RAPID_SECRET_ACCESS",
                severity="HIGH",
                username=username,
                user_id=str(user_id) if user_id else None,
                detail=f"{len(reads)} secret retrievals within {ANALYSIS_WINDOW_SECONDS}s",
                evidence={
                    "read_count": len(reads),
                    "secrets_accessed": secret_names,
                    "window_seconds": ANALYSIS_WINDOW_SECONDS,
                }
            ))

    return alerts


def detect_off_hours_access(logs: list[dict]) -> list[AnomalyAlert]:
    alerts = []
    off_hours_map = defaultdict(list)

    for entry in logs:
        if entry["action"] in ("RETRIEVE", "STORE", "ROTATE", "DELETE") and entry["status"] == "SUCCESS":
            occurred_at = entry["occurred_at"]
            if isinstance(occurred_at, datetime):
                hour = occurred_at.hour
            else:
                hour = datetime.fromisoformat(str(occurred_at)).hour

            is_off_hours = (hour >= OFF_HOURS_START) or (hour < OFF_HOURS_END)
            if is_off_hours:
                off_hours_map[entry["username"]].append(entry)

    for username, entries in off_hours_map.items():
        user_id = entries[0].get("user_id")
        hours = [
            (e["occurred_at"].hour if isinstance(e["occurred_at"], datetime)
             else datetime.fromisoformat(str(e["occurred_at"])).hour)
            for e in entries
        ]
        alerts.append(AnomalyAlert(
            alert_type="OFF_HOURS_ACCESS",
            severity="MEDIUM",
            username=username,
            user_id=str(user_id) if user_id else None,
            detail=f"{len(entries)} secret operations outside business hours",
            evidence={
                "operation_count": len(entries),
                "hours_observed": list(set(hours)),
                "off_hours_definition": f"{OFF_HOURS_START}:00 to 0{OFF_HOURS_END}:00 UTC",
            }
        ))

    return alerts


def detect_ip_anomaly(logs: list[dict]) -> list[AnomalyAlert]:
    alerts = []
    user_ips = defaultdict(set)
    user_id_map = {}

    for entry in logs:
        if entry["status"] == "SUCCESS" and entry["ip_address"]:
            user_ips[entry["username"]].add(entry["ip_address"])
            if entry["user_id"]:
                user_id_map[entry["username"]] = str(entry["user_id"])

    for username, ips in user_ips.items():
        if len(ips) >= 3:
            alerts.append(AnomalyAlert(
                alert_type="MULTIPLE_SOURCE_IPS",
                severity="MEDIUM",
                username=username,
                user_id=user_id_map.get(username),
                detail=f"Activity from {len(ips)} distinct IP addresses in {ANALYSIS_WINDOW_SECONDS}s",
                evidence={
                    "ip_count": len(ips),
                    "source_ips": list(ips),
                    "window_seconds": ANALYSIS_WINDOW_SECONDS,
                }
            ))

    return alerts


def notify_go_service(alert: AnomalyAlert) -> None:
    try:
        requests.post(
            "http://go-service:8080/internal/anomaly",
            json={"anomaly_type": alert.alert_type, "severity": alert.severity},
            timeout=2,
        )
    except requests.RequestException:
        pass


def run_analysis():
    log.info("Running audit log analysis cycle")
    try:
        conn = get_connection()
        logs = fetch_recent_logs(conn, ANALYSIS_WINDOW_SECONDS)

        if not logs:
            log.info("No audit log entries in analysis window")
            conn.close()
            return

        log.info(f"Analysing {len(logs)} audit log entries")

        all_alerts = []
        all_alerts.extend(detect_brute_force(logs))
        all_alerts.extend(detect_rapid_reads(logs))
        all_alerts.extend(detect_off_hours_access(logs))
        all_alerts.extend(detect_ip_anomaly(logs))

        if not all_alerts:
            log.info("No anomalies detected")
        else:
            for alert in all_alerts:
                log.warning(f"ANOMALY [{alert.severity}] {alert.alert_type} — user: {alert.username}")
                print(alert.to_json())
                write_anomaly_to_db(conn, alert)
                notify_go_service(alert)


        conn.close()

    except Exception as e:
        log.error(f"Analysis cycle failed: {e}")


def main():
    log.info("VaultNet audit log analyser starting")
    log.info(f"Analysis window: {ANALYSIS_WINDOW_SECONDS}s | Interval: 60s")

    run_analysis()

    schedule.every(60).seconds.do(run_analysis)

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()
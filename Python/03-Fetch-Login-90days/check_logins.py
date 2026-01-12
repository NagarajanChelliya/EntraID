import csv
import datetime as dt
import time
from typing import Dict, List, Tuple

import boto3


# =========================
# HARD-CODED CONFIG
# =========================
AWS_REGION = "us-east-1"
LOG_GROUP_NAME = "aws-controltower/CloudTrailLogs"
INPUT_CSV = "identitystore_users.csv"
OUTPUT_CSV = "user_login_90days_report.csv"
LOOKBACK_DAYS = 90
# =========================


def read_users(csv_path: str) -> List[dict]:
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {"UserId", "UserName", "Email"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV missing columns: {sorted(missing)}. Found: {reader.fieldnames}")

        users = []
        for row in reader:
            users.append({
                "UserId": (row.get("UserId") or "").strip(),
                "UserName": (row.get("UserName") or "").strip(),
                "Email": (row.get("Email") or "").strip(),
            })
        return users


def norm(value: str) -> str:
    return (value or "").strip().lower()


def to_epoch_seconds(d: dt.datetime) -> int:
    return int(d.astimezone(dt.timezone.utc).timestamp())


def run_logs_insights_query(logs_client, log_group: str, start_time: int, end_time: int, query: str):
    resp = logs_client.start_query(
        logGroupName=log_group,
        startTime=start_time,
        endTime=end_time,
        queryString=query,
    )
    query_id = resp["queryId"]

    while True:
        res = logs_client.get_query_results(queryId=query_id)
        status = res["status"]
        if status == "Complete":
            return res["results"]
        if status in ("Failed", "Cancelled", "Timeout"):
            raise RuntimeError(f"Logs Insights query ended with status: {status}")
        time.sleep(1.5)


def results_to_dicts(results):
    rows = []
    for r in results:
        rows.append({item["field"]: item.get("value", "") for item in r})
    return rows


def main():
    users = read_users(INPUT_CSV)

    # CloudWatch client
    logs = boto3.client("logs", region_name=AWS_REGION)

    end_time = dt.datetime.now(dt.timezone.utc)
    start_time = end_time - dt.timedelta(days=LOOKBACK_DAYS)

    # ✅ Query without values()
    # - Find successful console logins
    # - Extract identity signals
    # - Aggregate with supported functions:
    #     latest(@timestamp), latest(recipientAccountId), count_distinct(recipientAccountId)
    query = r"""
fields @timestamp, @message
| filter @message like /"eventSource":"signin\.amazonaws\.com"/
| filter @message like /"eventName":"ConsoleLogin"/
| filter @message like /"ConsoleLogin":"Success"/
| parse @message /"recipientAccountId":"(?<recipientAccountId>[^"]+)"/
| parse @message /"principalId":"(?<principalId>[^"]+)"/
| parse @message /"userName":"(?<userName>[^"]+)"/
| parse @message /"arn":"(?<arn>[^"]+)"/
| parse arn /assumed-role\/[^\/]+\/(?<sessionName>.+)$/ 
| stats
    latest(@timestamp) as lastLogin,
    latest(recipientAccountId) as anyAccount,
    count_distinct(recipientAccountId) as accountCount
  by userName, principalId, arn, sessionName
| sort lastLogin desc
"""

    results = run_logs_insights_query(
        logs_client=logs,
        log_group=LOG_GROUP_NAME,
        start_time=to_epoch_seconds(start_time),
        end_time=to_epoch_seconds(end_time),
        query=query,
    )

    rows = results_to_dicts(results)

    # Build lookup: identity_string -> (lastLogin, anyAccount, accountCount)
    last_seen: Dict[str, Tuple[str, str, str]] = {}

    for r in rows:
        last_login = r.get("lastLogin", "")
        any_account = r.get("anyAccount", "")
        account_count = r.get("accountCount", "")

        identities = [
            r.get("userName", ""),
            r.get("principalId", ""),
            r.get("arn", ""),
            r.get("sessionName", ""),
        ]

        for ident in identities:
            k = norm(ident)
            if not k:
                continue
            if k not in last_seen or last_login > last_seen[k][0]:
                last_seen[k] = (last_login, any_account, account_count)

    # Now match CSV users against logs
    output_rows = []
    for u in users:
        keys_to_try = []
        if u["UserName"]:
            keys_to_try.append(norm(u["UserName"]))
        if u["Email"]:
            keys_to_try.append(norm(u["Email"]))

        best_login = ""
        best_account = ""
        best_account_count = ""
        matched_on = ""

        for k in keys_to_try:
            if k in last_seen:
                last_login, any_acc, acc_count = last_seen[k]
                if last_login > best_login:
                    best_login = last_login
                    best_account = any_acc
                    best_account_count = acc_count
                    matched_on = k

        output_rows.append({
            "UserId": u["UserId"],
            "UserName": u["UserName"],
            "Email": u["Email"],
            f"LoggedInLast{LOOKBACK_DAYS}Days": "YES" if best_login else "NO",
            "LastLoginUtc": best_login,
            "AnyAccountSeenIn": best_account,
            "AccountCountSeenIn": best_account_count,
            "MatchedOn": matched_on,
        })

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=output_rows[0].keys())
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"✅ Report generated: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

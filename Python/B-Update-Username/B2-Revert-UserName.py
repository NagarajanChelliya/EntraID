#!/usr/bin/env python3
"""
Update AWS IAM Identity Center (Identity Store) userName using values from an input CSV.

- Uses UserId from CSV as the primary key.
- Sets userName to the value in the CSV "UserName" column.
- Writes a new CSV with an added column: Result
    - "Success" on success
    - Otherwise the actual AWS error (code + message)

Hardcoded:
- AWS profile, region
- Input CSV path (your attached file path in this environment)
- Output CSV path
"""

import csv
import time
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# =========================
# HARDCODED CONFIG
# =========================
AWS_PROFILE = "Nagarajan"
AWS_REGION = "us-east-1"

INPUT_CSV = r"A1-Fetch-All-Users-Respective-Groups.csv"
OUTPUT_CSV = r"B2-Username-Revereted_OUT.csv"

# Reduce throttling risk (set to 0 to disable)
SLEEP_SECONDS_BETWEEN_UPDATES = 0.05
# =========================


def get_identity_store_id(session: boto3.Session) -> str:
    """Discover IdentityStoreId from IAM Identity Center instance."""
    sso_admin = session.client("sso-admin", region_name=AWS_REGION)
    resp = sso_admin.list_instances()
    instances = resp.get("Instances", [])
    if not instances:
        raise RuntimeError("No IAM Identity Center instance found in this account/region.")
    return instances[0]["IdentityStoreId"]


def find_column(fieldnames, candidates):
    """
    Return the first matching column name from fieldnames (case-insensitive),
    checking multiple candidate names.
    """
    if not fieldnames:
        return None
    lower_map = {c.lower(): c for c in fieldnames}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    return None


def aws_error_to_string(e: Exception) -> str:
    """Convert botocore exceptions to a useful single-line message."""
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "ClientError")
        msg = e.response.get("Error", {}).get("Message", str(e))
        return f"{code}: {msg}"
    return str(e)


def update_username(identitystore, identity_store_id: str, user_id: str, new_username: str) -> None:
    """Update Identity Store userName using UpdateUser operations."""
    identitystore.update_user(
        IdentityStoreId=identity_store_id,
        UserId=user_id,
        Operations=[{"AttributePath": "userName", "AttributeValue": new_username}],
    )


def main():
    session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
    identitystore = session.client("identitystore", region_name=AWS_REGION)
    identity_store_id = get_identity_store_id(session)

    print(f"IdentityStoreId: {identity_store_id}")
    print(f"Input:  {INPUT_CSV}")
    print(f"Output: {OUTPUT_CSV}")

    # Read all rows first
    with open(INPUT_CSV, "r", newline="", encoding="utf-8-sig") as fin:
        reader = csv.DictReader(fin)
        if not reader.fieldnames:
            raise RuntimeError("Input CSV has no header row / no columns detected.")

        # Detect required columns (case-insensitive)
        user_id_col = find_column(reader.fieldnames, ["UserId", "userid", "user_id", "User ID"])
        username_col = find_column(reader.fieldnames, ["UserName", "username", "user_name", "User Name"])

        if not user_id_col:
            raise RuntimeError(
                f"Could not find a UserId column. Found columns: {reader.fieldnames}. "
                f"Expected: UserId / userid / user_id"
            )
        if not username_col:
            raise RuntimeError(
                f"Could not find a UserName column. Found columns: {reader.fieldnames}. "
                f"Expected: UserName / username / user_name"
            )

        rows = list(reader)
        out_fieldnames = list(reader.fieldnames)
        if "Result" not in out_fieldnames:
            out_fieldnames.append("Result")

    success = 0
    failed = 0

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=out_fieldnames)
        writer.writeheader()

        for idx, row in enumerate(rows, start=1):
            user_id = (row.get(user_id_col) or "").strip()
            new_username = (row.get(username_col) or "").strip()

            if not user_id:
                row["Result"] = "ERROR: Missing UserId"
                failed += 1
                writer.writerow(row)
                continue

            if not new_username:
                row["Result"] = "ERROR: Missing UserName"
                failed += 1
                writer.writerow(row)
                continue

            try:
                update_username(identitystore, identity_store_id, user_id, new_username)
                row["Result"] = "Success"
                success += 1
            except (ClientError, BotoCoreError) as e:
                row["Result"] = aws_error_to_string(e)
                failed += 1
            except Exception as e:
                row["Result"] = f"UnexpectedError: {e}"
                failed += 1

            writer.writerow(row)

            if SLEEP_SECONDS_BETWEEN_UPDATES:
                time.sleep(SLEEP_SECONDS_BETWEEN_UPDATES)

            if idx % 100 == 0:
                print(f"Processed {idx}/{len(rows)} rows... (success={success}, failed={failed})")

    print(f"DONE. success={success}, failed={failed}")
    print(f"Output written to: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

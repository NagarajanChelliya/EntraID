import boto3
import csv
import sys
from botocore.exceptions import BotoCoreError, ClientError

# =========================
# HARDCODED CONFIG
# =========================
AWS_PROFILE = "Nagarajan"
AWS_REGION = "us-east-1"
OUT_CSV = "backup_users.csv"
# =========================


def get_identity_store_id(session):
    sso_admin = session.client("sso-admin", region_name=AWS_REGION)
    resp = sso_admin.list_instances()
    instances = resp.get("Instances", [])

    if not instances:
        raise RuntimeError("No IAM Identity Center instance found")

    return instances[0]["IdentityStoreId"]


def pick_work_email(emails):
    if not emails:
        return ""

    primary = [e for e in emails if e.get("Primary") is True and e.get("Value")]
    if primary:
        return primary[0]["Value"]

    work = [e for e in emails if str(e.get("Type", "")).lower() == "work" and e.get("Value")]
    if work:
        return work[0]["Value"]

    return emails[0].get("Value", "")


def export_users():
    session = boto3.Session(
        profile_name=AWS_PROFILE,
        region_name=AWS_REGION
    )

    identity_store_id = get_identity_store_id(session)
    identitystore = session.client("identitystore", region_name=AWS_REGION)

    print(f"IdentityStoreId: {identity_store_id}")
    print(f"Writing output to: {OUT_CSV}")

    fieldnames = [
        "UserId",
        "UserName",
        "DisplayName",
        "Email",
        "FirstName",
        "LastName",
        "Status"
    ]

    try:
        with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            paginator = identitystore.get_paginator("list_users")
            total = 0

            for page in paginator.paginate(IdentityStoreId=identity_store_id):
                for u in page.get("Users", []):
                    user_id = u["UserId"]

                    detail = identitystore.describe_user(
                        IdentityStoreId=identity_store_id,
                        UserId=user_id
                    )

                    status = "ACTIVE" if detail.get("Active", True) else "DISABLED"

                    row = {
                        "UserId": detail.get("UserId", ""),
                        "UserName": detail.get("UserName", ""),
                        "DisplayName": detail.get("DisplayName", ""),
                        "Email": pick_work_email(detail.get("Emails", [])),
                        "FirstName": detail.get("Name", {}).get("GivenName", ""),
                        "LastName": detail.get("Name", {}).get("FamilyName", ""),
                        "Status": status
                    }

                    writer.writerow(row)
                    total += 1

            print(f"Done. Exported {total} users.")

    except (BotoCoreError, ClientError) as e:
        print("AWS error:", e)
        sys.exit(1)
    except OSError as e:
        print("File error:", e)
        sys.exit(1)


if __name__ == "__main__":
    export_users()

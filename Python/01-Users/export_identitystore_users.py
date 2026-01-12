import boto3
import csv
from botocore.exceptions import ClientError

# =========================
# HARD-CODED CONFIG
# =========================
REGION = "us-east-1"                   # Change if needed
OUTPUT_CSV = "identitystore_users.csv" # Output file name
AWS_PROFILE = "Nagarajan"                     # e.g. "Nagarajan" or None to use default
# =========================


def get_identity_store_id(session: boto3.Session) -> str:
    """
    Dynamically fetch IdentityStoreId from IAM Identity Center (SSO Admin).
    """
    sso_admin = session.client("sso-admin", region_name=REGION)

    instances = []
    token = None

    while True:
        kwargs = {"MaxResults": 50}
        if token:
            kwargs["NextToken"] = token

        resp = sso_admin.list_instances(**kwargs)
        instances.extend(resp.get("Instances", []))
        token = resp.get("NextToken")

        if not token:
            break

    if not instances:
        raise RuntimeError(
            f"No IAM Identity Center instances found in region {REGION}"
        )

    if len(instances) > 1:
        print("⚠ Multiple Identity Center instances found, using the first one.")

    return instances[0]["IdentityStoreId"]


def extract_email(user: dict) -> str:
    """
    Extract primary email if present, otherwise first available email.
    """
    emails = user.get("Emails") or []

    for e in emails:
        if e.get("Primary") and e.get("Value"):
            return e["Value"]

    for e in emails:
        if e.get("Value"):
            return e["Value"]

    return ""


def list_identity_store_users(session: boto3.Session, identity_store_id: str):
    """
    Yield UserId, UserName, Email for all users.
    """
    identitystore = session.client("identitystore", region_name=REGION)
    token = None

    while True:
        kwargs = {
            "IdentityStoreId": identity_store_id,
            "MaxResults": 50
        }
        if token:
            kwargs["NextToken"] = token

        resp = identitystore.list_users(**kwargs)

        for u in resp.get("Users", []):
            yield {
                "UserId": u.get("UserId", ""),
                "UserName": u.get("UserName", ""),
                "Email": extract_email(u)
            }

        token = resp.get("NextToken")
        if not token:
            break


def main():
    session = (
        boto3.Session(profile_name=AWS_PROFILE)
        if AWS_PROFILE
        else boto3.Session()
    )

    try:
        identity_store_id = get_identity_store_id(session)
        print(f"✅ IdentityStoreId: {identity_store_id}")

        users = list(list_identity_store_users(session, identity_store_id))
        print(f"👤 Users fetched: {len(users)}")

        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["UserId", "UserName", "Email"]
            )
            writer.writeheader()
            writer.writerows(users)

        print(f"📁 CSV exported successfully → {OUTPUT_CSV}")

    except ClientError as e:
        print(f"❌ AWS error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()

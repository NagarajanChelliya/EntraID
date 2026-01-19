import csv
import os
import sys
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# =========================
# HARDCODED CONFIG
# =========================
AWS_PROFILE = "Nagarajan"  # <-- change
AWS_REGION = "us-east-1"   # <-- change
OUTPUT_CSV = r"IAMIdentityCenter-output_groups.csv"  # <-- change
# =========================


def ensure_output_dir(path: str) -> None:
    out_dir = os.path.dirname(path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)


def get_identity_store_id(sso_admin_client) -> str:
    """
    Finds the IdentityStoreId by listing IAM Identity Center instances.
    Most orgs have exactly one instance.
    """
    resp = sso_admin_client.list_instances()
    instances = resp.get("Instances", [])
    if not instances:
        raise RuntimeError("No IAM Identity Center instances found in this region/profile.")
    # If multiple exist, pick the first.
    return instances[0]["IdentityStoreId"]


def list_all_groups(identitystore_client, identity_store_id: str) -> list[dict]:
    """
    Paginates through all groups in the Identity Store.
    """
    groups: list[dict] = []
    next_token = None

    while True:
        kwargs = {"IdentityStoreId": identity_store_id, "MaxResults": 50}
        if next_token:
            kwargs["NextToken"] = next_token

        resp = identitystore_client.list_groups(**kwargs)
        groups.extend(resp.get("Groups", []))

        next_token = resp.get("NextToken")
        if not next_token:
            break

    return groups


def main() -> int:
    try:
        session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)

        sso_admin = session.client("sso-admin")
        identitystore = session.client("identitystore")

        identity_store_id = get_identity_store_id(sso_admin)
        print(f"IdentityStoreId: {identity_store_id}")

        groups = list_all_groups(identitystore, identity_store_id)
        print(f"Total groups found: {len(groups)}")

        ensure_output_dir(OUTPUT_CSV)

        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Common fields available from list_groups: GroupId, DisplayName
            writer.writerow(["GroupId", "DisplayName"])
            for g in groups:
                writer.writerow([g.get("GroupId", ""), g.get("DisplayName", "")])

        print(f"✅ Export complete: {OUTPUT_CSV}")
        return 0

    except (ClientError, BotoCoreError) as e:
        print(f"❌ AWS error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

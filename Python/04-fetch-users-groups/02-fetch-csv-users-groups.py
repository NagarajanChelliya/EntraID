import boto3
import csv
from botocore.config import Config

INPUT_CSV = "identitystore_users.csv"
OUTPUT_CSV = "02-fetch-csv-users-groups.csv"

def get_identity_store_id(region: str, profile: str | None = None) -> str:
    session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    sso_admin = session.client("sso-admin")
    resp = sso_admin.list_instances()
    instances = resp.get("Instances", [])
    if not instances:
        raise RuntimeError("No IAM Identity Center (SSO) instance found in this account/region.")
    return instances[0]["IdentityStoreId"]

def get_group_name(identitystore, identity_store_id: str, group_id: str, cache: dict) -> str:
    if group_id in cache:
        return cache[group_id]
    g = identitystore.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    name = g.get("DisplayName", group_id)
    cache[group_id] = name
    return name

def list_user_groups(identitystore, identity_store_id: str, user_id: str, group_cache: dict) -> list[str]:
    groups = []
    paginator = identitystore.get_paginator("list_group_memberships_for_member")
    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        MemberId={"UserId": user_id}
    ):
        for gm in page.get("GroupMemberships", []):
            gid = gm["GroupId"]
            groups.append(get_group_name(identitystore, identity_store_id, gid, group_cache))
    return groups

def main(region="eu-west-1", profile=None, input_csv=INPUT_CSV, output_csv=OUTPUT_CSV):
    cfg = Config(retries={"max_attempts": 10, "mode": "standard"})
    session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)

    identitystore = session.client("identitystore", config=cfg)
    identity_store_id = get_identity_store_id(region, profile)

    group_cache: dict[str, str] = {}

    with open(input_csv, "r", encoding="utf-8-sig", newline="") as f_in, \
         open(output_csv, "w", encoding="utf-8", newline="") as f_out:

        reader = csv.DictReader(f_in)
        required = {"UserId", "UserName", "Email"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise RuntimeError(f"Input CSV missing columns: {', '.join(sorted(missing))}")

        writer = csv.writer(f_out)
        writer.writerow(["UserId", "UserName", "Email", "Groups"])

        for row in reader:
            user_id = (row.get("UserId") or "").strip()
            user_name = (row.get("UserName") or "").strip()
            email = (row.get("Email") or "").strip()

            if not user_id:
                # If you ever have rows without UserId, you can implement lookup here.
                # But best practice: keep UserId in the input CSV.
                writer.writerow([user_id, user_name, email, "ERROR: Missing UserId"])
                continue

            try:
                groups = list_user_groups(identitystore, identity_store_id, user_id, group_cache)
                writer.writerow([user_id, user_name, email, "|".join(groups)])
            except Exception as e:
                writer.writerow([user_id, user_name, email, f"ERROR: {e}"])

    print(f"Exported: {output_csv}")

if __name__ == "__main__":
    # Examples:
    main(region="us-east-1", profile="Nagarajan")
    #main(region="eu-west-1", profile=None)

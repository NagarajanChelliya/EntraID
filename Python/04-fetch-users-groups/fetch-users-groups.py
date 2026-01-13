import boto3
import csv
from botocore.config import Config

def get_identity_store_id(sso_admin):
    resp = sso_admin.list_instances()
    instances = resp.get("Instances", [])
    if not instances:
        raise RuntimeError("No IAM Identity Center instance found.")
    return instances[0]["IdentityStoreId"]

def list_all_users(identitystore, identity_store_id):
    users = []
    paginator = identitystore.get_paginator("list_users")
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        users.extend(page.get("Users", []))
    return users

def get_user_groups(identitystore, identity_store_id, user_id, group_cache):
    groups = []
    paginator = identitystore.get_paginator("list_group_memberships_for_member")

    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        MemberId={"UserId": user_id}
    ):
        for gm in page.get("GroupMemberships", []):
            group_id = gm["GroupId"]

            if group_id not in group_cache:
                g = identitystore.describe_group(
                    IdentityStoreId=identity_store_id,
                    GroupId=group_id
                )
                group_cache[group_id] = g.get("DisplayName", group_id)

            groups.append(group_cache[group_id])

    return groups

def main(region="us-east-1", profile="Nagarajan", out_csv="iam_identity_center_users.csv"):
    cfg = Config(retries={"max_attempts": 10, "mode": "standard"})
    session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)

    sso_admin = session.client("sso-admin", config=cfg)
    identitystore = session.client("identitystore", config=cfg)

    identity_store_id = get_identity_store_id(sso_admin)
    users = list_all_users(identitystore, identity_store_id)

    group_cache = {}

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["UserId", "UserName", "DisplayName", "Groups"])

        for u in users:
            user_id = u["UserId"]
            user_name = u.get("UserName", "")
            display_name = (u.get("Name") or {}).get("Formatted", "")

            groups = get_user_groups(identitystore, identity_store_id, user_id, group_cache)

            writer.writerow([
                user_id,
                user_name,
                display_name,
                "|".join(groups)
            ])

    print(f"CSV exported: {out_csv}")

if __name__ == "__main__":
    # Examples:
    # main(profile="Nagarajan")
    main()

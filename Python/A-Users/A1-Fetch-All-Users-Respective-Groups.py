#!/usr/bin/env python3
"""
Export AWS IAM Identity Center (Identity Store) users + their group memberships.

Output columns:
- UserId, UserName, EmailId, FirstName, LastName, DisplayName, Groups

Groups are joined with the '|' symbol.

Requires:
- boto3
- AWS CLI profile configured (SSO or access keys)
"""

import csv
import sys
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# =========================
# HARDCODED CONFIG
# =========================
AWS_PROFILE = "Nagarajan"
AWS_REGION = "us-east-1"
OUT_CSV = "A1-Fetch-All-Users-Respective-Groups.csv"
GROUP_SEPARATOR = "|"
# =========================


def get_identity_store_id(session: boto3.Session) -> str:
    """Discover IdentityStoreId via sso-admin list_instances."""
    sso_admin = session.client("sso-admin", region_name=AWS_REGION)
    resp = sso_admin.list_instances()
    instances = resp.get("Instances", [])
    if not instances:
        raise RuntimeError("No IAM Identity Center instance found (sso-admin list_instances returned none).")
    return instances[0]["IdentityStoreId"]


def pick_email(user_obj: dict) -> str:
    """Pick best email from the IdentityStore user object."""
    emails = user_obj.get("Emails") or []
    if not emails:
        return ""

    # Prefer Primary
    for e in emails:
        if e.get("Primary") is True and e.get("Value"):
            return e["Value"]

    # Prefer work
    for e in emails:
        if str(e.get("Type", "")).lower() == "work" and e.get("Value"):
            return e["Value"]

    # Fallback to first
    return emails[0].get("Value", "")


def list_user_group_ids(identitystore, identity_store_id: str, user_id: str) -> list[str]:
    """Return list of GroupIds for a given user (member)."""
    group_ids: list[str] = []
    paginator = identitystore.get_paginator("list_group_memberships_for_member")

    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        MemberId={"UserId": user_id},
    ):
        for membership in page.get("GroupMemberships", []):
            gid = membership.get("GroupId")
            if gid:
                group_ids.append(gid)

    return group_ids


def get_group_display_name(identitystore, identity_store_id: str, group_id: str, cache: dict) -> str:
    """Describe group and return DisplayName, with caching."""
    if group_id in cache:
        return cache[group_id]

    resp = identitystore.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    name = resp.get("DisplayName") or group_id
    cache[group_id] = name
    return name


def export_users_with_groups():
    session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
    identitystore = session.client("identitystore", region_name=AWS_REGION)

    identity_store_id = get_identity_store_id(session)
    print(f"IdentityStoreId: {identity_store_id}")
    print(f"Region: {AWS_REGION}")
    print(f"Output: {OUT_CSV}")

    fieldnames = [
        "UserId",
        "UserName",
        "EmailId",
        "FirstName",
        "LastName",
        "DisplayName",
        "Groups",
    ]

    group_name_cache: dict[str, str] = {}

    try:
        with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            paginator = identitystore.get_paginator("list_users")

            total = 0
            for page in paginator.paginate(IdentityStoreId=identity_store_id):
                for user_obj in page.get("Users", []):
                    user_id = user_obj.get("UserId", "")
                    username = user_obj.get("UserName", "")
                    display_name = user_obj.get("DisplayName", "")

                    name = user_obj.get("Name") or {}
                    first_name = name.get("GivenName", "")
                    last_name = name.get("FamilyName", "")
                    email = pick_email(user_obj)

                    # Fetch group memberships
                    group_ids = list_user_group_ids(identitystore, identity_store_id, user_id)
                    group_names = [
                        get_group_display_name(identitystore, identity_store_id, gid, group_name_cache)
                        for gid in group_ids
                    ]
                    group_names_sorted = sorted(set(group_names), key=str.lower)
                    groups_joined = GROUP_SEPARATOR.join(group_names_sorted)

                    writer.writerow(
                        {
                            "UserId": user_id,
                            "UserName": username,
                            "EmailId": email,
                            "FirstName": first_name,
                            "LastName": last_name,
                            "DisplayName": display_name,
                            "Groups": groups_joined,
                        }
                    )

                    total += 1
                    if total % 200 == 0:
                        print(f"Processed {total} users...")

            print(f"Done. Exported {total} users to {OUT_CSV}")

    except (BotoCoreError, ClientError) as e:
        print("AWS API error:", e)
        sys.exit(1)
    except OSError as e:
        print("File error:", e)
        sys.exit(1)


if __name__ == "__main__":
    export_users_with_groups()

import csv
from typing import Dict, List

import boto3


# =========================
# HARD-CODED CONFIG
# =========================
AWS_PROFILE = "Nagarajan"
AWS_REGION = "us-east-1"

INPUT_CSV = "identitystore_users.csv"
OUTPUT_CSV = "identitycenter_user_access_report.csv"

RESOLVE_NAMES = True
# =========================


def get_sso_instance(session):
    sso_admin = session.client("sso-admin")
    resp = sso_admin.list_instances()
    if not resp.get("Instances"):
        raise RuntimeError("No IAM Identity Center instance found.")
    inst = resp["Instances"][0]
    return inst["InstanceArn"], inst["IdentityStoreId"]


def get_user_groups(identitystore, identity_store_id: str, user_id: str) -> List[str]:
    groups = []
    paginator = identitystore.get_paginator("list_group_memberships_for_member")

    for page in paginator.paginate(
        IdentityStoreId=identity_store_id,
        MemberId={"UserId": user_id},
    ):
        for gm in page.get("GroupMemberships", []):
            gid = gm["GroupId"]
            g = identitystore.describe_group(
                IdentityStoreId=identity_store_id,
                GroupId=gid,
            )
            groups.append(g.get("DisplayName") or gid)

    return sorted(set(groups))


def get_user_account_assignments(sso_admin, instance_arn: str, user_id: str):
    assigns = []
    paginator = sso_admin.get_paginator("list_account_assignments_for_principal")

    for page in paginator.paginate(
        InstanceArn=instance_arn,
        PrincipalType="USER",
        PrincipalId=user_id,
    ):
        assigns.extend(page.get("AccountAssignments", []))

    return assigns


def resolve_permission_set_name(sso_admin, instance_arn: str, ps_arn: str) -> str:
    resp = sso_admin.describe_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=ps_arn,
    )
    return resp.get("PermissionSet", {}).get("Name", "")


from botocore.exceptions import ClientError

def resolve_account_name(orgs, account_id: str) -> str:
    try:
        resp = orgs.describe_account(AccountId=account_id)
        return resp.get("Account", {}).get("Name", "")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccountNotFoundException", "AWSOrganizationsNotInUseException"):
            print(f"⚠️ Account not found in Organizations: {account_id}")
            return "NOT_FOUND"
        if code in ("AccessDeniedException", "UnauthorizedOperation"):
            print(f"⚠️ No permission to describe account {account_id}. Returning blank name.")
            return "NO_ACCESS"
        # anything else should still raise
        raise



def main():
    session = boto3.Session(
        profile_name=AWS_PROFILE,
        region_name=AWS_REGION,
    )

    sso_admin = session.client("sso-admin")
    identitystore = session.client("identitystore")
    orgs = session.client("organizations")

    instance_arn, identity_store_id = get_sso_instance(session)

    permset_cache: Dict[str, str] = {}
    account_cache: Dict[str, str] = {}

    output_rows = []

    with open(INPUT_CSV, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        if "UserId" not in reader.fieldnames:
            raise ValueError("Input CSV must contain 'UserId' column.")

        for r in reader:
            user_id = (r.get("UserId") or "").strip()
            username = (r.get("UserName") or "").strip()
            email = (r.get("Email") or "").strip()

            if not user_id:
                continue

            # Groups
            groups = get_user_groups(identitystore, identity_store_id, user_id)
            groups_str = ";".join(groups)

            # Account assignments
            assigns = get_user_account_assignments(sso_admin, instance_arn, user_id)

            if not assigns:
                output_rows.append({
                    "UserId": user_id,
                    "UserName": username,
                    "Email": email,
                    "Groups": groups_str,
                    "AccountId": "",
                    "AccountName": "",
                    "PermissionSet": "",
                    "Status": "NO_ACCOUNT_ASSIGNMENTS",
                })
                continue

            for a in assigns:
                acc_id = a["AccountId"]
                ps_arn = a["PermissionSetArn"]

                ps_name = ""
                acc_name = ""

                if RESOLVE_NAMES:
                    if ps_arn not in permset_cache:
                        permset_cache[ps_arn] = resolve_permission_set_name(
                            sso_admin, instance_arn, ps_arn
                        )
                    ps_name = permset_cache[ps_arn]

                    if acc_id not in account_cache:
                        account_cache[acc_id] = resolve_account_name(orgs, acc_id)
                    acc_name = account_cache[acc_id]

                output_rows.append({
                    "UserId": user_id,
                    "UserName": username,
                    "Email": email,
                    "Groups": groups_str,
                    "AccountId": acc_id,
                    "AccountName": acc_name,
                    "PermissionSet": ps_name or ps_arn,
                    "Status": "OK",
                })

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "UserId",
                "UserName",
                "Email",
                "Groups",
                "AccountId",
                "AccountName",
                "PermissionSet",
                "Status",
            ],
        )
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"✅ Report generated: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

import boto3
import json
import csv
from botocore.config import Config
from botocore.exceptions import ClientError

def get_sso_instance(sso_admin):
    resp = sso_admin.list_instances()
    instances = resp.get("Instances", [])
    if not instances:
        raise RuntimeError("No IAM Identity Center (SSO) instance found in this account/region.")
    # Most orgs have one instance
    return instances[0]["InstanceArn"], instances[0]["IdentityStoreId"]

def list_all_permission_sets(sso_admin, instance_arn):
    permset_arns = []
    paginator = sso_admin.get_paginator("list_permission_sets")
    for page in paginator.paginate(InstanceArn=instance_arn):
        permset_arns.extend(page.get("PermissionSets", []))
    return permset_arns

def safe_get_inline_policy(sso_admin, instance_arn, permset_arn):
    try:
        resp = sso_admin.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permset_arn
        )
        policy = resp.get("InlinePolicy")
        # InlinePolicy is a JSON string when present; empty string if not set in some cases
        if policy and policy.strip():
            return policy
        return None
    except ClientError as e:
        # Some environments may not allow; treat as missing
        if e.response["Error"]["Code"] in ("AccessDeniedException", "ResourceNotFoundException"):
            return None
        raise

def list_attached_managed_policies(sso_admin, instance_arn, permset_arn):
    policies = []
    paginator = sso_admin.get_paginator("list_managed_policies_in_permission_set")
    for page in paginator.paginate(
        InstanceArn=instance_arn,
        PermissionSetArn=permset_arn
    ):
        policies.extend(page.get("AttachedManagedPolicies", []))
    # Each item: { "Name": "...", "Arn": "..." }
    return policies

def list_customer_managed_policy_refs(sso_admin, instance_arn, permset_arn):
    refs = []
    paginator = sso_admin.get_paginator("list_customer_managed_policy_references_in_permission_set")
    for page in paginator.paginate(
        InstanceArn=instance_arn,
        PermissionSetArn=permset_arn
    ):
        refs.extend(page.get("CustomerManagedPolicyReferences", []))
    # Each item: { "Name": "...", "Path": "/optional/" }
    return refs

def safe_get_permissions_boundary(sso_admin, instance_arn, permset_arn):
    """
    Returns dict like:
    { "CustomerManagedPolicyReference": {"Name": "...", "Path": "..." } }
    or
    { "ManagedPolicyArn": "arn:aws:iam::aws:policy/..." }
    or None
    """
    try:
        resp = sso_admin.get_permissions_boundary_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=permset_arn
        )
        return resp.get("PermissionsBoundary")
    except ClientError as e:
        # If boundary not set, AWS may return ResourceNotFoundException depending on API behavior/region
        if e.response["Error"]["Code"] in ("ResourceNotFoundException", "AccessDeniedException"):
            return None
        raise

def main(
    region="eu-west-1",
    profile=None,
    out_csv="permission_sets_policies.csv",
    out_json="permission_sets_policies.json"
):
    cfg = Config(retries={"max_attempts": 10, "mode": "standard"})
    session = boto3.Session(profile_name=profile, region_name=region) if profile else boto3.Session(region_name=region)
    sso_admin = session.client("sso-admin", config=cfg)

    instance_arn, _identity_store_id = get_sso_instance(sso_admin)

    permset_arns = list_all_permission_sets(sso_admin, instance_arn)
    results = []

    for ps_arn in permset_arns:
        ps = sso_admin.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn
        )["PermissionSet"]

        attached_managed = list_attached_managed_policies(sso_admin, instance_arn, ps_arn)
        customer_refs = list_customer_managed_policy_refs(sso_admin, instance_arn, ps_arn)
        inline_policy = safe_get_inline_policy(sso_admin, instance_arn, ps_arn)
        boundary = safe_get_permissions_boundary(sso_admin, instance_arn, ps_arn)

        item = {
            "PermissionSetName": ps.get("Name", ""),
            "PermissionSetArn": ps_arn,
            "Description": ps.get("Description", ""),
            "SessionDuration": ps.get("SessionDuration", ""),
            "RelayState": ps.get("RelayState", ""),
            "CreatedDate": ps.get("CreatedDate").isoformat() if ps.get("CreatedDate") else "",
            "AttachedManagedPolicies": attached_managed,  # list of {Name, Arn}
            "CustomerManagedPolicyReferences": customer_refs,  # list of {Name, Path}
            "InlinePolicy": inline_policy,  # JSON string or None
            "PermissionsBoundary": boundary,  # dict or None
        }
        results.append(item)

    # ---- Write JSON (keeps full inline policy) ----
    with open(out_json, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2, default=str)
    print(f"Wrote JSON: {out_json}")

    # ---- Write CSV (flattened; inline policy in a single column) ----
    with open(out_csv, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow([
            "PermissionSetName",
            "PermissionSetArn",
            "Description",
            "SessionDuration",
            "AttachedManagedPolicies",              # pipe separated "Name (Arn)"
            "CustomerManagedPolicyReferences",      # pipe separated "PathName" (Path/Name)
            "PermissionsBoundary",                  # string representation
            "HasInlinePolicy",
            "InlinePolicyJson"                      # full json string (can be large)
        ])

        for r in results:
            managed_str = "|".join([f"{p.get('Name','')} ({p.get('Arn','')})" for p in r["AttachedManagedPolicies"]])
            cust_str = "|".join([f"{(c.get('Path','') or '')}{c.get('Name','')}" for c in r["CustomerManagedPolicyReferences"]])

            boundary = r["PermissionsBoundary"]
            if boundary is None:
                boundary_str = ""
            else:
                # boundary can be either ManagedPolicyArn OR CustomerManagedPolicyReference
                if "ManagedPolicyArn" in boundary:
                    boundary_str = boundary["ManagedPolicyArn"]
                elif "CustomerManagedPolicyReference" in boundary:
                    cmpr = boundary["CustomerManagedPolicyReference"]
                    boundary_str = f"{(cmpr.get('Path','') or '')}{cmpr.get('Name','')}"
                else:
                    boundary_str = json.dumps(boundary)

            inline = r["InlinePolicy"] or ""
            writer.writerow([
                r["PermissionSetName"],
                r["PermissionSetArn"],
                r["Description"],
                r["SessionDuration"],
                managed_str,
                cust_str,
                boundary_str,
                "YES" if inline.strip() else "NO",
                inline
            ])

    print(f"Wrote CSV:  {out_csv}")
    print(f"Permission sets found: {len(results)}")

if __name__ == "__main__":
    # Examples:
    # main(region="eu-west-1")                      # default credentials
    main(region="us-east-1", profile="Nagarajan") # named profile
    #main(region="eu-west-1", profile=None)

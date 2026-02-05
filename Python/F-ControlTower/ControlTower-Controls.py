#!/usr/bin/env python3
"""
Export AWS Control Tower enabled controls + effective applicability per account to one CSV.

Hardcoded:
  - AWS profile
  - Region (Control Tower home region)
  - Output CSV

Key point:
  - Use controltower:list_enabled_controls to find what's enabled on OU/Account targets
  - Use controlcatalog:get_control to fetch control metadata (Name/Description/Behavior/etc.)
"""

import boto3
import csv
import sys
from typing import Dict, List

# ==========================
# HARD-CODED CONFIG
# ==========================
PROFILE_NAME = "Nagarajan"     # <-- change if needed
REGION = "us-east-1"                    # Control Tower home region
OUTPUT_CSV = "control_tower_controls.csv"
# ==========================


def paginate(client, method_name: str, result_key: str, **kwargs):
    paginator = client.get_paginator(method_name)
    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item


def build_ou_tree(org_client):
    roots = org_client.list_roots()["Roots"]
    if not roots:
        raise RuntimeError("No AWS Organizations root found.")
    root_id = roots[0]["Id"]

    ou_by_id = {}

    def walk(parent_id):
        for ou in paginate(
            org_client,
            "list_organizational_units_for_parent",
            "OrganizationalUnits",
            ParentId=parent_id
        ):
            ou_by_id[ou["Id"]] = {
                "Id": ou["Id"],
                "Arn": ou.get("Arn"),
                "Name": ou.get("Name"),
                "ParentId": parent_id,
            }
            walk(ou["Id"])

    walk(root_id)
    return root_id, ou_by_id


def list_accounts(org_client):
    return list(paginate(org_client, "list_accounts", "Accounts"))


def get_parent_chain(org_client, child_id):
    chain = []
    current = child_id
    while True:
        parents = org_client.list_parents(ChildId=current).get("Parents", [])
        if not parents:
            break
        parent = parents[0]
        chain.append(parent)
        if parent["Type"] == "ROOT":
            break
        current = parent["Id"]
    return chain


def resolve_ou_path(org_client, ou_by_id, account_id):
    chain = get_parent_chain(org_client, account_id)
    ou_ids = [p["Id"] for p in chain if p["Type"] == "ORGANIZATIONAL_UNIT"]
    ou_ids.reverse()

    ou_names = []
    for ou_id in ou_ids:
        if ou_id not in ou_by_id:
            ou = org_client.describe_organizational_unit(OrganizationalUnitId=ou_id)["OrganizationalUnit"]
            ou_by_id[ou_id] = {
                "Id": ou["Id"],
                "Arn": ou.get("Arn"),
                "Name": ou.get("Name"),
                "ParentId": None,
            }
        ou_names.append(ou_by_id[ou_id]["Name"])

    return ou_ids, ou_names


def list_enabled_controls(controltower_client, target_arn):
    """
    targetIdentifier must be an OU ARN or Account ARN (NOT ROOT ARN).
    """
    controls = []
    for c in paginate(
        controltower_client,
        "list_enabled_controls",
        "enabledControls",
        targetIdentifier=target_arn
    ):
        cid = c.get("controlIdentifier")
        if cid:
            controls.append(cid)
    return controls


def get_control_metadata(controlcatalog_client, control_arn: str, cache: Dict[str, dict]) -> dict:
    """
    Uses Control Catalog GetControl, which *does* return:
      Name, Description, Behavior (PREVENTIVE/PROACTIVE/DETECTIVE), Severity, Implementation, Aliases, GovernedResources
    GetControl accepts controltower ARNs or controlcatalog ARNs.
    """
    if control_arn in cache:
        return cache[control_arn]

    try:
        resp = controlcatalog_client.get_control(ControlArn=control_arn)
    except Exception as e:
        cache[control_arn] = {
            "Name": "",
            "Description": "",
            "Behavior": "",
            "Severity": "",
            "Aliases": [],
            "ImplementationType": "",
            "ImplementationIdentifier": "",
            "GovernedResources": [],
            "_error": str(e),
        }
        return cache[control_arn]

    impl = resp.get("Implementation") or {}
    cache[control_arn] = {
        "Name": resp.get("Name", ""),
        "Description": resp.get("Description", ""),
        "Behavior": resp.get("Behavior", ""),     # PREVENTIVE / PROACTIVE / DETECTIVE
        "Severity": resp.get("Severity", ""),     # LOW / MEDIUM / HIGH / CRITICAL
        "Aliases": resp.get("Aliases", []) or [],
        "ImplementationType": impl.get("Type", ""),
        "ImplementationIdentifier": impl.get("Identifier", ""),
        "GovernedResources": resp.get("GovernedResources", []) or [],
    }
    return cache[control_arn]


def main():
    print("Starting Control Tower control export...", file=sys.stderr)

    session = boto3.Session(profile_name=PROFILE_NAME, region_name=REGION)
    org = session.client("organizations")
    ct = session.client("controltower")
    cc = session.client("controlcatalog")  # <-- IMPORTANT

    root_id, ou_by_id = build_ou_tree(org)
    accounts = list_accounts(org)

    # Targets to query: ALL OUs + ALL Accounts (no ROOT)
    targets = []

    for ou in ou_by_id.values():
        if ou.get("Arn"):
            targets.append(("OU", ou["Name"], ou["Arn"]))

    account_targets = []
    for acc in accounts:
        acc_arn = acc.get("Arn")
        if acc_arn:
            account_targets.append(("ACCOUNT", acc["Name"], acc_arn))

    targets.extend(account_targets)

    print(f"Querying enabled controls across {len(targets)} targets (OUs + Accounts)...", file=sys.stderr)

    enabled_by_target: Dict[str, List[str]] = {}
    for ttype, name, arn in targets:
        try:
            enabled_by_target[arn] = list_enabled_controls(ct, arn)
        except Exception as e:
            print(f"WARNING: Could not list enabled controls for {ttype} {name} ({arn}): {e}", file=sys.stderr)
            enabled_by_target[arn] = []

    # For OU path resolution
    ou_arn_by_id = {ou_id: ou.get("Arn") for ou_id, ou in ou_by_id.items()}
    ou_name_by_id = {ou_id: ou.get("Name", ou_id) for ou_id, ou in ou_by_id.items()}

    # Control metadata cache
    meta_cache: Dict[str, dict] = {}

    rows = []
    print(f"Computing effective controls for {len(accounts)} accounts...", file=sys.stderr)

    for acc in accounts:
        acc_id = acc["Id"]
        acc_name = acc["Name"]
        acc_arn = acc.get("Arn")

        ou_ids, ou_names = resolve_ou_path(org, ou_by_id, acc_id)
        ou_path = " / ".join(ou_names) if ou_names else ""

        # Inheritance layers: parent OUs (top-down) + account itself
        layers = []
        for ou_id in ou_ids:
            ou_arn = ou_arn_by_id.get(ou_id)
            if ou_arn:
                layers.append(("OU", ou_name_by_id.get(ou_id, ou_id), ou_arn))

        if acc_arn:
            layers.append(("ACCOUNT", acc_name, acc_arn))

        for layer_type, layer_name, layer_arn in layers:
            for control_arn in enabled_by_target.get(layer_arn, []):
                meta = get_control_metadata(cc, control_arn, meta_cache)

                rows.append({
                    "account_id": acc_id,
                    "account_name": acc_name,
                    "ou_path": ou_path,

                    "control_arn": control_arn,
                    "control_name": meta["Name"],
                    "control_behavior": meta["Behavior"],              # ✅ now filled
                    "control_severity": meta["Severity"],
                    "control_description": meta["Description"],        # ✅ now filled

                    # Instead of "category" (not provided by GetControl)
                    "implementation_type": meta["ImplementationType"],
                    "implementation_identifier": meta["ImplementationIdentifier"],
                    "aliases": ";".join(meta["Aliases"]),
                    "governed_resources": ";".join(meta["GovernedResources"]),

                    "enabled_on_type": layer_type,     # OU / ACCOUNT
                    "enabled_on_name": layer_name,
                    "enabled_on_arn": layer_arn,

                    "region": REGION,
                })

    fieldnames = [
        "account_id", "account_name", "ou_path",
        "control_arn", "control_name", "control_behavior", "control_severity", "control_description",
        "implementation_type", "implementation_identifier", "aliases", "governed_resources",
        "enabled_on_type", "enabled_on_name", "enabled_on_arn",
        "region"
    ]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    print(f"✅ Export completed: {OUTPUT_CSV} (rows: {len(rows)})", file=sys.stderr)


if __name__ == "__main__":
    main()

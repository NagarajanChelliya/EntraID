#!/usr/bin/env python3
import boto3
import csv
from botocore.exceptions import ClientError

# =========================
# HARDCODED VALUES
# =========================
AWS_PROFILE = "Nagarajan"                 # <-- change
AWS_REGION = "us-east-1"                  # <-- change if needed
OUTPUT_CSV = "03-controltower-all-controls.csv"
# =========================


def derive_service_from_implementation_type(impl_type: str) -> str:
    """
    Best-effort derivation:
      AWS::Config::ConfigRule -> Config
      AWS::CloudFormation::Guard -> CloudFormation
    """
    if not impl_type:
        return ""
    parts = impl_type.split("::")
    if len(parts) >= 2 and parts[0] == "AWS":
        return parts[1]
    return impl_type


def list_all_control_arns(cc):
    arns = []
    next_token = None

    while True:
        params = {"MaxResults": 100}
        if next_token:
            params["NextToken"] = next_token

        resp = cc.list_controls(**params)
        for c in resp.get("Controls", []):
            arn = c.get("ControlArn") or c.get("Arn")
            if arn:
                arns.append(arn)

        next_token = resp.get("NextToken")
        if not next_token:
            break

    return arns


def build_common_controls_map(cc):
    """
    Build a dict:
      { "<controlArn>": set(["<commonControlArn1>", "<commonControlArn2>", ...]) }
    using list_control_mappings with MappingTypes=['COMMON_CONTROL'].
    """
    common_map = {}
    next_token = None

    print("Building COMMON_CONTROL mapping map (ListControlMappings)...")

    while True:
        params = {
            "MaxResults": 100,
            "Filter": {"MappingTypes": ["COMMON_CONTROL"]}
        }
        if next_token:
            params["NextToken"] = next_token

        resp = cc.list_control_mappings(**params)

        for m in resp.get("ControlMappings", []):
            control_arn = m.get("ControlArn", "")
            mapping = m.get("Mapping", {}) or {}
            cc_obj = mapping.get("CommonControl") or {}
            common_arn = cc_obj.get("CommonControlArn")

            if control_arn and common_arn:
                common_map.setdefault(control_arn, set()).add(common_arn)

        next_token = resp.get("NextToken")
        if not next_token:
            break

    return common_map


def get_control_details(cc, control_arn):
    """
    GetControl returns top-level fields like:
      Arn, Name, Description, Behavior, Implementation{Type,Identifier}, ...
    (not nested under "Control" in the AWS API reference)
    """
    resp = cc.get_control(ControlArn=control_arn)

    behavior = resp.get("Behavior", "")
    impl = resp.get("Implementation", {}) or {}
    impl_type = impl.get("Type", "")
    impl_identifier = impl.get("Identifier", "")

    # "implementation" column: keep both Type and Identifier to be useful
    implementation = impl_type
    if impl_identifier:
        implementation = f"{impl_type} | {impl_identifier}" if impl_type else impl_identifier

    service = derive_service_from_implementation_type(impl_type)

    return {
        "ControlArn": resp.get("Arn", control_arn),
        "Name": resp.get("Name", ""),
        "Service": service,
        "Behaviour": behavior,
        "Implementation": implementation,
    }


def main():
    session = boto3.Session(profile_name=AWS_PROFILE)
    cc = session.client("controlcatalog", region_name=AWS_REGION)

    print("Listing all controls (ControlCatalog ListControls)...")
    control_arns = list_all_control_arns(cc)
    print(f"Found {len(control_arns)} controls.")

    common_map = build_common_controls_map(cc)

    print("Fetching control details (GetControl) and exporting CSV...")
    fieldnames = ["ControlArn", "Name", "Service", "CommonControls", "Behaviour", "Implementation"]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        for arn in control_arns:
            try:
                row = get_control_details(cc, arn)

                # CommonControls from mapping map
                commons = sorted(list(common_map.get(row["ControlArn"], set())))  # match on catalog ARN
                if not commons:
                    # sometimes list_controls returns a CT ARN; get_control returns catalog ARN.
                    # also check using original ARN
                    commons = sorted(list(common_map.get(arn, set())))

                row["CommonControls"] = ",".join(commons)

                w.writerow(row)

            except ClientError as e:
                code = e.response["Error"].get("Code", "Unknown")
                print(f"[WARN] Failed for {arn}: {code}")
                w.writerow({
                    "ControlArn": arn,
                    "Name": "",
                    "Service": "",
                    "CommonControls": "",
                    "Behaviour": "",
                    "Implementation": ""
                })

    print(f"\n[DONE] CSV exported: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

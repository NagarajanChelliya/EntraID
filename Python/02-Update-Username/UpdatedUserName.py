import boto3
import csv
from botocore.exceptions import ClientError

# =========================
# HARD-CODED CONFIG
# =========================
REGION = "us-east-1"
AWS_PROFILE = None  # e.g. "Nagarajan" or None
INPUT_CSV = "identitystore_users.csv"
OUTPUT_CSV = "identitystore_users_update_results.csv"
# =========================


def get_identity_store_id(session: boto3.Session) -> str:
    """Discover IdentityStoreId dynamically from IAM Identity Center."""
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
            f"No IAM Identity Center instances found in region '{REGION}'. "
            "Make sure REGION is where Identity Center is configured."
        )

    if len(instances) > 1:
        print("⚠ Multiple Identity Center instances found. Using the first one.")

    return instances[0]["IdentityStoreId"]


def update_username(identitystore_client, identity_store_id: str, user_id: str, new_username: str):
    """Update identitystore userName to new_username."""
    identitystore_client.update_user(
        IdentityStoreId=identity_store_id,
        UserId=user_id,
        Operations=[
            {
                "AttributePath": "userName",
                "AttributeValue": new_username
            }
        ]
    )


def main():
    session = boto3.Session(profile_name=AWS_PROFILE) if AWS_PROFILE else boto3.Session()
    identity_store_id = get_identity_store_id(session)
    print(f"✅ IdentityStoreId: {identity_store_id}")

    identitystore = session.client("identitystore", region_name=REGION)

    # Read input + write output as we go (safer for large CSVs)
    with open(INPUT_CSV, "r", encoding="utf-8-sig", newline="") as fin, \
         open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as fout:

        reader = csv.DictReader(fin)

        # Ensure required columns exist
        required_cols = {"UserId", "Email"}
        missing = required_cols - set(reader.fieldnames or [])
        if missing:
            raise RuntimeError(f"Input CSV missing required column(s): {', '.join(sorted(missing))}")

        fieldnames = list(reader.fieldnames) + ["UpdatedUserName", "Status", "Error"]
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        processed = 0
        success = 0
        failed = 0

        for row in reader:
            processed += 1

            user_id = (row.get("UserId") or "").strip()
            email = (row.get("Email") or "").strip()

            row["UpdatedUserName"] = email

            # Basic validation
            if not user_id or not email:
                row["Status"] = "FAILED"
                row["Error"] = "Missing UserId or Email"
                writer.writerow(row)
                failed += 1
                continue

            try:
                update_username(identitystore, identity_store_id, user_id, email)
                row["Status"] = "SUCCESS"
                row["Error"] = ""
                success += 1
            except ClientError as e:
                row["Status"] = "FAILED"
                row["Error"] = str(e)
                failed += 1
            except Exception as e:
                row["Status"] = "FAILED"
                row["Error"] = str(e)
                failed += 1

            writer.writerow(row)

    print(f"Done.\nProcessed: {processed}\nSuccess: {success}\nFailed: {failed}")
    print(f"📁 Output CSV: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

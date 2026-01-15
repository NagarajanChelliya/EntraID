import csv
import sys
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

# =========================
# HARD-CODED CONFIG
# =========================
CSV_FILE_PATH = "identitystore_users.csv"  # <-- attached file path (hardcoded)
AWS_PROFILE = "Nagarajan"                             # <-- change if needed
AWS_REGION = "us-east-1"                              # <-- change if needed

# CSV column names expected (case-insensitive match)
USERID_COL_CANDIDATES = {"userid", "user_id", "user id", "id"}
USERNAME_COL_CANDIDATES = {"username", "userName", "user_name", "user name", "newusername", "new_user_name", "new user name"}


def get_identity_store_id(session: boto3.Session) -> str:
    """Fetch Identity Store ID dynamically using SSO Admin ListInstances."""
    sso_admin = session.client("sso-admin", region_name=AWS_REGION)
    resp = sso_admin.list_instances()
    instances = resp.get("Instances", [])

    if not instances:
        raise RuntimeError(
            "No IAM Identity Center (SSO) instances found in this account/region. "
            "Check AWS_PROFILE/AWS_REGION and that IAM Identity Center is enabled."
        )

    # If multiple, pick the first (common case is 1 instance).
    return instances[0]["IdentityStoreId"]


def sniff_dialect(csv_path: Path):
    """Try to detect delimiter; fall back to semicolon then comma."""
    sample = csv_path.read_text(encoding="utf-8-sig", errors="replace")[:5000]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,|\t,")
        return dialect
    except Exception:
        # Default preference: semicolon (common in EU Excel exports), then comma
        class _D:
            delimiter = ";"
            quotechar = '"'
            doublequote = True
            skipinitialspace = True
            lineterminator = "\n"
            quoting = csv.QUOTE_MINIMAL
        return _D()


def normalize_header(h: str) -> str:
    return (h or "").strip().lower()


def find_column(fieldnames, candidates_set):
    """Return the actual column name in CSV that matches candidates (case-insensitive)."""
    if not fieldnames:
        return None
    normalized_map = {normalize_header(fn): fn for fn in fieldnames}
    for c in candidates_set:
        key = normalize_header(c)
        if key in normalized_map:
            return normalized_map[key]
    return None


def update_usernames_from_csv():
    csv_path = Path(CSV_FILE_PATH)
    if not csv_path.exists():
        print(f"ERROR: CSV file not found: {CSV_FILE_PATH}", file=sys.stderr)
        sys.exit(1)

    session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)

    # Dynamically get Identity Store ID
    identity_store_id = get_identity_store_id(session)
    print(f"IdentityStoreId: {identity_store_id}")
    print(f"Region: {AWS_REGION}")
    print(f"Profile: {AWS_PROFILE}")
    print(f"CSV: {CSV_FILE_PATH}")
    print("-" * 60)

    identitystore = session.client("identitystore", region_name=AWS_REGION)

    dialect = sniff_dialect(csv_path)

    # Read CSV
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, dialect=dialect)

        userid_col = find_column(reader.fieldnames, USERID_COL_CANDIDATES)
        username_col = find_column(reader.fieldnames, USERNAME_COL_CANDIDATES)

        if not userid_col or not username_col:
            print("ERROR: Could not find required columns in CSV.", file=sys.stderr)
            print(f"Detected headers: {reader.fieldnames}", file=sys.stderr)
            print(
                "Expected something like:\n"
                "  - UserId (userid/user_id)\n"
                "  - UserName (username/user_name/newusername)\n",
                file=sys.stderr,
            )
            sys.exit(2)

        success = 0
        failed = 0
        total = 0

        for row in reader:
            total += 1
            user_id = (row.get(userid_col) or "").strip()
            new_username = (row.get(username_col) or "").strip()

            if not user_id or not new_username:
                failed += 1
                print(f"[SKIP] Row {total}: missing UserId or UserName -> {row}")
                continue

            try:
                identitystore.update_user(
                    IdentityStoreId=identity_store_id,
                    UserId=user_id,
                    Operations=[
                        {
                            "AttributePath": "userName",
                            "AttributeValue": new_username,
                        }
                    ],
                )
                success += 1
                print(f"[OK]   {user_id} -> {new_username}")
            except ClientError as e:
                failed += 1
                code = e.response.get("Error", {}).get("Code", "Unknown")
                msg = e.response.get("Error", {}).get("Message", str(e))
                print(f"[FAIL] {user_id} -> {new_username} | {code}: {msg}")

    print("-" * 60)
    print(f"Done. Total rows: {total}, Success: {success}, Failed/Skipped: {failed}")


if __name__ == "__main__":
    update_usernames_from_csv()

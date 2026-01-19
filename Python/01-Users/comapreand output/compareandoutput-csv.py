import csv
import os

# ==========================
# HARDCODED FILE PATHS
# ==========================
CSV_LOGIN_90DAYS = r"user_login_90days_report.csv"
CSV_ALL_USERS = r"A1-Fetch-All-Users-Respective-Groups.csv"
OUTPUT_CSV = r"matched_users_with_groups.csv"
# ==========================


def normalize_col(name: str) -> str:
    """Normalize column names for safe comparison"""
    return name.strip().lower()


def load_userids(csv_path: str) -> set:
    """Load UserIds from the login report CSV"""
    user_ids = set()

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        columns = {normalize_col(c): c for c in reader.fieldnames}

        if "userid" not in columns:
            raise ValueError(f"'UserId' column not found in {csv_path}")

        userid_col = columns["userid"]

        for row in reader:
            uid = row.get(userid_col, "").strip()
            if uid:
                user_ids.add(uid)

    return user_ids


def filter_users(source_csv: str, valid_userids: set, output_csv: str) -> None:
    """Write rows from source_csv where UserId exists in valid_userids"""
    with open(source_csv, newline="", encoding="utf-8") as src, \
         open(output_csv, "w", newline="", encoding="utf-8") as out:

        reader = csv.DictReader(src)
        columns = {normalize_col(c): c for c in reader.fieldnames}

        if "userid" not in columns:
            raise ValueError(f"'UserId' column not found in {source_csv}")

        userid_col = columns["userid"]

        writer = csv.DictWriter(out, fieldnames=reader.fieldnames)
        writer.writeheader()

        matched = 0
        for row in reader:
            uid = row.get(userid_col, "").strip()
            if uid in valid_userids:
                writer.writerow(row)
                matched += 1

    print(f"✅ Matched users written: {matched}")
    print(f"📄 Output file: {output_csv}")


def main():
    login_userids = load_userids(CSV_LOGIN_90DAYS)
    print(f"🔎 Users with login activity: {len(login_userids)}")

    filter_users(CSV_ALL_USERS, login_userids, OUTPUT_CSV)


if __name__ == "__main__":
    main()

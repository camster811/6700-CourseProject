import os
import json
import subprocess

import pandas as pd


# Base directory where you have cloned the repositories.
# Example structure: repos/<owner>/<repo>/
REPOS_BASE_DIR = "repos"


def parse_repo_url(repo_url: str):
    if not isinstance(repo_url, str):
        return None, None

    s = repo_url.strip()

    if s.endswith(".git"):
        s = s[:-4]

    # Handle GitHub API URLs: https://api.github.com/repos/owner/repo
    if "api.github.com/repos/" in s:
        parts = s.split("api.github.com/repos/", 1)[-1].strip("/")
        owner_repo = parts.split("/")
        if len(owner_repo) >= 2:
            return owner_repo[0], owner_repo[1]

    # Fallback: normal github.com URLs
    if "github.com" in s:
        if s.startswith("http://") or s.startswith("https://"):
            parts = s.split("github.com", 1)[-1].strip("/")
        elif s.startswith("git@github.com:"):
            parts = s.split("git@github.com:", 1)[-1].strip("/")
        else:
            parts = s.split("github.com", 1)[-1].strip("/")

        owner_repo = parts.split("/")
        if len(owner_repo) >= 2:
            return owner_repo[0], owner_repo[1]

    return None, None



def run_bandit_on_file(file_path: str) -> int:
    """
    Run Bandit on the given file_path.

    Returns:
        1 if Bandit reports >= 1 issue.
        0 if no issues or an error occurs (or Bandit not installed).
    """
    try:
        # bandit -f json -q <file>
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Bandit exit codes:
        # 0 = no issues
        # 1 = issues found
        # 2+ = execution error
        if result.returncode not in (0, 1):
            print(f"[Bandit] Error scanning {file_path}: {result.stderr.strip()}")
            return 0

        if not result.stdout.strip():
            return 0

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"[Bandit] Failed to parse JSON output for {file_path}")
            return 0

        findings = data.get("results", [])
        return 1 if len(findings) > 0 else 0

    except FileNotFoundError:
        print(
            "Bandit is not installed or not found in PATH. "
            "Install it with `pip install bandit`."
        )
        return 0
    except Exception as e:
        print(f"Unexpected error running Bandit on {file_path}: {e}")
        return 0


def task7_analyze_vulnerable_files():
    """
    Task 7:
    Starting from the Task-4 CSV, create a new CSV with an extra
    VULNERABLEFILE column.

    VULNERABLEFILE = 1 if:
        (i) file is a Python program (.py);
        (ii) file exists in the local clone of the repository;
        (iii) Bandit reports >= 1 vulnerability.

    Otherwise, VULNERABLEFILE = 0.
    """
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    task4_file = os.path.join(output_dir, "task4_pr_commit_details.csv")
    task1_file = os.path.join(output_dir, "task1_pull_requests.csv")

    if not os.path.exists(task4_file):
        raise FileNotFoundError(
            f"Task-4 CSV not found at {task4_file}. Run task4.py first."
        )

    if not os.path.exists(task1_file):
        raise FileNotFoundError(
            f"Task-1 CSV not found at {task1_file}. Run task1.py first."
        )

    print(f"Loading Task-4 CSV from: {task4_file}")
    task4_df = pd.read_csv(task4_file)

    print(f"Loading Task-1 CSV from: {task1_file}")
    task1_df = pd.read_csv(task1_file)

    # Ensure IDs are strings for a reliable merge
    task4_df["PRID"] = task4_df["PRID"].astype(str)
    task1_df["ID"] = task1_df["ID"].astype(str)

    # Join Task-4 with Task-1 to get REPOURL for each PRID
    print("Merging Task-4 commit details with Task-1 PR repo URLs...")
    merged = task4_df.merge(
        task1_df[["ID", "REPOURL"]],
        left_on="PRID",
        right_on="ID",
        how="left",
    )

    # only need ID to get REPOURL and drop the extra ID column
    merged = merged.drop(columns=["ID"])

    # Initialize VULNERABLEFILE to 0 for all rows
    merged["VULNERABLEFILE"] = 0

    # Cache to avoid scanning the same file path multiple times
    # Key: (local_repo_dir, relative_file_path) -> 0/1
    bandit_cache = {}

    print("Beginning Bandit scanning for Python files...")
    total_rows = len(merged)
    python_candidates = 0
    scanned_files = 0

    for idx, row in merged.iterrows():
        filename = row.get("PRFILE")
        repo_url = row.get("REPOURL")

        # Skip non-strings and non-Python files
        if not isinstance(filename, str):
            continue
        if not filename.lower().endswith(".py"):
            continue

        python_candidates += 1

        if not isinstance(repo_url, str) or not repo_url.strip():
            # No repo URL or it can't locate file
            continue

        owner, repo_name = parse_repo_url(repo_url)
        if not owner or not repo_name:
            # Could not parse repository URL
            continue

        local_repo_dir = os.path.join(REPOS_BASE_DIR, owner, repo_name)

        # Normalize relative path under the repo
        rel_path = filename.lstrip("/\\")
        rel_path_parts = rel_path.replace("\\", "/").split("/")
        file_path = os.path.join(local_repo_dir, *rel_path_parts)

        if not os.path.isfile(file_path):
            # File not present locally means its not "available in the repo" right now
            continue

        cache_key = (local_repo_dir, rel_path)
        if cache_key in bandit_cache:
            vuln_flag = bandit_cache[cache_key]
        else:
            scanned_files += 1
            print(f"[{scanned_files}] Scanning with Bandit: {file_path}")
            vuln_flag = run_bandit_on_file(file_path)
            bandit_cache[cache_key] = vuln_flag

        merged.at[idx, "VULNERABLEFILE"] = vuln_flag

    print(f"Total rows in Task-4 data: {total_rows}")
    print(f"Python file candidates: {python_candidates}")
    print(f"Unique Python files scanned by Bandit: {scanned_files}")

    # Build final Task-7 dataframe with required columns
    task7_df = merged[
        [
            "PRID",
            "PRSHA",
            "PRCOMMITMESSAGE",
            "PRFILE",
            "PRSTATUS",
            "PRADDS",
            "PRDELSS",
            "PRCHANGECOUNT",
            "PRDIFF",
            "VULNERABLEFILE",
        ]
    ]

    output_file = os.path.join(output_dir, "task7_pr_commit_vulnerabilities.csv")
    task7_df.to_csv(output_file, index=False, encoding="utf-8")
    print(f"Task-7 output saved to: {output_file}")
    print(f"Number of records in Task-7 CSV: {len(task7_df)}")

    return task7_df


if __name__ == "__main__":
    print("Processing Task 7: Analyze Vulnerable Files with Bandit")
    print("=" * 70)

    try:
        df = task7_analyze_vulnerable_files()
        print("\nTask 7 execution completed")
    except Exception as e:
        print(f"\nTask 7 execution failed: {e}")

import os
import pandas as pd


def task6_add_validated_flag():
    """
    Task 6:
    Starting from the Task-5 CSV, create a new CSV with an extra VALIDATED column.

    Final CSV (for grading) columns:
        ID, AGENT, TYPE, CONFIDENCE, SECURITY, VALIDATED

    VALIDATED is initialized to 0 for all rows.
    You will manually change VALIDATED to 1 for rows where:
        - SECURITY == 1
        - and, after reading TITLE/BODY, you decide it's truly security-related.

    This script also optionally creates a 'review sheet' that includes TITLE/BODYSTRING
    to make manual inspection easier.
    """

    try:
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # --- Load Task-5 CSV ---
        task5_file = os.path.join(output_dir, "task5_pr_security_summary.csv")
        if not os.path.exists(task5_file):
            raise FileNotFoundError(
                f"Task-5 CSV not found at {task5_file}. "
                "Run task5.py first to generate it."
            )

        print(f"Loading Task-5 CSV from: {task5_file}")
        task5_df = pd.read_csv(task5_file)

        # --- Add VALIDATED column (default 0) ---
        print("Adding VALIDATED column (default 0 for all rows)...")
        task5_df["VALIDATED"] = 0

        # --- Build final Task-6 CSV with exactly required columns ---
        task6_df = task5_df[["ID", "AGENT", "TYPE", "CONFIDENCE", "SECURITY", "VALIDATED"]]

        task6_file = os.path.join(output_dir, "task6_pr_security_validated.csv")
        task6_df.to_csv(task6_file, index=False)

        print("Task 6 base CSV created successfully.")
        print(f"Task-6 CSV (for grading) saved to: {task6_file}")
        print(f"Number of records in Task-6 CSV: {len(task6_df)}")

        # --- created a review sheet with TITLE/BODYSTRING for convenience ---
        task1_file = os.path.join(output_dir, "task1_pull_requests.csv")
        if os.path.exists(task1_file):
            print(f"\nLoading Task-1 CSV from: {task1_file} to build review sheet...")
            task1_df = pd.read_csv(task1_file)

            # only really need ID, TITLE, BODYSTRING for review
            # Make IDs comparable as strings
            task1_df["ID"] = task1_df["ID"].astype(str)
            task6_df["ID"] = task6_df["ID"].astype(str)

            review_df = task6_df.merge(
                task1_df[["ID", "TITLE", "BODYSTRING"]],
                on="ID",
                how="left",
            )

            review_file = os.path.join(output_dir, "task6_review_sheet.csv")
            review_df.to_csv(review_file, index=False)

            print("Review sheet with TITLE/BODYSTRING created.")
            print(f"Review CSV saved to: {review_file}")
            print("Use this file to inspect rows where SECURITY == 1 and "
                  "update VALIDATED accordingly.")
        else:
            print(
                "\nNOTE: Task-1 CSV not found at "
                f"{task1_file}. Skipping creation of review sheet."
            )

        return task6_df

    except Exception as e:
        print(f"Error processing Task 6: {str(e)}")
        return None


if __name__ == "__main__":
    print("Processing Task 6: Add VALIDATED flag")
    print("=" * 50)

    result = task6_add_validated_flag()

    if result is not None:
        print("\nTask 6 execution completed")
    else:
        print("\nTask 6 execution failed")

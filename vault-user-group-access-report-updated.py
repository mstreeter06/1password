import os
import subprocess
import csv
import json
import sys
import time
import logging
import shutil
from pathlib import Path
import re
from datetime import datetime
import argparse

# ------------------ Config ------------------
OUTPUT_DIR = Path("vault_reports")
BACKUP_DIR = OUTPUT_DIR / "backups"
FINAL_REPORT = "vault_access_report.csv"
BACKUP_RETENTION = 3  # Keep last 3 backups
LOG_RETENTION = 6  # Keep last 6 log runs
ENABLE_BACKUPS = True  # Set to False to disable backups
HEADERS = [
    "vaultName",
    "vaultUUID",
    "name",
    "email",
    "userUUID",
    "status",
    "assignment",
    "permissions",
]
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds

# Logging destinations
LOG_DIR = Path("logs")
RUN_TS = datetime.now().strftime("%Y%m%d-%H%M%S")
FULL_LOG_PATH = LOG_DIR / f"run-{RUN_TS}.txt"
ISSUES_LOG_PATH = LOG_DIR / f"issues-{RUN_TS}.txt"
ISSUES_CSV_PATH = LOG_DIR / f"issues-{RUN_TS}.csv"
STATS_LOG_PATH = LOG_DIR / f"stats-{RUN_TS}.txt"

# Add to the Config section after existing variables
SCRIPT_START_TIME = None
SCRIPT_STATS = {
    "start_time": None,
    "end_time": None,
    "total_vaults": 0,
    "completed_vaults": 0,
    "failed_vaults": 0,
    "skipped_vaults": 0,
    "total_users": 0,
    "total_group_members": 0,
    "warnings_count": 0,
    "errors_count": 0
}
# --------------------------------------------

# Setup logging
LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Clear any default handlers (if running repeatedly in REPL/Notebook)
logger.handlers.clear()

fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

# Console
console = logging.StreamHandler(sys.stdout)
console.setLevel(logging.INFO)
console.setFormatter(fmt)
logger.addHandler(console)

# Full log file (everything at INFO+)
file_all = logging.FileHandler(FULL_LOG_PATH, encoding="utf-8")
file_all.setLevel(logging.INFO)
file_all.setFormatter(fmt)
logger.addHandler(file_all)

# Warnings+ to a separate .log
file_issues = logging.FileHandler(ISSUES_LOG_PATH, encoding="utf-8")
file_issues.setLevel(logging.WARNING)
file_issues.setFormatter(fmt)
logger.addHandler(file_issues)

# Optional: Warnings+ also to a CSV
class CsvIssuesHandler(logging.Handler):
    def __init__(self, path: Path):
        super().__init__(level=logging.WARNING)
        self._f = open(path, "w", newline="", encoding="utf-8")
        self._w = csv.writer(self._f)
        self._w.writerow(["timestamp", "level", "message"])

    def emit(self, record: logging.LogRecord):
        try:
            # record.created is epoch seconds
            ts = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S")
            self._w.writerow([ts, record.levelname, record.getMessage()])
            self._f.flush()
        except Exception:
            # Avoid raising inside logging
            pass

    def close(self):
        try:
            self._f.close()
        finally:
            super().close()

csv_issues = CsvIssuesHandler(ISSUES_CSV_PATH)
logger.addHandler(csv_issues)

# Add custom exception class
class AuthenticationError(Exception):
    """Raised when 1Password CLI authentication fails or expires."""
    pass

# Add a custom logging handler to count warnings/errors
class StatsHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.warning_count = 0
        self.error_count = 0
    
    def emit(self, record):
        if record.levelno >= logging.ERROR:
            self.error_count += 1
        elif record.levelno >= logging.WARNING:
            self.warning_count += 1

stats_handler = StatsHandler()
logger.addHandler(stats_handler)

def run_op(args):
    """
    Run an `op` CLI command with retries and auth detection.
    """
    cmd = ["op"] + args
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip()
            
            # Check for authentication issues
            if is_auth_error(error_msg):
                logging.error(f"🔐 Authentication timeout detected: {error_msg}")
                logging.error("   Your 1Password CLI session has expired.")
                logging.error("   Please run 'op signin' to re-authenticate and restart the script.")
                raise AuthenticationError("1Password CLI session expired")
            
            logging.error(f"Command failed (attempt {attempt}/{MAX_RETRIES}): {' '.join(cmd)}\n{error_msg}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            else:
                raise
    return ""

# Add custom exception class
class AuthenticationError(Exception):
    """Raised when 1Password CLI authentication fails or expires."""
    pass

def load_json_list(payload: str, ctx: str) -> list:
    """
    Parse JSON that should be a list. Returns [] on null/invalid/non-list.
    """
    try:
        data = json.loads(payload)
    except Exception as e:
        logging.error(f"{ctx}: failed to parse JSON: {e}")
        return []
    if data is None:
        logging.warning(f"{ctx}: got null; treating as empty list")
        return []
    if isinstance(data, list):
        return data
    logging.warning(f"{ctx}: expected list, got {type(data)}; treating as empty list")
    return []

def get_vaults():
    """
    Get all vaults the signed-in account has manage_vault permission for.
    """
    vaults_json = run_op(["vault", "list", "--permission=manage_vault", "--format=json"])
    return load_json_list(vaults_json, "vault list")

def get_vault_users(vault_id):
    """
    Get users assigned to a vault.
    """
    users_json = run_op(["vault", "user", "list", vault_id, "--format=json"])
    return load_json_list(users_json, f"vault users {vault_id}")

def get_vault_groups(vault_id):
    """
    Get groups assigned to a vault.
    """
    groups_json = run_op(["vault", "group", "list", vault_id, "--format=json"])
    return load_json_list(groups_json, f"vault groups {vault_id}")

def get_group_users(group_id):
    """
    Get users in a group.
    """
    users_json = run_op(["group", "user", "list", group_id, "--format=json"])
    return load_json_list(users_json, f"group users {group_id}")

def sanitize_filename(name: str, max_length: int = 150) -> str:
    """
    Make a string safe for use as a filename across platforms.
    Replaces reserved characters and trims problematic endings.
    """
    # Replace invalid/reserved characters (covers macOS/Linux/Windows)
    clean = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "_", name)
    # Collapse whitespace, trim, and remove trailing dots/spaces
    clean = re.sub(r"\s+", " ", clean).strip().strip(".")
    if not clean:
        clean = "unnamed"
    # Keep names from getting too long
    if len(clean) > max_length:
        clean = clean[:max_length].rstrip()
    return clean

def vault_report_path(vault_name: str, vault_id: str, output_dir: Path = OUTPUT_DIR) -> Path:
    """
    Build a safe per-vault CSV path.
    """
    safe_name = sanitize_filename(vault_name)
    return output_dir / f"{safe_name}_{vault_id}.csv"

def writeVaultReport(vault_name, vault_id, rows, output_dir=OUTPUT_DIR):
    """
    Write per-vault CSV.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = vault_report_path(vault_name, vault_id, output_dir)

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        writer.writerows(rows)

    logging.info(f"✅ Wrote report for vault {vault_name} ({vault_id}) -> {file_path}")

def update_script_stats(**kwargs):
    """Update script statistics."""
    SCRIPT_STATS.update(kwargs)

def format_duration(seconds):
    """Format duration in a human-readable way."""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        minutes = (seconds % 3600) / 60
        return f"{hours:.1f} hours, {minutes:.0f} minutes"

def process_vault(vault, output_dir=OUTPUT_DIR):
    """
    Process a single vault, fetching users + groups and writing checkpoint file.
    """
    vault_id = vault["id"]
    vault_name = vault["name"]
    file_path = vault_report_path(vault_name, vault_id, output_dir)

    if file_path.exists():
        logging.info(f"⏩ Skipping {vault_name} ({vault_id}) — already exported")
        update_script_stats(skipped_vaults=SCRIPT_STATS["skipped_vaults"] + 1)
        return True  # Return success status

    rows = []
    try:
        logging.debug(f"Fetching users for vault: {vault_name}")
        # Direct users
        users = get_vault_users(vault_id)
        for user in users:
            rows.append([
                vault_name,
                vault_id,
                user.get("name", ""),
                user.get("email", ""),
                user.get("id", ""),
                user.get("state", ""),
                "Direct",
                ",".join(user.get("permissions", [])),
            ])

        logging.debug(f"Fetching groups for vault: {vault_name}")
        # Groups - only expand members, skip the group placeholder row
        groups = get_vault_groups(vault_id)
        for group in groups:
            group_name = group.get("name", "")
            group_id = group.get("id", "")
            group_perms = ",".join(group.get("permissions", []))

            logging.debug(f"Fetching members for group: {group_name}")
            # Only add rows for group members (skip the group placeholder row)
            group_users = get_group_users(group_id)
            for guser in group_users:
                rows.append([
                    vault_name,
                    vault_id,
                    guser.get("name", ""),
                    guser.get("email", ""),
                    guser.get("id", ""),
                    guser.get("state", ""),
                    f"Group ({group_name})",
                    group_perms,
                ])

        # Write checkpoint
        writeVaultReport(vault_name, vault_id, rows, output_dir=output_dir)
        
        user_count = len([r for r in rows if r[6] == "Direct"])
        group_user_count = len([r for r in rows if r[6].startswith("Group")])
        
        # Update stats
        update_script_stats(
            total_users=SCRIPT_STATS["total_users"] + user_count,
            total_group_members=SCRIPT_STATS["total_group_members"] + group_user_count
        )
        
        logging.info(f"⭐ {vault_name}: {user_count} direct users, {group_user_count} group members")
        
        return True

    except AuthenticationError:
        # Re-raise auth errors to stop processing
        raise
    except Exception as e:
        logging.error(f"❌ Failed to process vault {vault_name} ({vault_id}): {e}")
        return False

def manage_backups(output_dir=OUTPUT_DIR, backup_dir=BACKUP_DIR, retention=BACKUP_RETENTION):
    """
    Backup existing vault CSV files and manage retention (keep last N runs).
    """
    if not ENABLE_BACKUPS:
        logging.info("📦 Backups disabled, skipping backup process")
        return

    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Create timestamped backup directory for this run
    run_backup_dir = backup_dir / f"run_{RUN_TS}"
    
    # Check if there are any existing vault CSV files to backup
    existing_files = list(output_dir.glob("*.csv"))
    if not existing_files:
        logging.info("📦 No existing vault CSV files to backup")
    else:
        run_backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup existing vault CSV files
        backed_up_count = 0
        for csv_file in existing_files:
            backup_path = run_backup_dir / csv_file.name
            try:
                # Copy the file to backup directory
                with open(csv_file, 'r', encoding='utf-8') as src, \
                     open(backup_path, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
                backed_up_count += 1
            except Exception as e:
                logging.warning(f"Failed to backup {csv_file.name}: {e}")
        
        logging.info(f"📦 Backed up {backed_up_count} vault CSV files to {run_backup_dir}")
    
    # Manage retention - keep only the last N backup runs
    cleanup_old_backups(backup_dir, retention)

def cleanup_old_backups(backup_dir, retention):
    """
    Remove old backup runs, keeping only the most recent N runs.
    """
    try:
        # Get all run_* directories, sorted by name (which includes timestamp)
        run_dirs = [d for d in backup_dir.iterdir() if d.is_dir() and d.name.startswith("run_")]
        run_dirs.sort(key=lambda x: x.name, reverse=True)  # Most recent first
        
        if len(run_dirs) <= retention:
            logging.info(f"📦 {len(run_dirs)} backup runs found, no cleanup needed (retention: {retention})")
            return
        
        # Remove old backup runs beyond retention limit
        dirs_to_remove = run_dirs[retention:]
        for old_dir in dirs_to_remove:
            try:
                # Use shutil.rmtree with error handling for Windows
                def handle_remove_readonly(func, path, exc):
                    """Error handler for Windows readonly files."""
                    import stat
                    if exc[1].errno == 13:  # Permission denied
                        os.chmod(path, stat.S_IWRITE)
                        func(path)
                    else:
                        raise
                
                shutil.rmtree(old_dir, onerror=handle_remove_readonly)
                logging.info(f"📦 Removed old backup: {old_dir.name}")
            except Exception as e:
                logging.warning(f"Failed to remove old backup {old_dir.name}: {e}")
                # Try alternative approach if shutil.rmtree fails
                try:
                    # Force remove readonly attributes and try again
                    for root, dirs, files in os.walk(old_dir, topdown=False):
                        for name in files:
                            file_path = os.path.join(root, name)
                            os.chmod(file_path, 0o777)
                            os.remove(file_path)
                        for name in dirs:
                            dir_path = os.path.join(root, name)
                            os.chmod(dir_path, 0o777)
                            os.rmdir(dir_path)
                    os.rmdir(old_dir)
                    logging.info(f"📦 Removed old backup (fallback method): {old_dir.name}")
                except Exception as e2:
                    logging.error(f"Failed to remove backup directory {old_dir.name} with fallback method: {e2}")
        
        remaining_runs = len(run_dirs) - len([d for d in dirs_to_remove if not d.exists()])
        logging.info(f"📦 Cleanup complete: {remaining_runs} backup runs retained")
        
    except Exception as e:
        logging.error(f"Failed to cleanup old backups: {e}")

def cleanup_old_exports(exports_dir, retention):
    """
    Remove old export files, keeping only the most recent N files.
    """
    try:
        # Get all vault_access_report_*.csv files, sorted by name (which includes timestamp)
        export_files = [f for f in exports_dir.iterdir() 
                       if f.is_file() and f.name.startswith("vault_access_report_") and f.name.endswith(".csv")]
        export_files.sort(key=lambda x: x.name, reverse=True)  # Most recent first
        
        if len(export_files) <= retention:
            logging.info(f"📁 {len(export_files)} export files found, no cleanup needed (retention: {retention})")
            return
        
        # Remove old export files beyond retention limit
        files_to_remove = export_files[retention:]
        for old_file in files_to_remove:
            try:
                old_file.unlink()
                logging.info(f"📁 Removed old export: {old_file.name}")
            except Exception as e:
                logging.warning(f"Failed to remove old export {old_file.name}: {e}")
        
        remaining_files = len(export_files) - len(files_to_remove)
        logging.info(f"📁 Export cleanup complete: {remaining_files} export files retained")
        
    except Exception as e:
        logging.error(f"Failed to cleanup old exports: {e}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Generate 1Password vault access report")
    parser.add_argument("--no-backup", action="store_true", 
                       help="Disable backup of existing vault CSV files")
    parser.add_argument("--backup-retention", type=int, default=BACKUP_RETENTION,
                       help=f"Number of backup runs to keep (default: {BACKUP_RETENTION})")
    parser.add_argument("--fresh-run", action="store_true",
                       help="Start a fresh run by removing existing vault CSV files (forces re-processing of all vaults)")
    
    # Add filtering options
    parser.add_argument("--vault-filter", 
                       help="Filter vaults by name (supports regex patterns)")
    parser.add_argument("--user-name-filter", 
                       help="Filter results by user name (supports regex patterns)")
    parser.add_argument("--user-email-filter", 
                       help="Filter results by user email (supports regex patterns)")
    parser.add_argument("--case-sensitive", action="store_true",
                       help="Make filters case-sensitive (default: case-insensitive)")
    
    return parser.parse_args()

def filter_vaults(vaults, pattern=None, case_sensitive=False):
    """Filter vaults based on regex pattern if provided."""
    if not pattern:
        return vaults
    
    try:
        flags = 0 if case_sensitive else re.IGNORECASE
        regex = re.compile(pattern, flags)
        filtered = [v for v in vaults if regex.search(v['name'])]
        logging.info(f"🔍 Vault filter '{pattern}' matched {len(filtered)}/{len(vaults)} vaults")
        
        if len(filtered) == 0:
            logging.warning("⚠️  No vaults matched the filter pattern")
        else:
            logging.debug("Matched vaults: " + ", ".join([v['name'] for v in filtered[:5]]) + 
                         ("..." if len(filtered) > 5 else ""))
        
        return filtered
    except re.error as e:
        logging.error(f"❌ Invalid regex pattern '{pattern}': {e}")
        logging.info("Proceeding without vault filtering")
        return vaults

def filter_report_data(all_rows, user_name_filter=None, user_email_filter=None, case_sensitive=False):
    """Filter report data based on user name and/or email patterns."""
    if not user_name_filter and not user_email_filter:
        return all_rows
    
    flags = 0 if case_sensitive else re.IGNORECASE
    filtered_rows = []
    original_count = len(all_rows)
    
    try:
        # Compile regex patterns
        name_regex = re.compile(user_name_filter, flags) if user_name_filter else None
        email_regex = re.compile(user_email_filter, flags) if user_email_filter else None
        
        for row in all_rows:
            # Row format: [vaultName, vaultUUID, name, email, userUUID, status, assignment, permissions]
            user_name = row[2] if len(row) > 2 else ""
            user_email = row[3] if len(row) > 3 else ""
            
            name_match = True if not name_regex else name_regex.search(user_name)
            email_match = True if not email_regex else email_regex.search(user_email)
            
            # Include row if both conditions are met (AND logic)
            if name_match and email_match:
                filtered_rows.append(row)
        
        # Log filtering results
        if user_name_filter and user_email_filter:
            logging.info(f"🔍 User filters (name: '{user_name_filter}', email: '{user_email_filter}') matched {len(filtered_rows)}/{original_count} entries")
        elif user_name_filter:
            logging.info(f"🔍 User name filter '{user_name_filter}' matched {len(filtered_rows)}/{original_count} entries")
        elif user_email_filter:
            logging.info(f"🔍 User email filter '{user_email_filter}' matched {len(filtered_rows)}/{original_count} entries")
        
        if len(filtered_rows) == 0:
            logging.warning("⚠️  No entries matched the user filter patterns")
        
        return filtered_rows
        
    except re.error as e:
        pattern = user_name_filter or user_email_filter
        logging.error(f"❌ Invalid regex pattern '{pattern}': {e}")
        logging.info("Proceeding without user filtering")
        return all_rows

def combine_reports(output_dir=OUTPUT_DIR, final_report=FINAL_REPORT, user_name_filter=None, user_email_filter=None, case_sensitive=False):
    """
    Combine all per-vault reports into a single CSV, with optional filtering, sorted by email.
    """
    all_rows = []
    for file in output_dir.glob("*.csv"):
        with open(file, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            all_rows.extend(list(reader))

    # Apply user-based filtering if specified
    all_rows = filter_report_data(all_rows, user_name_filter, user_email_filter, case_sensitive)

    # Sort by email (index 3), case-insensitive; blanks last. Tie-breaker: userUUID (index 4).
    def sort_key(row):
        email = (row[3] or "").strip().lower()
        user_uuid = (row[4] or "").strip().lower()
        empty_email = 1 if not email else 0
        return (empty_email, email, user_uuid)

    all_rows.sort(key=sort_key)

    # Determine if we're creating a filtered report
    is_filtered = bool(user_name_filter or user_email_filter)
    
    if is_filtered:
        # Create filtered report with suffix
        base_name = Path(final_report).stem  # "vault_access_report"
        extension = Path(final_report).suffix  # ".csv"
        filtered_report = f"{base_name}_filtered{extension}"
        
        # Write filtered report
        with open(filtered_report, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(HEADERS)
            writer.writerows(all_rows)
        
        logging.info(f"📊 Filtered report written to {filtered_report} (sorted by email)")
        main_report_path = filtered_report
    else:
        # Write main report (unfiltered)
        with open(final_report, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(HEADERS)
            writer.writerows(all_rows)
        
        logging.info(f"📊 Combined report written to {final_report} (sorted by email)")
        main_report_path = final_report

    # Also write timestamped copy to exports directory
    exports_dir = output_dir / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    
    # Create timestamped filename with filter indication
    base_name = Path(final_report).stem  # "vault_access_report"
    extension = Path(final_report).suffix  # ".csv"
    
    # Add filter suffix to filename if filters were applied
    filter_suffix = "_filtered" if is_filtered else ""
    
    timestamped_filename = f"{base_name}_{RUN_TS}{filter_suffix}{extension}"
    timestamped_path = exports_dir / timestamped_filename
    
    with open(timestamped_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        writer.writerows(all_rows)
    
    logging.info(f"📊 Timestamped copy written to {timestamped_path}")
    
    # Cleanup old export files (keep same retention as backups)
    cleanup_old_exports(exports_dir, BACKUP_RETENTION)
    
    return main_report_path  # Return the path to the main report created

# Update the generate_summary_stats function to handle filtered data
def generate_summary_stats(final_report, filters_applied=False):
    """Generate and log summary statistics from the final report."""
    try:
        with open(final_report, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        unique_users = len(set(row['userUUID'] for row in rows if row['userUUID']))
        unique_emails = len(set(row['email'] for row in rows if row['email']))
        unique_vaults = len(set(row['vaultUUID'] for row in rows))
        direct_access = len([r for r in rows if r['assignment'] == 'Direct'])
        group_access = len([r for r in rows if r['assignment'].startswith('Group')])
        active_users = len([r for r in rows if r['status'] == 'ACTIVE'])
        inactive_users = len([r for r in rows if r['status'] != 'ACTIVE'])
        
        stats = {
            "total_entries": len(rows),
            "unique_users": unique_users,
            "unique_emails": unique_emails,
            "unique_vaults": unique_vaults,
            "direct_access": direct_access,
            "group_access": group_access,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "filters_applied": filters_applied
        }
        
        return stats
        
    except Exception as e:
        logging.warning(f"Could not generate final report statistics: {e}")
        return {"filters_applied": filters_applied}

def cleanup_old_logs(log_dir, retention):
    """
    Remove old log runs, keeping only the most recent N runs.
    A run includes: run-*.txt, issues-*.txt, issues-*.csv, stats-*.txt files.
    """
    try:
        # Get all timestamped log files and group by timestamp
        log_files = [f for f in log_dir.iterdir() if f.is_file()]
        
        # Extract timestamps from filenames (format: prefix-YYYYMMDD-HHMMSS.ext)
        run_timestamps = set()
        for file in log_files:
            # Match files like run-20240903-143052.txt, issues-20240903-143052.txt, etc.
            match = re.match(r'(run|issues|stats)-(\d{8}-\d{6})\.(txt|csv)$', file.name)
            if match:
                timestamp = match.group(2)
                run_timestamps.add(timestamp)
        
        # Sort timestamps (most recent first)
        sorted_timestamps = sorted(run_timestamps, reverse=True)
        
        if len(sorted_timestamps) <= retention:
            logging.info(f"📝 {len(sorted_timestamps)} log runs found, no cleanup needed (retention: {retention})")
            return
        
        # Identify timestamps to remove (beyond retention limit)
        timestamps_to_remove = sorted_timestamps[retention:]
        
        # Remove files for old timestamps
        removed_count = 0
        for timestamp in timestamps_to_remove:
            # Find all files for this timestamp
            pattern = f"*-{timestamp}.*"
            files_to_remove = list(log_dir.glob(pattern))
            
            for old_file in files_to_remove:
                try:
                    old_file.unlink()
                    removed_count += 1
                    logging.debug(f"📝 Removed old log: {old_file.name}")
                except Exception as e:
                    logging.warning(f"Failed to remove old log {old_file.name}: {e}")
        
        remaining_runs = len(sorted_timestamps) - len(timestamps_to_remove)
        logging.info(f"📝 Log cleanup complete: {remaining_runs} log runs retained, {removed_count} files removed")
        
    except Exception as e:
        logging.error(f"Failed to cleanup old logs: {e}")

def cleanup_logging():
    """Properly close all logging handlers and cleanup old logs."""
    # Close handlers first
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    
    # Then cleanup old log files
    cleanup_old_logs(LOG_DIR, LOG_RETENTION)

def clean_existing_reports(output_dir=OUTPUT_DIR):
    """
    Remove existing vault CSV files to force a fresh run.
    """
    existing_files = list(output_dir.glob("*.csv"))
    if not existing_files:
        logging.info("🧹 No existing vault CSV files to clean")
        return
    
    removed_count = 0
    for csv_file in existing_files:
        try:
            csv_file.unlink()
            removed_count += 1
            logging.debug(f"Removed: {csv_file.name}")
        except Exception as e:
            logging.warning(f"Failed to remove {csv_file.name}: {e}")
    
    logging.info(f"🧹 Cleaned {removed_count} existing vault CSV files for fresh run")

def is_auth_error(error_output: str) -> bool:
    """Check if the error indicates authentication timeout or issues."""
    auth_indicators = [
        "authorization timeout",
        "not currently signed in",
        "authentication required",
        "session expired",
        "unauthorized"
    ]
    return any(indicator in error_output.lower() for indicator in auth_indicators)

def save_progress(completed_vaults, total_vaults, failed_vaults=None):
    """Save progress to allow resuming interrupted runs."""
    progress_file = OUTPUT_DIR / f"progress_{RUN_TS}.json"
    progress = {
        "completed": len(completed_vaults),
        "total": total_vaults,
        "completed_vault_ids": completed_vaults,
        "failed_vault_ids": failed_vaults or [],
        "timestamp": datetime.now().isoformat(),
        "run_id": RUN_TS
    }
    with open(progress_file, "w") as f:
        json.dump(progress, f, indent=2)

def validate_environment():
    """Validate that required tools are available and configured."""
    try:
        result = subprocess.run(["op", "--version"], capture_output=True, text=True, check=True)
        logging.info(f"✅ Using 1Password CLI version: {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logging.error("❌ 1Password CLI (op) not found or not working")
        logging.error("   Install from: https://developer.1password.com/docs/cli/get-started/")
        sys.exit(1)
    
    try:
        # Check if signed in
        subprocess.run(["op", "account", "get"], capture_output=True, check=True)
        logging.info("✅ 1Password CLI authenticated")
    except subprocess.CalledProcessError:
        logging.error("❌ Not signed in to 1Password CLI")
        logging.error("   Run: op signin")
        sys.exit(1)

# Add this helper function near the top of the file, after the imports
def get_terminal_width():
    """Get the current terminal width, with fallback to 80 characters."""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except (ImportError, OSError):
        return 80  # fallback width

# Update the main function to use the returned report path
def main():
    # Initialize script start time
    SCRIPT_STATS["start_time"] = time.time()
    
    # Parse command line arguments
    args = parse_args()

    # Validate environment first
    validate_environment()
    
    # Update global settings based on args
    global ENABLE_BACKUPS, BACKUP_RETENTION
    ENABLE_BACKUPS = not args.no_backup
    BACKUP_RETENTION = args.backup_retention

    # Prepare filter information for statistics
    filters_info = {
        'vault_filter': args.vault_filter,
        'user_name_filter': args.user_name_filter,
        'user_email_filter': args.user_email_filter,
        'case_sensitive': args.case_sensitive
    }

    completed_vaults = []
    failed_vaults = []
    
    try:
        # Get and filter vaults
        all_vaults = get_vaults()
        vaults = filter_vaults(all_vaults, args.vault_filter, args.case_sensitive)
        
        update_script_stats(total_vaults=len(vaults))
        logging.info(f"Discovered {len(all_vaults)} total vaults, processing {len(vaults)} after filtering")

        # Backup existing vault CSV files before processing (if enabled)
        manage_backups()

        # Clean existing reports if fresh run requested
        if args.fresh_run:
            clean_existing_reports()

        for idx, vault in enumerate(vaults, 1):
            vault_id = vault['id']
            logging.info(f"Processing vault {idx}/{len(vaults)}: {vault['name']} ({vault_id})")
            
            success = process_vault(vault)
            if success:
                completed_vaults.append(vault_id)
                update_script_stats(completed_vaults=len(completed_vaults))
            else:
                failed_vaults.append(vault_id)
                update_script_stats(failed_vaults=len(failed_vaults))
                logging.warning(f"⚠️  Vault {vault['name']} failed but continuing with remaining vaults")
            
            # Save progress every 10 vaults
            if idx % 10 == 0:
                save_progress(completed_vaults, len(vaults), failed_vaults)

        # Final progress save
        save_progress(completed_vaults, len(vaults), failed_vaults)

        # Merge into one CSV with user filtering applied
        actual_report_path = combine_reports(
            user_name_filter=args.user_name_filter,
            user_email_filter=args.user_email_filter,
            case_sensitive=args.case_sensitive
        )

        # Generate final report statistics
        filters_applied = bool(args.user_name_filter or args.user_email_filter)
        report_stats = generate_summary_stats(actual_report_path, filters_applied)

        # Print comprehensive statistics (also saves to file)
        print_final_statistics(report_stats, filters_info)

        # Legacy logging info (keep for log files)
        if failed_vaults:
            logging.warning(f"⚠️  {len(failed_vaults)} vaults failed processing")
        logging.info(f"✅ Successfully processed {len(completed_vaults)}/{len(vaults)} vaults")

        logging.info(f"Logs: {FULL_LOG_PATH}")
        logging.info(f"Issues (WARN/ERROR): {ISSUES_LOG_PATH}")
        logging.info(f"Issues CSV: {ISSUES_CSV_PATH}")
        logging.info(f"Statistics: {STATS_LOG_PATH}")

    except AuthenticationError:
        logging.error("🛑 Stopping script due to authentication timeout")
        logging.error("   To resume: Run 'op signin' then restart the script")
        logging.error("   Progress has been saved - completed vaults will be skipped on restart")
        print_final_statistics(filters_info=filters_info)  # Show stats even on auth failure
        sys.exit(2)
    except KeyboardInterrupt:
        logging.info("🛑 Script interrupted by user")
        print_final_statistics(filters_info=filters_info)  # Show stats even on interruption
        sys.exit(1)
    except Exception as e:
        logging.error(f"❌ Unexpected error: {e}")
        print_final_statistics(filters_info=filters_info)  # Show stats even on error
        sys.exit(1)
    finally:
        cleanup_logging()

# Update save_statistics_to_file to show the correct main report filename
def save_statistics_to_file(report_stats=None, filters_info=None):
    """Save comprehensive script statistics to a file."""
    end_time = time.time()
    duration = end_time - SCRIPT_STATS["start_time"]
    
    # Update final stats
    update_script_stats(
        end_time=end_time,
        warnings_count=stats_handler.warning_count,
        errors_count=stats_handler.error_count
    )
    
    # Determine the main report filename based on filters
    is_filtered = bool(filters_info and (filters_info.get('user_name_filter') or filters_info.get('user_email_filter')))
    main_report_name = "vault_access_report_filtered.csv" if is_filtered else FINAL_REPORT
    
    # Get terminal width for dynamic separator
    width = get_terminal_width()
    separator = "=" * width
    
    # Create the statistics content
    stats_content = []
    stats_content.append(separator)
    stats_content.append("📊 SCRIPT EXECUTION SUMMARY")
    stats_content.append(separator)

    # Filter information (if any)
    if filters_info and any(filters_info.values()):
        stats_content.append("🔍 Filters Applied:")
        if filters_info.get('vault_filter'):
            stats_content.append(f"   Vault name: {filters_info['vault_filter']}")
        if filters_info.get('user_name_filter'):
            stats_content.append(f"   User name: {filters_info['user_name_filter']}")
        if filters_info.get('user_email_filter'):
            stats_content.append(f"   User email: {filters_info['user_email_filter']}")
        if filters_info.get('case_sensitive'):
            stats_content.append("   Case-sensitive matching: Yes")
        stats_content.append("")

    # Timing information
    stats_content.append("🕒 Execution Time:")
    stats_content.append(f"   Start: {datetime.fromtimestamp(SCRIPT_STATS['start_time']).strftime('%Y-%m-%d %H:%M:%S')}")
    stats_content.append(f"   End:   {datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')}")
    stats_content.append(f"   Duration: {format_duration(duration)}")
    
    # Vault processing statistics
    stats_content.append("\n🏦 Vault Processing:")
    stats_content.append(f"   Total vaults discovered: {SCRIPT_STATS['total_vaults']}")
    stats_content.append(f"   Successfully processed: {SCRIPT_STATS['completed_vaults']}")
    stats_content.append(f"   Skipped (already done): {SCRIPT_STATS['skipped_vaults']}")
    stats_content.append(f"   Failed: {SCRIPT_STATS['failed_vaults']}")
    
    # Processing rate
    if duration > 0:
        vaults_per_minute = (SCRIPT_STATS['completed_vaults'] + SCRIPT_STATS['skipped_vaults']) / (duration / 60)
        stats_content.append(f"   Processing rate: {vaults_per_minute:.1f} vaults/minute")
    
    # User statistics
    stats_content.append("\n👥 User Data Collected:")
    stats_content.append(f"   Direct vault users: {SCRIPT_STATS['total_users']}")
    stats_content.append(f"   Group members: {SCRIPT_STATS['total_group_members']}")
    stats_content.append(f"   Total access entries: {SCRIPT_STATS['total_users'] + SCRIPT_STATS['total_group_members']}")
    
    # Final report statistics (if available)
    if report_stats:
        filter_note = " (after filtering)" if report_stats.get('filters_applied') else ""
        stats_content.append(f"\n📋 Final Report Analysis{filter_note}:")
        stats_content.append(f"   Total entries in report: {report_stats.get('total_entries', 'N/A')}")
        stats_content.append(f"   Unique users: {report_stats.get('unique_users', 'N/A')}")
        stats_content.append(f"   Unique email addresses: {report_stats.get('unique_emails', 'N/A')}")
        stats_content.append(f"   Vaults in report: {report_stats.get('unique_vaults', 'N/A')}")
        stats_content.append(f"   Direct access entries: {report_stats.get('direct_access', 'N/A')}")
        stats_content.append(f"   Group access entries: {report_stats.get('group_access', 'N/A')}")
        stats_content.append(f"   Active users: {report_stats.get('active_users', 'N/A')}")
        stats_content.append(f"   Inactive users: {report_stats.get('inactive_users', 'N/A')}")
    
    # Error and warning statistics
    stats_content.append("\n⚠️ Issues Summary:")
    stats_content.append(f"   Warnings: {SCRIPT_STATS['warnings_count']}")
    stats_content.append(f"   Errors: {SCRIPT_STATS['errors_count']}")
    
    # Success rate
    total_processed = SCRIPT_STATS['completed_vaults'] + SCRIPT_STATS['failed_vaults']
    if total_processed > 0:
        success_rate = (SCRIPT_STATS['completed_vaults'] / total_processed) * 100
        stats_content.append(f"\n✅ Success Rate: {success_rate:.1f}%")
    
    # File locations
    stats_content.append("\n📁 Output Files:")
    stats_content.append(f"   Main report: {main_report_name}")
    filter_suffix = "_filtered" if is_filtered else ""
    stats_content.append(f"   Timestamped copy: vault_reports/exports/vault_access_report_{RUN_TS}{filter_suffix}.csv")
    stats_content.append(f"   Full log: {FULL_LOG_PATH}")
    stats_content.append(f"   Issues log: {ISSUES_LOG_PATH}")
    stats_content.append(f"   Issues CSV: {ISSUES_CSV_PATH}")
    stats_content.append(f"   Statistics: {STATS_LOG_PATH}")
    
    if SCRIPT_STATS['warnings_count'] > 0 or SCRIPT_STATS['errors_count'] > 0:
        stats_content.append("\n💡 Tip: Check the issues log for details on warnings and errors")
    
    stats_content.append(separator)
    
    # Write to file
    try:
        with open(STATS_LOG_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(stats_content))
        logging.info(f"📊 Statistics saved to {STATS_LOG_PATH}")
    except Exception as e:
        logging.warning(f"Failed to save statistics file: {e}")
    
    return stats_content

def print_final_statistics(report_stats=None, filters_info=None):
    """Print comprehensive script statistics to console and save to file."""
    # Save to file and get the content
    stats_content = save_statistics_to_file(report_stats, filters_info)
    
    # Print to console (same content)
    for line in stats_content:
        print(line)

# Update the main function to use the returned report path
def main():
    # Initialize script start time
    SCRIPT_STATS["start_time"] = time.time()
    
    # Parse command line arguments
    args = parse_args()

    # Validate environment first
    validate_environment()
    
    # Update global settings based on args
    global ENABLE_BACKUPS, BACKUP_RETENTION
    ENABLE_BACKUPS = not args.no_backup
    BACKUP_RETENTION = args.backup_retention

    # Prepare filter information for statistics
    filters_info = {
        'vault_filter': args.vault_filter,
        'user_name_filter': args.user_name_filter,
        'user_email_filter': args.user_email_filter,
        'case_sensitive': args.case_sensitive
    }

    completed_vaults = []
    failed_vaults = []
    
    try:
        # Get and filter vaults
        all_vaults = get_vaults()
        vaults = filter_vaults(all_vaults, args.vault_filter, args.case_sensitive)
        
        update_script_stats(total_vaults=len(vaults))
        logging.info(f"Discovered {len(all_vaults)} total vaults, processing {len(vaults)} after filtering")

        # Backup existing vault CSV files before processing (if enabled)
        manage_backups()

        # Clean existing reports if fresh run requested
        if args.fresh_run:
            clean_existing_reports()

        for idx, vault in enumerate(vaults, 1):
            vault_id = vault['id']
            logging.info(f"Processing vault {idx}/{len(vaults)}: {vault['name']} ({vault_id})")
            
            success = process_vault(vault)
            if success:
                completed_vaults.append(vault_id)
                update_script_stats(completed_vaults=len(completed_vaults))
            else:
                failed_vaults.append(vault_id)
                update_script_stats(failed_vaults=len(failed_vaults))
                logging.warning(f"⚠️  Vault {vault['name']} failed but continuing with remaining vaults")
            
            # Save progress every 10 vaults
            if idx % 10 == 0:
                save_progress(completed_vaults, len(vaults), failed_vaults)

        # Final progress save
        save_progress(completed_vaults, len(vaults), failed_vaults)

        # Merge into one CSV with user filtering applied
        actual_report_path = combine_reports(
            user_name_filter=args.user_name_filter,
            user_email_filter=args.user_email_filter,
            case_sensitive=args.case_sensitive
        )

        # Generate final report statistics
        filters_applied = bool(args.user_name_filter or args.user_email_filter)
        report_stats = generate_summary_stats(actual_report_path, filters_applied)

        # Print comprehensive statistics (also saves to file)
        print_final_statistics(report_stats, filters_info)

        # Legacy logging info (keep for log files)
        if failed_vaults:
            logging.warning(f"⚠️  {len(failed_vaults)} vaults failed processing")
        logging.info(f"✅ Successfully processed {len(completed_vaults)}/{len(vaults)} vaults")

        logging.info(f"Logs: {FULL_LOG_PATH}")
        logging.info(f"Issues (WARN/ERROR): {ISSUES_LOG_PATH}")
        logging.info(f"Issues CSV: {ISSUES_CSV_PATH}")
        logging.info(f"Statistics: {STATS_LOG_PATH}")

    except AuthenticationError:
        logging.error("🛑 Stopping script due to authentication timeout")
        logging.error("   To resume: Run 'op signin' then restart the script")
        logging.error("   Progress has been saved - completed vaults will be skipped on restart")
        print_final_statistics(filters_info=filters_info)  # Show stats even on auth failure
        sys.exit(2)
    except KeyboardInterrupt:
        logging.info("🛑 Script interrupted by user")
        print_final_statistics(filters_info=filters_info)  # Show stats even on interruption
        sys.exit(1)
    except Exception as e:
        logging.error(f"❌ Unexpected error: {e}")
        print_final_statistics(filters_info=filters_info)  # Show stats even on error
        sys.exit(1)
    finally:
        cleanup_logging()

if __name__ == "__main__":
    main()

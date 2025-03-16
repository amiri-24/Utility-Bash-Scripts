#!/bin/bash

# Configuration
BACKUP_DIR="/backup/mytestbackup"
REMOTE_DIR="/backup/testbackup"
REMOTE_USER="root"
REMOTE_HOST="192.168.1.1"
REMOTE_PORT="22"
EMAIL="yourmail@domain.com"
LOG_DIR="/backup/testbackup"
LOG_FILE="$LOG_DIR/log-$(date +%F).txt"
SSH_KEY="/root/.ssh/transfer_data"
THROTTLE_RATE="2000000" # Throttle bandwidth limit in KB/s for scp to reduce IO load
STOP_FILE="/tmp/stopbk2tmp"  # Shortened stop file name

# Ensure backup and log directories exist
mkdir -p "$BACKUP_DIR"
mkdir -p "$LOG_DIR"

# Initialize log file with start time
echo "Backup Log - $(date)" > "$LOG_FILE"
echo "Script started at: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# Function to log and echo messages
log_message() {
  echo "$1" | tee -a "$LOG_FILE"
}

# Function to check if the stop flag exists
check_stop() {
  if [ -f "$STOP_FILE" ]; then
    log_message "Stop file detected. Exiting process and cleaning up."
    exit 1
  fi
}

# Function to create backup for a user
backup_user() {
  local user=$1
  
  # Check if stop signal is given
  check_stop

  # Extract user's home directory using whmapi1
  USER_DIR=$(whmapi1 accountsummary user="$user" | grep -i 'partition' | awk '{print $2}')
  if [ -z "$USER_DIR" ]; then
    log_message "Home directory for $user not found via whmapi1, skipping..."
    return 1
  fi

  log_message "Found home directory for $user: $USER_DIR"
  BACKUP_FILE="$BACKUP_DIR/cpmove-${user}.tar.gz"

  # Create backup
  /scripts/pkgacct "$user" "$BACKUP_DIR" >> "$LOG_FILE" 2>&1

  # Ensure the backup file was created
  if [ ! -f "$BACKUP_FILE" ]; then
    log_message "Backup file for $user not created, skipping..."
    return 1
  fi

  # Check the integrity of the backup file
  md5sum "$BACKUP_FILE" > "$BACKUP_FILE.md5"
  if ! md5sum -c "$BACKUP_FILE.md5" &>/dev/null; then
    log_message "Backup integrity check for $user failed"
    return 1
  fi

  log_message "Backup for $user succeeded"

  # Transfer backup to remote server
  scp -i "$SSH_KEY" -P "$REMOTE_PORT" -l "$THROTTLE_RATE" "$BACKUP_FILE" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/" >> "$LOG_FILE" 2>&1
  if [ $? -eq 0 ]; then
    # Delete local backup after successful transfer
    rm -f "$BACKUP_FILE" "$BACKUP_FILE.md5"
    log_message "Transfer for $user succeeded"
  else
    log_message "Transfer for $user failed"
    return 1
  fi

  return 0
}

# Function to clean up files if the process is stopped
cleanup_files() {
  log_message "Cleaning up temporary files..."
  rm -f "$BACKUP_DIR/cpmove-*.tar.gz"
  rm -f "$BACKUP_DIR/cpmove-*.tar.gz.md5"
}

# Trap SIGINT (Ctrl+C) to clean up files and exit the script
trap 'cleanup_files; exit 1' SIGINT SIGTERM

# Create an alias for stopping the backup process (for simplicity)
alias stopbk2tmp="touch /tmp/stopbk2tmp && echo 'Backup process stopped.'"

# Loop through all cPanel users and back them up
for user in $(ls /var/cpanel/users); do
  log_message "Processing user: $user"

  # Check if stop flag is set
  check_stop

  backup_user "$user"
  
  # Log spacing between each user
  echo "" >> "$LOG_FILE"
done

# Log the end time
echo "Script ended at: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"

# Email the log file
if command -v mail &>/dev/null; then
  mail -s "Backup Log - $(date)" "$EMAIL" < "$LOG_FILE"
else
  log_message "Mail command not found, unable to send log via email."
fi

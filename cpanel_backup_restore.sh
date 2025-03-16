#!/bin/bash

# Check for root access
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

# Function for confirmation from user
confirm() {
    read -p "$1 (y/n): " choice
    case "$choice" in 
      y|Y ) echo "Continuing...";;
      n|N ) echo "Exiting."; exit 1;;
      * ) echo "Invalid response."; confirm "$1";;
    esac
}

# Function to get backup directory
get_backup_dir() {
    while true; do
        read -p "Please enter the backup directory path: " BACKUP_DIR
        if [[ -d "$BACKUP_DIR" ]]; then
            echo "Backup directory: $BACKUP_DIR"
            break
        else
            echo "Invalid directory. Please try again."
        fi
    done
}

# Function to get log directory
get_log_dir() {
    while true; do
        read -p "Please enter the log directory path (it will be created if it doesn't exist): " LOG_DIR
        mkdir -p "$LOG_DIR"  # Create directory if it doesn't exist
        if [[ -d "$LOG_DIR" ]]; then
            echo "Log directory: $LOG_DIR"
            break
        else
            echo "Invalid directory. Please try again."
        fi
    done
}

# Function to get transfer method and port
get_transfer_method() {
    while true; do
        read -p "Do you want to use SCP or FTP for transfer? (scp/ftp): " METHOD
        if [[ "$METHOD" == "scp" || "$METHOD" == "ftp" ]]; then
            read -p "Please enter the port (default 22 for SCP, 21 for FTP): " PORT
            [[ -z "$PORT" ]] && PORT=22  # Default to 22 if empty
            break
        else
            echo "Invalid option. Please enter 'scp' or 'ftp'."
        fi
    done
}

# Function to get FTP connection info
get_ftp_info() {
    read -p "Please enter the FTP server address: " FTP_SERVER
    read -p "Please enter the FTP username: " FTP_USER
    read -sp "Please enter the FTP password: " FTP_PASS
    echo
}

# Function to get SCP connection info
get_scp_info() {
    read -p "Please enter the SCP server address: " SCP_SERVER
    read -p "Please enter the SCP username: " SCP_USER
    read -sp "Please enter the SCP password: " SCP_PASS
    echo
}

# Backup function
backup() {
    DATE=$(date +%F)
    BACKUP_LOG="$LOG_DIR/backup_$DATE.log"
    echo "Starting backup process..." | tee -a "$BACKUP_LOG"

    mkdir -p "$BACKUP_DIR/$DATE"
    
    backup_config() {
        local description="$1"
        local command="$2"
        local output_file="$3"
        
        confirm "$description"
        eval "$command" > "$BACKUP_DIR/$DATE/$output_file" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            echo "$description backup created and stored in $BACKUP_DIR/$DATE/$output_file." | tee -a "$BACKUP_LOG"
        else
            echo "Error backing up $description." | tee -a "$BACKUP_LOG"
        fi
    }

    # Backup different configurations
    backup_config "Basic WebHost Manager Setup" "/usr/local/cpanel/bin/whmapi1 get_basic_config" "basic_config.json"
    backup_config "Tweak Settings" "/usr/local/cpanel/bin/whmapi1 get_tweaksettings" "tweak_settings.json"
    backup_config "Apache mod_userdir Tweak" "/usr/local/cpanel/bin/whmapi1 get_mod_userdir_tweak" "mod_userdir_tweak.json"
    backup_config "cPHulk Brute Force Protection" "/usr/local/cpanel/bin/whmapi1 get_cphulk_config" "cphulk_config.json"
    backup_config "ModSecurity Configuration" "/usr/local/cpanel/bin/whmapi1 get_modsecurity_config" "modsecurity_config.json"
    backup_config "Password Strength Configuration" "/usr/local/cpanel/bin/whmapi1 get_password_strength" "password_strength.json"
    backup_config "Apache Configuration" "/usr/local/cpanel/bin/whmapi1 get_apache_config" "apache_config.json"
    backup_config "Exim Configuration Manager" "/usr/local/cpanel/bin/whmapi1 get_exim_config" "exim_config.json"
    backup_config "FTP Server Configuration" "/usr/local/cpanel/bin/whmapi1 get_ftpserver_config" "ftpserver_config.json"
    backup_config "DNS Server Config" "/usr/local/cpanel/bin/whmapi1 get_dns_config" "dns_config.json"
    backup_config "Easy Apache Config" "/usr/local/cpanel/bin/whmapi1 get_ea4_profile" "easy_apache_config.json"
    
    # Check and backup CSF if installed
    if command -v csf > /dev/null; then
        backup_config "CSF Config" "cat /etc/csf/csf.conf" "csf_config.txt"
    else
        echo "CSF is not installed." | tee -a "$BACKUP_LOG"
    fi

    # Check and backup Litespeed if installed
    if [[ -d "/usr/local/lsws" ]]; then
        backup_config "Litespeed Config" "cat /usr/local/lsws/conf/httpd_config.conf" "litespeed_config.txt"
    else
        echo "Litespeed is not installed." | tee -a "$BACKUP_LOG"
    fi

    # Check and backup Imunify if installed
    if command -v imunify360-agent > /dev/null; then
        backup_config "Imunify Config" "/opt/alt/python39/bin/imunify360-agent config display" "imunify_config.txt"
    else
        echo "Imunify is not installed." | tee -a "$BACKUP_LOG"
    fi

    echo "Backup process completed." | tee -a "$BACKUP_LOG"
    
    # Transfer files
    if [[ "$METHOD" == "ftp" ]]; then
        get_ftp_info
        echo "Transferring files to FTP server..." | tee -a "$BACKUP_LOG"
        # FTP transfer code (using curl or lftp) goes here
        # Example using curl:
        # curl -T "$BACKUP_DIR/$DATE/*" -u "$FTP_USER:$FTP_PASS" "ftp://$FTP_SERVER:$PORT/"
    else
        get_scp_info
        echo "Transferring files to SCP server..." | tee -a "$BACKUP_LOG"
        # SCP transfer code goes here
        # Example using sshpass for password:
        # sshpass -p "$SCP_PASS" scp -P "$PORT" "$BACKUP_DIR/$DATE/*" "$SCP_USER@$SCP_SERVER:/path/to/destination/"
    fi
}

# Restore function
restore() {
    DATE=$(date +%F)
    RESTORE_LOG="$LOG_DIR/restore_$DATE.log"
    echo "Starting restore process..." | tee -a "$RESTORE_LOG"

    restore_config() {
        local description="$1"
        local command="$2"
        local input_file="$3"
        
        confirm "$description"
        if [[ -f "$BACKUP_DIR/$DATE/$input_file" ]]; then
            eval "$command" < "$BACKUP_DIR/$DATE/$input_file"
            echo "$description restored successfully." | tee -a "$RESTORE_LOG"
        else
            echo "Backup file $input_file not found." | tee -a "$RESTORE_LOG"
        fi
    }

    # Restore configurations
    restore_config "Basic WebHost Manager Setup" "/usr/local/cpanel/bin/whmapi1 set_basic_config" "basic_config.json"
    restore_config "Tweak Settings" "/usr/local/cpanel/bin/whmapi1 set_tweaksettings" "tweak_settings.json"
    restore_config "Apache mod_userdir Tweak" "/usr/local/cpanel/bin/whmapi1 set_mod_userdir_tweak" "mod_userdir_tweak.json"
    restore_config "cPHulk Brute Force Protection" "/usr/local/cpanel/bin/whmapi1 set_cphulk_config" "cphulk_config.json"
    restore_config "ModSecurity Configuration" "/usr/local/cpanel/bin/whmapi1 set_modsecurity_config" "modsecurity_config.json"
    restore_config "Password Strength Configuration" "/usr/local/cpanel/bin/whmapi1 set_password_strength" "password_strength.json"
    restore_config "Apache Configuration" "/usr/local/cpanel/bin/whmapi1 set_apache_config" "apache_config.json"
    restore_config "Exim Configuration Manager" "/usr/local/cpanel/bin/whmapi1 set_exim_config" "exim_config.json"
    restore_config "FTP Server Configuration" "/usr/local/cpanel/bin/whmapi1 set_ftpserver_config" "ftpserver_config.json"
    restore_config "DNS Server Config" "/usr/local/cpanel/bin/whmapi1 set_dns_config" "dns_config.json"
    restore_config "Easy Apache Config" "/usr/local/cpanel/bin/whmapi1 apply_ea4_profile" "easy_apache_config.json"
    
    # Check and restore CSF if backed up
    if [[ -f "$BACKUP_DIR/$DATE/csf_config.txt" ]]; then
        restore_config "CSF Config" "cp -f $BACKUP_DIR/$DATE/csf_config.txt /etc/csf/csf.conf && csf -r" "csf_config.txt"
    else
        echo "CSF backup file not found." | tee -a "$RESTORE_LOG"
    fi

    # Check and restore Litespeed if backed up
    if [[ -f "$BACKUP_DIR/$DATE/litespeed_config.txt" ]]; then
        restore_config "Litespeed Config" "cp -f $BACKUP_DIR/$DATE/litespeed_config.txt /usr/local/lsws/conf/httpd_config.conf && service lsws restart" "litespeed_config.txt"
    else
        echo "Litespeed backup file not found." | tee -a "$RESTORE_LOG"
    fi

    # Check and restore Imunify if backed up
    if [[ -f "$BACKUP_DIR/$DATE/imunify_config.txt" ]]; then
        restore_config "Imunify Config" "/opt/alt/python39/bin/imunify360-agent config update" "imunify_config.txt"
    else
        echo "Imunify backup file not found." | tee -a "$RESTORE_LOG"
    fi

    echo "Restore process completed." | tee -a "$RESTORE_LOG"
}

# Check input arguments
if [[ $# -eq 0 ]]; then
    read -p "Do you want to backup or restore? (backup/restore): " ACTION
else
    ACTION=$1
fi

# Process based on input
if [[ "$ACTION" == "backup" ]]; then
    get_backup_dir
    get_log_dir
    get_transfer_method
    backup
elif [[ "$ACTION" == "restore" ]]; then
    get_backup_dir
    get_log_dir
    restore
else
    echo "Invalid operation. Please enter 'backup' or 'restore'."
    exit 1
fi

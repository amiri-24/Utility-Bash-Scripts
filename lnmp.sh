#!/bin/bash
set -e

# Define variables
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"  
RESET="\033[0m"
CONFIG_DIRECTORY="/var/log/taniweb"
CONFIG_FILE="$CONFIG_DIRECTORY/server_setup_done"
CONFIG_DATA="$CONFIG_DIRECTORY/server_setup_data"
DEFAULT_MailLOG="$CONFIG_DIRECTORY/email_setup.log"
LOG_FILE="$CONFIG_DIRECTORY/server_setup.log"
FIRST_ENTRY_FLAG="$CONFIG_DIRECTORY/first_entry.flag"
DEFAULT_BASE_DOMAIN="miniservice.com"
DEFAULT_HOSTNAME="server"
DEFAULT_SERVER_DOMAIN="$DEFAULT_HOSTNAME.$DEFAULT_BASE_DOMAIN"
DEFAULT_DB_DOMAIN="database.$DEFAULT_BASE_DOMAIN"
DEFAULT_MAIL_DOMAIN="mailbox.$DEFAULT_BASE_DOMAIN"
DEFAULT_INSTALL_PHP_VERSIONS=("8.4" "8.3" "8.1" "7.4")
#DEFAULT_INSTALL_PHP_VERSIONS=("8.4" "8.3" "8.2" "8.1" "7.4")
DEFAULT_PHP_VERSION="8.1"
DEFAULT_PUBLIC_IP="109.122.240.46"
DEFAULT_RESOLVER1="1.1.1.1"
DEFAULT_RESOLVER2="8.8.8.8"
DEFAULT_APACHE_PORT="8080"
DEFAULT_INTERFACE=$(ip -o link | awk -F': ' '{print $2}' | grep -v "lo" | head -n 1)
DEFAULT_NETPLAN_CONFIG=$(ls /etc/netplan/ | head -n 1) # First Netplan file as default
DEFAULT_NANESERVER1="ns1"
DEFAULT_NANESERVER2="ns2"
DEFAULT_LETSENCRYPT="0"
DEFAULT_ADMIN="admin"
DEFAULT_FTP_PASS="MojT4Ba@123n"
DEFAULT_FAVICON="https://www.mojtaba-amiri.ir/files/scripts_data/favicon.ico"
DEFAULT_SOURCEGUARDIAN="https://www.mojtaba-amiri.ir/files/scripts_data/loaders.linux-x86_64.zip"
ACC_INFO_FILE="account_info.txt"




save_and_display() {
    local output="[DEBUG] $1"
    echo "$output"  # Display output in terminal
    # Check for the flag file to determine if this is the first call
    if [ ! -f "$FIRST_ENTRY_FLAG" ]; then
        echo "$1" > "$CONFIG_DATA"  # First call: overwrite the file
        touch "$FIRST_ENTRY_FLAG"  # Create flag file to indicate first call has occurred
    else
        echo "$1" >> "$CONFIG_DATA"  # Subsequent calls: append to the file
    fi
}


# Function to load the configuration from the given file path
load_config() {
    local config_file="$1"  # Get the file path as a parameter
    # Check if the file exists
    if [[ ! -f "$config_file" ]]; then
        echo "Error: Config file '$config_file' not found!"
        return 1  # Exit with error code if file doesn't exist
    fi
    # Read the config file line by line
    while IFS=":" read -r key value; do
        # Trim leading/trailing spaces
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        # Check if the value contains commas (indicating an array)
        if [[ "$value" == *","* ]]; then
            # Convert comma-separated string to an array by replacing commas with spaces
            IFS=',' read -r -a arr <<< "$value"
            # Export the array as a string
            export "${key}=${arr[*]}"
            # Correctly display the array using indirect expansion
            echo "Loaded array for $key: ${arr[*]}"
        else
            # Export the value to make it accessible outside the function
            export "$key=$value"
            echo "Loaded $key: $value"
        fi
    done < "$config_file"
}



# Function to generate a random password
generate_password() {
    openssl rand -base64 12
}

# Function to confirm user input (yes/no)
confirm() {
    local prompt=$1
    while true; do
        read -p "$prompt (yes/no): " choice
        case "$choice" in
            y|Y|yes|Yes|YES)
                return 0 ;; # Confirmed
            n|N|no|No|NO)
                return 1 ;; # Rejected
            *)
                echo "Please respond with 'yes' or 'no'."
                ;;
        esac
    done
}



# Function to check if a port is in use
check_port_in_use() {
    local port=$1
    if sudo netstat -tuln | grep -q ":$port "; then
        echo "Port $port is already in use."
        return 0
    else
        echo "Port $port is available."
        return 1
    fi
}










# Function to update DNS resolverss in Netplan
update_dns_resolvers() {
    local config_file=$1
    local resolver1=$2
    local resolver2=$3
    local interface=$4

    if [ ! -f "$config_file" ]; then
        cat > "$config_file" <<EOF
network:
  ethernets:
    $interface:
      addresses:
        - $public_ip/24
      nameservers:
        addresses:
          - $resolver1
          - $resolver2
  version: 2
EOF
    fi

# Check if yq is installed
if ! command -v yq &> /dev/null; then
        sudo apt install snapd -y
        sudo add-apt-repository ppa:rmescandon/yq -y
        sudo apt install yq -y
fi

    # Update nameservers using yq
if grep -q "nameservers:" "$config_file"; then
        sudo yq e ".network.ethernets.\"$interface\".nameservers.addresses = [\"$resolver1\", \"$resolver2\"]" -i "$config_file"
    else
        sudo yq e ".network.ethernets.\"$interface\" += {nameservers: {addresses: [\"$resolver1\", \"$resolver2\"]}}" -i "$config_file"
fi

    sudo chmod 600 "$config_file"
    sudo chown root:root "$config_file"
    sudo netplan apply
    sudo systemctl restart systemd-resolved
    sudo resolvectl flush-caches
    echo "DNS resolvers updated successfully in $config_file."
}



# Function to set up firewall rules
setup_firewall_rules() {
    for port in "${allowed_ports[@]}"; do
        sudo ufw allow "$port/tcp"
        echo "Port $port/tcp allowed in UFW."
    done
    sudo ufw allow "53/tcp"
    sudo ufw allow "53/udp"  
    sudo ufw enable
}

# Function to validate domain
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "Invalid domain name: $domain"
        return 1
    fi
    return 0
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "Invalid IP address: $ip"
        return 1
    fi
    return 0
}

# Function to validate port
validate_port() {
    local port=$1
    if [[ ! "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "Invalid port number: $port"
        return 1
    fi
    return 0
}

# Function to check if an element exists in an array
validate_input() {
    local element="$1"
    shift
    local array=("$@")
    for e in "${array[@]}"; do
        if [[ "$e" == "$element" ]]; then
            return 0
        fi
    done
    return 1
}



# Function to gather domains from the BIND directory
gather_domains() {
    # Fixed path to the BIND directory
    local bind_dir="/etc/bind"

    # Check if the BIND directory exists
    if [ ! -d "$bind_dir" ]; then
        # Print an error message and exit if the directory doesn't exist
        echo "Error: $bind_dir does not exist!"
        exit 1  # Exit the script with an error code
    fi

    # Initialize an empty array for storing active DOMAINS_LIST
    local domains_list=()

    # Loop through files that start with db. and are not in the exclusion list
    for file in $(ls "$bind_dir" | grep '^db\.' | grep -Ev 'db\.0|db\.127|db\.255|db\.empty|db\.local'); do
        # Remove the "db." prefix from the file name to get the domain name
        local domain=$(echo "$file" | sed 's/^db\.//')

        # Add both the domain and its www subdomain to the array
        domains_list+=("$domain" "www.$domain")
    done

    # Return the array as a space-separated string
    echo "${domains_list[@]}"
}


# Function to get all usernames in the system
get_all_usernames() {
    # Get all usernames from /etc/passwd and return them as an array
    local usernames=()
    IFS=' ' read -r -a usernames <<< "$(cut -d: -f1 /etc/passwd | paste -sd ' ')"
    
    # Return the array of usernames
    echo "${usernames[@]}"
}



# Function to get allowed usernames (users with UID >= 1000, excluding 'nobody', and adding 'root')
get_allowed_usernames() {
    # Get all usernames with UID >= 1000, excluding 'nobody', and add 'root'
    local allowed_usernames=()
    allowed_usernames=($(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd))

    # Return the array of allowed usernames
    echo "${allowed_usernames[@]}"
}




# Function to select a network interface
select_network_interface() {
  # Get the list of network interfaces
  INTERFACES=$(ip -o link | awk -F': ' '{print $2}' | grep -v "lo")

  # Display network interfaces with numbered list
  echo "Available network interfaces:"
  i=1
  for interface in $INTERFACES; do
    echo "$i) $interface"
    ((i++))
  done

  # Ask user to select a network interface or press Enter for default
  while true; do
    read -p "Select a network interface (Enter number or press Enter for default : $DEFAULT_INTERFACE )" network_selection

    # If input is empty (Enter pressed), select the default (first interface)
    if [[ -z "$network_selection" ]]; then
      selected_interface=$(echo "$INTERFACES" | head -n 1)
	  echo "selected interface : $selected_interface"
      break
    # If input is a valid number and within range, select the interface
    elif [[ "$network_selection" =~ ^[0-9]+$ ]] && (( network_selection >= 1 && network_selection <= $(echo "$INTERFACES" | wc -l) )); then
      selected_interface=$(echo "$INTERFACES" | sed -n "${network_selection}p")
	  echo "selected interface : $selected_interface"
      break
    else
      # Invalid selection, prompt user again
      echo "Invalid selection, please enter a valid number."
    fi
  done
 		echo ""

}



# Function to select a Netplan configuration file
select_netplan_config() {
  # Get the list of Netplan configuration files
  NETPLAN_FILES=$(ls /etc/netplan/)

  # Display Netplan files with numbered list
  echo "Available Netplan configuration files:"
  i=1
  for file in $NETPLAN_FILES; do
    echo "$i) $file"
    ((i++))
  done

  # Ask user to select a Netplan file or press Enter for default
  while true; do
    read -p "Select a network interface (Enter number or press Enter for default : $DEFAULT_NETPLAN_CONFIG ): " network_selection

    # If input is empty (Enter pressed), select the default (first file)
    if [[ -z "$netplan_selection" ]]; then
      netplan_config_file=$(echo "$NETPLAN_FILES" | head -n 1)
	  echo "selected config file : $netplan_config_file"
      break
    # If input is a valid number and within range, select the file
    elif [[ "$netplan_selection" =~ ^[0-9]+$ ]] && (( netplan_selection >= 1 && netplan_selection <= $(echo "$NETPLAN_FILES" | wc -l) )); then
      netplan_config_file=$(echo "$NETPLAN_FILES" | sed -n "${netplan_selection}p")
	  echo "selected config file : $netplan_config_file"
      break
    else
      # Invalid selection, prompt user again
      echo "Invalid selection, please enter a valid number."
    fi
  done
 		echo ""

}



create_web_files() {
    local domain="$1"
    local username="$2"
    local document_root="$3"
    local php_version="$4"
    
    # Check if document root exists
    if [ ! -d "$document_root" ]; then
        echo "Directory $document_root not found."
        return 1
    fi
    
	# Create required files with domain and user information
	echo "<!DOCTYPE html><html><head><title>Welcome to $domain</title><link rel='icon' href='https://$domain/favicon.ico'></head><body><h1>Welcome to $domain</h1><p>User: $username</p><p>PHP Version: $php_version</p></body></html>" > "$document_root/index.php"

	echo "<!DOCTYPE html><html><head><title>Welcome to $domain</title><link rel='icon' href='https://$domain/favicon.ico'></head><body><h1>Welcome to $domain</h1><p>User: $username</p><p>PHP Version: $php_version</p></body></html>" > "$document_root/index.html"

	echo "<!DOCTYPE html><html><head><title>404 Not Found</title><link rel='icon' href='favicon.ico'></head><body><h1>404 - Page Not Found</h1></body></html>" > "$document_root/404.html"

	echo "<!DOCTYPE html><html><head><title>403 Forbidden</title><link rel='icon' href='favicon.ico'></head><body><h1>403 - Access Forbidden</h1></body></html>" > "$document_root/403.html"

	echo "<!DOCTYPE html><html><head><title>500 Internal Server Error</title><link rel='icon' href='favicon.ico'></head><body><h1>500 - Internal Server Error</h1></body></html>" > "$document_root/500.html"
    
    # Download or create favicon.ico
    if curl -o "$document_root/favicon.ico" "$DEFAULT_FAVICON"; then
        echo "favicon.ico downloaded successfully."
    else
        touch "$document_root/favicon.ico"
        echo "Failed to download favicon.ico. An empty file has been created."
    fi
    
	sudo chown -R "$username":"$username" "$document_root/" 
	sudo chmod -R 755 "$document_root/"
    echo "All files for domain $domain have been created."
}





# Function to configure Roundcube
configure_roundcube() {
    if confirm "Do you want to configure Roundcube automatically?"; then

        sudo systemctl reload apache2
    else
        echo "Roundcube configuration skipped."
    fi
}


# Function to configure phpMyAdmin
configure_phpmyadmin() {
    if confirm "Do you want to configure phpMyAdmin automatically?"; then

        sudo systemctl reload apache2
    else
        echo "phpMyAdmin configuration skipped."
    fi
}


# Function to secure MariaDB
secure_mariadb() {
    if confirm "Do you want to secure MariaDB automatically?"; then
        sudo mysql_secure_installation
    else
        echo "MariaDB security setup skipped."
    fi
}






# Function to download and install IonCube Loader
install_ioncube() {
    local version=$1
    local ioncube_url="https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz"
    local ioncube_tar="/tmp/ioncube_loaders_lin_x86-64.tar.gz"
    local ioncube_dir="/tmp/ioncube"

    # Check if the file is already downloaded
    if [ ! -f "$ioncube_tar" ]; then
        echo "Downloading IonCube Loader for PHP $version..."
        wget -q -O "$ioncube_tar" "$ioncube_url"
    else
        echo "IonCube Loader for PHP $version is already downloaded."
    fi

    # Extract the downloaded tarball if not already extracted
    if [ ! -d "$ioncube_dir" ]; then
        echo "Extracting IonCube Loader..."
        tar -xzf "$ioncube_tar" -C "/tmp"
    else
        echo "IonCube Loader is already extracted."
    fi

    # Find the correct IonCube Loader file for the given PHP version
    local ioncube_file=$(find "$ioncube_dir" -name "ioncube_loader_lin_${version}.so" | head -n 1)
    if [ -z "$ioncube_file" ]; then
        echo "IonCube Loader for PHP $version not found. Skipping installation."
        return
    fi

    # Get the extension_dir for the given PHP version and remove any trailing '='
    local extension_dir=$(php"$version" -i | grep extension_dir | cut -d'>' -f2 | tr -d ' ' | sed 's/=$//')

    # Ensure the extension_dir exists
    if [ ! -d "$extension_dir" ]; then
        echo "Extension directory $extension_dir does not exist. Creating it..."
        sudo mkdir -p "$extension_dir"
    fi

    # Copy the IonCube Loader file to the extension_dir
    echo "Copying IonCube Loader to $extension_dir..."
    sudo cp "$ioncube_file" "$extension_dir"

    # Create the ini file for IonCube Loader
    local ini_file_fpm="/etc/php/$version/fpm/conf.d/00-ioncube-loader.ini"
    local ini_file_cli="/etc/php/$version/cli/conf.d/00-ioncube-loader.ini"
    local loader_filename=$(basename "$ioncube_file")

    echo "Creating ini file for IonCube Loader..."
    sudo bash -c "echo 'zend_extension=$extension_dir/$loader_filename' > $ini_file_fpm"
    sudo bash -c "echo 'zend_extension=$extension_dir/$loader_filename' > $ini_file_cli"

    echo "Installation of IonCube Loader for PHP $version completed successfully."
}



# Function to download and install SourceGuardian
install_sourceguardian() {
    local version=$1
    local sg_version="${version//./}"
    local sg_url="https://www.sourceguardian.com/loaders/download/loaders.linux-x86_64.zip"
    local sg_zip="/tmp/loaders.linux-x86_64.zip"
    local sg_dir="/tmp/sourceguardian"

    # Check if the file is already downloaded and valid
    if [ -f "$sg_zip" ]; then
        echo "SourceGuardian for PHP $version is already downloaded. Checking integrity..."
        if unzip -tq "$sg_zip"; then
            echo "SourceGuardian archive is valid."
        else
            echo "SourceGuardian archive is corrupted. Deleting and redownloading..."
            sudo rm -f "$sg_zip"
        fi
    fi

    # Download SourceGuardian if not already downloaded or corrupted
    if [ ! -f "$sg_zip" ]; then
        echo "Downloading SourceGuardian for PHP $version from primary URL..."
        curl -s -L -o "$sg_zip" "$sg_url"
        if [ $? -ne 0 ]; then
            echo "Failed to download SourceGuardian from primary URL. Trying alternative URL..."
            curl -s -L -o "$sg_zip" "$DEFAULT_SOURCEGUARDIAN"
            if [ $? -ne 0 ]; then
                echo "Failed to download SourceGuardian from alternative URL. Please check the download links and try again."
                return
            fi
        fi
    fi

    # Extract the downloaded zip file if not already extracted
    if [ ! -d "$sg_dir" ]; then
        echo "Extracting SourceGuardian..."
        if unzip -q -o "$sg_zip" -d "$sg_dir"; then
            echo "Extraction successful."
        else
            echo "Failed to extract SourceGuardian archive. Please check the download link and try again."
            return
        fi
    else
        echo "SourceGuardian is already extracted."
    fi

    # Find the correct SourceGuardian file for the given PHP version
    local sg_file=$(find "$sg_dir" -name "ixed.${version}.lin" | head -n 1)
    if [ -z "$sg_file" ]; then
        echo "SourceGuardian for PHP $version not found. Skipping installation."
        return
    fi

    # Get the extension_dir for the given PHP version
    local extension_dir=$(php"$version" -i | grep extension_dir | cut -d'>' -f2 | tr -d ' ' | sed 's/=$//')

    # Ensure the extension_dir exists
    if [ ! -d "$extension_dir" ]; then
        echo "Extension directory $extension_dir does not exist. Creating it..."
        sudo mkdir -p "$extension_dir"
    fi

    # Copy the SourceGuardian file to the extension_dir
    echo "Copying SourceGuardian to $extension_dir..."
    sudo cp "$sg_file" "$extension_dir"

    # Create the ini file for SourceGuardian
    echo "Creating ini file for SourceGuardian..."
    sudo bash -c "echo 'extension=$extension_dir/$(basename $sg_file)' > /etc/php/$version/fpm/conf.d/00-sourceguardian.ini"
    sudo bash -c "echo 'extension=$extension_dir/$(basename $sg_file)' > /etc/php/$version/cli/conf.d/00-sourceguardian.ini"

    echo "Installation of SourceGuardian for PHP $version completed successfully."
}




config_ftp_server (){
	sudo mkdir -p /etc/ssl/private
	sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem \
	-subj "/C=US/ST=State/L=City/O=Company/CN=$mail_domain"
	sudo ufw allow "30000:50000/tcp"
	echo "1" | sudo tee /etc/pure-ftpd/conf/TLS
	echo "30000 35000" | sudo tee /etc/pure-ftpd/conf/PassivePortRange
	echo "yes" | sudo tee /etc/pure-ftpd/conf/IPV4Only
	echo "yes" | sudo tee /etc/pure-ftpd/conf/ChrootEveryone
	sudo ln -sf "/etc/pure-ftpd/conf/PureDB" "/etc/pure-ftpd/auth/60pdb"
	
	#if ! pure-pw show "$admin_username" &>/dev/null; then	
	#	echo "$username Ftp Creating ..."
	#else
	#	echo "Admin FTP User Already Exist"	
	#fi
	
	sudo pure-pw useradd "$admin_username" -u "$admin_username" -d "/home/$admin_username/domains" -m

	sudo pure-pw mkdb
	sudo systemctl restart pure-ftpd
}




setup_mail_server() {
    # Define local variables for username and domain
    local username="$admin_username"
    local domain="$mail_domain"
    
	# Define other variables
    local DB_USER="mailuser"
    local DB_PASSWORD=$(generate_password)
    local DOVECOT_USER="dovecot"
    local DOVECOT_PASSWORD=$(generate_password)
    local LOG_FILE="$DEFAULT_MailLOG"
    local EXIM_CONFIG_FILE="/etc/exim4/conf.d/router/300_exim_virtual_user"
    local DOVECOT_AUTH_CONF="/etc/dovecot/conf.d/10-auth.conf"
    local DOVECOT_AUTH_SQL_CONF="/etc/dovecot/conf.d/auth-sql.conf.ext"
    local DOVECOT_SQL_CONF="/etc/dovecot/dovecot-sql.conf.ext"
    local DOVECOT_MAIL_CONF="/etc/dovecot/conf.d/10-mail.conf"
    local MAIL_LOCATION="mail_location = maildir:/home/%u/mail/%d/%n/Maildir"

    local DOVECOT_SOCKET="/var/run/dovecot/auth-client"
    local DOVECOT_SOCKET_EXIM="/var/run/dovecot/auth-exim"	
    local EXIM_CONF_TEMPLATE="/etc/exim4/exim4.conf.template"
	local EXIM_CONF="/etc/exim4/exim4.conf.template"
	
    # Create log file and set permissions
    sudo touch "$LOG_FILE"
    sudo chmod 644 "$LOG_FILE"


    # Create vmail user and group if they do not exist (for Dovecot)
    if ! getent group vmail > /dev/null; then
        sudo groupadd -g 5000 vmail
    fi

    if ! getent passwd vmail > /dev/null; then
        sudo useradd -g vmail -u 5000 vmail -m -d /var/vmail -s /sbin/nologin
    fi	



	
    # Setup MariaDB: create database, users, and grant privileges
    sudo mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS mail;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON mail.* TO '$DB_USER'@'localhost';
CREATE USER IF NOT EXISTS '$DOVECOT_USER'@'localhost' IDENTIFIED BY '$DOVECOT_PASSWORD';
GRANT SELECT ON mail.* TO '$DOVECOT_USER'@'localhost';
FLUSH PRIVILEGES;
EOF



    # Create improved tables: users, domains, and emails
    sudo mysql -u root mail <<EOF
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    user_id INT NOT NULL,
    domain_id INT NOT NULL,
    password VARCHAR(255) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);
EOF


	# Check if the 10-mail.conf file exists
	if [ ! -f "$DOVECOT_MAIL_CONF" ]; then
	  echo "File $DOVECOT_MAIL_CONF does not exist."
	  exit 1
	fi

	# Backup the original file
	sudo cp "$DOVECOT_MAIL_CONF" "${DOVECOT_MAIL_CONF}.bak"

	# Remove existing mail_location setting if it is not commented out
	sudo sed -i "/^[^#]*mail_location\b/d" "$DOVECOT_MAIL_CONF"

	# Append the new mail_location setting to the file
	echo "$MAIL_LOCATION" | sudo tee -a "$DOVECOT_MAIL_CONF" > /dev/null	

    # Dovecot Configuration
    sudo tee "$DOVECOT_AUTH_CONF" > /dev/null <<EOF
auth_mechanisms = plain login cram-md5
!include auth-sql.conf.ext
EOF

    sudo tee "$DOVECOT_AUTH_SQL_CONF" > /dev/null <<EOF
passdb {
  driver = sql
  args = $DOVECOT_SQL_CONF
}
userdb {
    driver = sql
  args = $DOVECOT_SQL_CONF
}
EOF

    sudo tee "$DOVECOT_SQL_CONF" > /dev/null <<EOF
driver = mysql
connect = host=localhost dbname=mail user=$DOVECOT_USER password=$DOVECOT_PASSWORD
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM emails WHERE email='%u'
user_query = SELECT email as user, CONCAT('/home/', (SELECT username FROM users WHERE id = (SELECT user_id FROM emails WHERE email='%u')), '/mail/', '%d', '/', '%n', '/Maildir/') AS home FROM emails WHERE email='%u'
EOF

 


echo "Configuring Dovecot authentication socket..."

# Ensure the Dovecot authentication socket configuration is added only once
if ! grep -q "unix_listener $DOVECOT_SOCKET_EXIM" /etc/dovecot/conf.d/10-master.conf; then
  cat >> /etc/dovecot/conf.d/10-master.conf <<EOF

service auth {
  unix_listener $DOVECOT_SOCKET_EXIM {
    mode = 0660
    user = vmail
    group = vmail
  }
}
EOF
  # Restart Dovecot to apply the changes
  systemctl restart dovecot
  echo "Dovecot service restarted to apply changes."
else
  echo "Dovecot authentication socket configuration already exists."
fi



    # Reconfigure Exim4 using dpkg-reconfigure (noninteractive) with specified settings
    sudo debconf-set-selections <<EOF
exim4-config exim4/dc_eximconfig_configtype select internet site; mail is sent and received directly using SMTP
exim4-config exim4/dc_other_hostnames string $domain
exim4-config exim4/dc_local_interfaces string ''
exim4-config exim4/dc_readhost string 
exim4-config exim4/dc_relay_nets string 
exim4-config exim4/dc_minimaldns boolean false
exim4-config exim4/dc_smarthost string 
exim4-config exim4/dc_postmaster string $sc_postmaster
exim4-config exim4/no_configure boolean false
EOF
    sudo dpkg-reconfigure -f noninteractive exim4-config

	
	

	echo "Configuring Exim to use Dovecot authentication..."
	sed -i '/^begin authenticators$/,/^$/d' "$EXIM_CONF_TEMPLATE"

	# Step 3: Add Dovecot authenticators to Exim
	cat >> $EXIM_CONF_TEMPLATE <<EOF

# PLAIN/Login authentication via Dovecot
begin authenticators

# LOGIN authentication via Dovecot (for compatibility)
dovecot_login:
  driver = dovecot
  public_name = LOGIN
  server_socket = $DOVECOT_SOCKET_EXIM

# PLAIN authentication via Dovecot
dovecot_plain:
  driver = dovecot
  public_name = PLAIN
  server_socket = $DOVECOT_SOCKET_EXIM

end authenticators


EOF


sudo tee "$EXIM_CONFIG_FILE" > /dev/null <<'EOF'
virtual_domains:
  driver = accept
  domains = ${lookup mysql{SELECT domain FROM domains WHERE domain = '${domain}'}fail}
  transport = virtual_transport

virtual_user:
  driver = redirect
  domains = +virtual_domains
  data = ${lookup mysql{SELECT CONCAT('/home/', (SELECT username FROM users WHERE id = (SELECT user_id FROM emails WHERE email='${local_part}@${domain}')), '/mail/', '${domain}', '/', '${local_part}', '/Maildir/') FROM emails WHERE email='${local_part}@${domain}'}fail}

virtual_transport:
  driver = appendfile
  file = ${lookup mysql{SELECT CONCAT('/home/', (SELECT username FROM users WHERE id = (SELECT user_id FROM emails WHERE email='${local_part}@${domain}')), '/mail/', '${domain}', '/', '${local_part}', '/Maildir/new/') FROM emails WHERE email='${local_part}@${domain}'}fail}
  delivery_date_add = yes
  envelope_to_add = yes
EOF


 # TLS Configuration for Exim4
    # Use local variable $domain for main domain and $username for SSL directory path
    local SSL_DIR="/home/$username/ssl"
    if [ -f "$SSL_DIR/$domain.crt" ] && [ -f "$SSL_DIR/$domain.key" ]; then
        echo "Using existing certificate for $domain"
        sudo cp "$SSL_DIR/$domain.crt" /etc/exim4/exim.crt
        sudo cp "$SSL_DIR/$domain.key" /etc/exim4/exim.key
    else
        echo "Generating self-signed certificate for $domain"
        # Automatically fill subject values using environment variables (with defaults)
        local TLS_COUNTRY=${TLS_COUNTRY:-"US"}
        local TLS_STATE=${TLS_STATE:-"State"}
        local TLS_CITY=${TLS_CITY:-"City"}
        local TLS_ORG=${TLS_ORG:-"Organization"}
        local TLS_ORG_UNIT=${TLS_ORG_UNIT:-"Department"}
        local subj="/C=$TLS_COUNTRY/ST=$TLS_STATE/L=$TLS_CITY/O=$TLS_ORG/OU=$TLS_ORG_UNIT/CN=$domain"
        sudo openssl req -new -x509 -nodes -out /etc/exim4/exim.crt -keyout /etc/exim4/exim.key -days 365 -subj "$subj"
    fi

    # Enable TLS in Exim4 configuration
    sudo sed -i 's/DAEMON_OPTIONS=tls=none/DAEMON_OPTIONS=tls=openssl/g' /etc/exim4/update-exim4.conf.conf
    # Set Exim4 config type to internet to support external domains (like Gmail, Yahoo, etc.)
    sudo sed -i 's/^dc_eximconfig_configtype=.*/dc_eximconfig_configtype="internet"/' /etc/exim4/update-exim4.conf.conf

    # Set permissions for mail directories (/home/username/mail/)
    sudo chown -R vmail:vmail /home/*/mail/
    sudo find /home/*/mail/ -type d -exec chmod 700 {} \;
	
    # Update Exim4 configuration to apply changes
    sudo update-exim4.conf
	
    # Restart services
    sudo systemctl restart exim4 dovecot mariadb

	
		# Create account info file
		local account_info_file="/home/$LINUX_USER/$ACC_INFO_FILE"
		cat >> "$account_info_file" <<EOF
Mail SERVER: $mail_domain
DB_USER : $DB_USER
DB_PASSWORD : $DB_PASSWORD
DOVECOT_USER : $DOVECOT_USER
DOVECOT_PASSWORD : $DOVECOT_PASSWORD
LOG_FILE : $LOG_FILE
EOF
		
	
}



















mail_config_tmp() {


apt remove --purge exim*
rm -rf /var/lib/exim4
rm -rf /etc/exim4
apt-get remove --purge -y exim4\* && apt-get autoremove -y && apt-get autoclean
systemctl stop exim4-base.timer
systemctl disable exim4-base.timer
rm -f /var/crash/exim4-daemon-heavy.0.crash




# Variables
MYSQL_USER="mailuser"
MYSQL_PASS="password"
MYSQL_DB="mailserver"
MYSQL_HOST="localhost"

# Update and install necessary packages
echo "Updating package list and installing required packages..."
sudo apt update
sudo apt install -y mariadb-server exim4 dovecot-core dovecot-sqlite dovecot-imapd dovecot-pop3d

# Secure MariaDB installation
echo "Securing MariaDB installation..."
sudo mysql_secure_installation <<EOF

Y
root_password
root_password
Y
Y
Y
Y
EOF

# Create the mail database and user
echo "Creating database and user for mail server..."
sudo mysql -u root -proot_password <<EOF
CREATE DATABASE $MYSQL_DB;
CREATE USER '$MYSQL_USER'@'$MYSQL_HOST' IDENTIFIED BY '$MYSQL_PASS';
GRANT ALL PRIVILEGES ON $MYSQL_DB.* TO '$MYSQL_USER'@'$MYSQL_HOST';
FLUSH PRIVILEGES;
EOF

# Create the necessary tables
echo "Creating necessary tables in the database..."
sudo mysql -u $MYSQL_USER -p$MYSQL_PASS -D $MYSQL_DB <<EOF
CREATE TABLE domains (
    id INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    fqdn VARCHAR(250) NOT NULL,
    type ENUM('local','relay') NOT NULL DEFAULT 'local',
    description VARCHAR(250) NULL,
    active TINYINT(1) NOT NULL DEFAULT 0,
    created TIMESTAMP(14) NOT NULL DEFAULT NOW(),
    modified TIMESTAMP(14) NULL
);

CREATE TABLE mailboxes (
    id INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain_id INT(10) NOT NULL,
    local_part VARCHAR(250) NOT NULL,
    password VARCHAR(50) NULL,
    description VARCHAR(250) NULL,
    active TINYINT(1) NOT NULL DEFAULT 0,
    created TIMESTAMP(14) NOT NULL DEFAULT NOW(),
    modified TIMESTAMP(14) NULL
);

CREATE TABLE aliases (
    id INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain_id INT(10) NOT NULL,
    local_part VARCHAR(250) NOT NULL,
    goto VARCHAR(250) NOT NULL,
    description VARCHAR(250) NULL,
    active TINYINT(1) NOT NULL DEFAULT 0,
    created TIMESTAMP(14) NOT NULL DEFAULT NOW(),
    modified TIMESTAMP(14) NULL
);

CREATE TABLE vacations (
    id INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    mailbox_id INT(10) NOT NULL,
    subject VARCHAR(250) NOT NULL,
    body TEXT NOT NULL,
    description VARCHAR(250) NULL,
    active TINYINT(1) NOT NULL DEFAULT 0,
    created TIMESTAMP(14) NOT NULL DEFAULT NOW(),
    modified TIMESTAMP(14) NULL
);
EOF

# Configure Exim
echo "Configuring Exim..."
cat <<EOF | sudo tee /etc/exim4/exim4.conf.template
### GLOBAL SECTION

hide mysql_servers = $MYSQL_HOST/$MYSQL_DB/$MYSQL_USER/$MYSQL_PASS

domainlist local_domains = \${lookup mysql{SELECT fqdn AS domain FROM domains WHERE fqdn='\${quote_mysql:\$domain}' AND type='local' AND active=1}}
domainlist relay_to_domains = \${lookup mysql{SELECT fqdn AS domain FROM domains WHERE fqdn='\${quote_mysql:\$domain}' AND type='relay' AND active=1}}

auth_advertise_hosts = *

### ACL SECTION
accept  hosts         = +relay_from_hosts
        control       = submission
accept  authenticated = *
        control       = submission

### ROUTERS SECTION
user_vacation:
     driver = accept
     domains = \${lookup mysql{SELECT domains.fqdn AS domain FROM domains,mailboxes,vacations WHERE \
                   vacations.active=1 AND \
                   vacations.mailbox_id=mailboxes.id AND \
                   mailboxes.active=1 AND \
                   mailboxes.local_part='\${quote_mysql:\$local_part}' AND \
                   mailboxes.domain_id=domains.id AND \
                   domains.active=1 AND \
                   domains.fqdn='\${quote_mysql:\$domain}'}}
     no_expn
     senders = !^.*-request@.* : !^owner-.*@.* : !^postmaster@.* : \
             ! ^listmaster@.* : !^mailer-daemon@.*
     transport = vacation_reply
     unseen
     no_verify

dovecot_user:
     driver = accept
     condition = \${lookup mysql{SELECT CONCAT(mailboxes.local_part,'@',domains.fqdn) AS goto FROM domains,mailboxes WHERE \
                   mailboxes.local_part='\${quote_mysql:\$local_part}' AND \
                   mailboxes.active=1 AND \
                   mailboxes.domain_id=domains.id AND \
                   domains.fqdn='\${quote_mysql:\$domain}' AND \
                   domains.active=1}{yes}{no}}
     transport = dovecot_delivery

system_aliases:
     driver = redirect
     allow_fail
     allow_defer
     data = \${lookup mysql{SELECT aliases.goto AS goto FROM domains,aliases WHERE \
                   (aliases.local_part='\${quote_mysql:\$local_part}' OR aliases.local_part='@') AND \
                   aliases.active=1 AND \
                   aliases.domain_id=domains.id AND \
                   domains.fqdn='\${quote_mysql:\$domain}' AND \
                   domains.active=1}}

### TRANSPORT SECTION
local_delivery:
     driver = appendfile
     maildir_format = true
     directory = /var/spool/mail/\$domain/\$local_part
     create_directory = true
     directory_mode = 0770
     mode_fail_narrower = false
     group = mail
     mode = 0660

dovecot_delivery:
     driver = appendfile
     maildir_format = true
     directory = /var/spool/mail/\$domain/\$local_part
     create_directory = true
     directory_mode = 0770
     mode_fail_narrower = false
     user = mail
     group = mail
     mode = 0660

vacation_reply:
     driver = autoreply
     to = "\${sender_address}"
     from = "\${local_part}@\${domain}"
     log = /var/spool/exim/msglog/exim_vacation.log
     once =/var/spool/exim/db/vacation.db
     once_repeat = 1d
     subject = "\${lookup mysql{SELECT vacations.subject AS subject FROM vacations,mailboxes,domains WHERE \
                   vacations.active=1 AND \
                   vacations.mailbox_id=mailboxes.id AND \
                   mailboxes.local_part='\${quote_mysql:\$local_part}' AND \
                   mailboxes.active=1 AND \
                   mailboxes.domain_id=domains.id AND \
                   domains.fqdn='\${quote_mysql:\$domain}' AND \
                   domains.active=1}}"
     text = "\${lookup mysql{SELECT vacations.body AS body FROM vacations,mailboxes,domains WHERE \
                   vacations.active=1 AND \
                   vacations.mailbox_id=mailboxes.id AND \
                   mailboxes.local_part='\${quote_mysql:\$local_part}' AND \
                   mailboxes.active=1 AND \
                   mailboxes.domain_id=domains.id AND \
                   domains.fqdn='\${quote_mysql:\$domain}' AND \
                   domains.active=1}}"
     file_optional = true

### AUTHENTICATOR SECTION
auth_plain:
     driver = plaintext
     public_name = PLAIN
     server_condition = \${lookup mysql{SELECT CONCAT(mailboxes.local_part,'@',domains.fqdn) FROM mailboxes,domains WHERE \
                       mailboxes.local_part=SUBSTRING_INDEX('\${quote_mysql:\$auth2}','@',1) AND \
                       mailboxes.password=MD5('\${quote_mysql:\$auth3}') AND \
                       mailboxes.active=1 AND \
                       mailboxes.domain_id=domains.id AND \
                       domains.fqdn=SUBSTRING_INDEX('\${quote_mysql:\$auth2}','@',-1) AND \
                       domains.active=1}{yes}{no}}
     server_prompts = :
     server_set_id = \$auth2

auth_login:
     driver = plaintext
     public_name = LOGIN
     server_condition = \${lookup mysql{SELECT CONCAT(mailboxes.local_part,'@',domains.fqdn) FROM mailboxes,domains WHERE \
                       mailboxes.local_part=SUBSTRING_INDEX('\${quote_mysql:\$auth1}','@',1) AND \
                       mailboxes.password=MD5('\${quote_mysql:\$auth2}') AND \
                       mailboxes.active=1 AND \
                       mailboxes.domain_id=domains.id AND \
                       domains.fqdn=SUBSTRING_INDEX('\${quote_mysql:\$auth1}','@',-1) AND \
                       domains.active=1}{yes}{no}}
     server_prompts = Username:: : Password::
     server_set_id = \$auth1
EOF

# Configure Dovecot
echo "Configuring Dovecot..."
cat <<EOF | sudo tee /etc/dovecot/dovecot.conf
base_dir = /var/run/dovecot/
protocols = imap pop3 lmtp
listen = *

disable_plaintext_auth = no
shutdown_clients = yes
log_timestamp = "%b %d %H:%M:%S "
syslog_facility = mail

ssl_cert_file = /etc/ssl/certs/dovecot.crt
ssl_key_file = /etc/ssl/private/dovecot.key

login_dir = /var/run/dovecot/login
login_chroot = yes
login_user = dovecot
login_process_size = 64
login_process_per_connection = yes
login_processes_count = 3
login_max_processes_count = 128

mail_location = maildir:/var/spool/mail/%d/%n
mail_access_groups = mail,exim,dovecot
mail_full_filesystem_access = yes
mail_debug = yes

verbose_proctitle = yes

first_valid_uid = 8
first_valid_gid = 8

protocol imap {
  imap_client_workarounds = outlook-idle tb-extra-mailbox-sep netscape-eoh
}

protocol pop3 {
  pop3_uidl_format = %08Xu%08Xv
  pop3_client_workarounds = outlook-no-nuls oe-bs-eoh
}

protocol lda {
  postmaster_address = postmaster@example.com
  log_path = /tmp/dovecot-deliver.log
  info_log_path = /tmp/dovecot-deliver.log
  auth_socket_path = /var/run/dovecot/auth-master
}

auth default {
  mechanisms = plain

  socket listen {
   master {
    path = /var/run/dovecot/auth-master
    mode = 0666
    user = mail
    group = mail
   }
  }

  passdb {
    driver = sql
    args = /etc/dovecot/dovecot-sql.conf.ext
  }

  userdb {
    driver = static
    args = uid=vmail gid=vmail home=/home/vmail/%d/%n/Maildir
  }
}
EOF

# Create Dovecot SQL configuration
echo "Creating Dovecot SQL configuration..."
cat <<EOF | sudo tee /etc/dovecot/dovecot-sql.conf.ext
driver = mysql
connect = host=$MYSQL_HOST dbname=$MYSQL_DB user=$MYSQL_USER password=$MYSQL_PASS
default_pass_scheme = PLAIN-MD5

password_query = SELECT CONCAT(mailboxes.local_part, '@', domains.fqdn) AS user, mailboxes.password AS password FROM mailboxes, domains WHERE mailboxes.local_part = '%n' AND mailboxes.active = 1 AND mailboxes.domain_id = domains.id AND domains.fqdn = '%d' AND domains.active = 1;

user_query = SELECT '/var/spool/mail/%d/%n' AS home, 8 AS uid, 12 AS gid;
EOF

# Insert example data into the database
echo "Inserting example data into the database..."
sudo mysql -u $MYSQL_USER -p$MYSQL_PASS -D $MYSQL_DB <<EOF
INSERT INTO domains VALUES(NULL,'my.domain.com','local','My nice domain for local delivery',1,NOW(),NOW());
INSERT INTO mailboxes VALUES(NULL,1,'alex.the.great',MD5('my_very_secret_password'),'My account for alex.the.great@my.domain.com',1,NOW(),NOW());
INSERT INTO aliases VALUES(NULL,1,'alexm','alex.the.great@my.domain.com','alexm is shorter and better',1,NOW(),NOW());
INSERT INTO mailboxes VALUES(NULL,1,'test_program','"|/usr/bin/mymailparser --please_parse_my_mail"','this is my test pipe',1,NOW(),NOW());
INSERT INTO mailboxes VALUES(NULL,1,'@','postmaster@my.domain.com','All mail to the domain will go to postmaster@my.domain.com',1,NOW(),NOW());
INSERT INTO vacations VALUES(NULL,1,'I am away now','Hello, I am away now. Will come back to you when I will come back (to me) :)','My out of office message',1,NOW(),NOW());
EOF

# Restart services
echo "Restarting Exim and Dovecot services..."
sudo systemctl restart exim4
sudo systemctl restart dovecot

# Check status
echo "Checking status of Exim and Dovecot..."
sudo systemctl status exim4
sudo systemctl status dovecot

echo "Setup completed successfully."

}

















add_mail_user() {
    # Retrieve parameters: domain, Linux username, and email local part
    local DOMAIN="$1"
    local LINUX_USER="$2"
    local EMAIL_PART="$3"
    local EMAIL="${EMAIL_PART}@${DOMAIN}"
    local MAILDIR="/home/${LINUX_USER}/mail/${DOMAIN}/${EMAIL_PART}/Maildir"
    local USER_PASSWORD=$(generate_password)
    local SALT=$(openssl rand -base64 8)
    local HASHED_PASSWORD=$(openssl passwd -6 -salt "$SALT" "$USER_PASSWORD")
    local MAILDIR_CUR="${MAILDIR}/cur"
    local MAILDIR_NEW="${MAILDIR}/new"
    local MAILDIR_TMP="${MAILDIR}/tmp"

    # Create Maildir directories
    sudo mkdir -p "$MAILDIR_CUR" "$MAILDIR_NEW" "$MAILDIR_TMP"
    sudo chown -R "vmail:vmail" "/home/${LINUX_USER}/mail"
	sudo find /home/$LINUX_USER/mail/ -type d -exec chmod 700 {} \;
	sudo find /home/$LINUX_USER/mail/ -type f -exec chmod 600 {} \;


    # Insert user and domain into the database
    sudo mysql -u root mail <<EOF
INSERT INTO users (username)
  SELECT '$LINUX_USER'
  WHERE NOT EXISTS (SELECT 1 FROM users WHERE username='$LINUX_USER');

INSERT INTO domains (domain)
  SELECT '$DOMAIN'
  WHERE NOT EXISTS (SELECT 1 FROM domains WHERE domain='$DOMAIN');

SET @user_id = (SELECT id FROM users WHERE username='$LINUX_USER' LIMIT 1);
SET @domain_id = (SELECT id FROM domains WHERE domain='$DOMAIN' LIMIT 1);

INSERT INTO emails (email, user_id, domain_id, password)
VALUES ('$EMAIL', @user_id, @domain_id, '$HASHED_PASSWORD')
ON DUPLICATE KEY UPDATE password='$HASHED_PASSWORD';
EOF

    # Send test email
    echo -e "Subject: Test Email\n\nThis is a test email for $EMAIL." | sendmail "$EMAIL"

    # Check if the test email was sent successfully
    if [ $? -eq 0 ]; then
        echo "✅ Test email sent successfully to $EMAIL"
		sudo cat /var/log/mail.log
		sudo mailq
		sudo cat /var/log/exim4/mainlog
		ls -alR /home/$LINUX_USER/mail/$DOMAIN/$EMAIL_PART
		echo -e "Subject: Test Email\nFrom: $EMAIL\n\nThis is a test email." | sendmail -f $EMAIL $testmail

    else
        echo "❌ Failed to send test email to $EMAIL"
    fi
		# Create account info file
		local account_info_file="/home/$LINUX_USER/$ACC_INFO_FILE"
		cat >> "$account_info_file" <<EOF
Mail SERVER: $mail_domain
Mail User: $EMAIL
Mail Password: $USER_PASSWORD
EOF
	
	
}




create_user() {
    local username="$1"
    local domain="$2"
    local password=$(generate_password)
    echo "DEBUG: Username is '$username'"
    echo "DEBUG: User domain is '$domain'"

    # Check if user exists
    if id "$username" &>/dev/null; then
        echo "User $username already exists."
    else
        # Create user with restricted shell
        sudo useradd -m -d "/home/$username" -s /bin/bash "$username"
        echo "$username:$password" | sudo chpasswd

        # Create necessary directories
		sudo mkdir -p "/home/$username"
        sudo mkdir -p "/home/$username/mail" "/home/$username/ssl" "/home/$username/logs" "/home/$username/domains"
        sudo chown -R "$username:$username" "/home/$username"
        sudo chmod -R 755 "/home/$username"
        sudo chmod -R 700 "/home/$username/mail" "/home/$username/ssl" "/home/$username/logs"

        # Set correct permissions for Apache and PHP
        sudo chown -R "$username":www-data "/home/$username/domains"
        sudo chmod -R 775 "/home/$username/domains"
        
        # Add user to www-data group for PHP execution
        sudo usermod -aG "$username" www-data

        # Set up chroot jail for SSH
        sudo chown root:root "/home/$username/domains"
        sudo chmod 755 "/home/$username/domains"
        
        echo "Match User $username" | sudo tee -a /etc/ssh/sshd_config
        echo "    ChrootDirectory /home/$username/domains" | sudo tee -a /etc/ssh/sshd_config
        echo "    ForceCommand internal-sftp" | sudo tee -a /etc/ssh/sshd_config
        echo "    AllowTcpForwarding no" | sudo tee -a /etc/ssh/sshd_config
        echo "    X11Forwarding no" | sudo tee -a /etc/ssh/sshd_config

		sudo mkdir -p "/home/$username/bin"
		for cmd in ls cp mv mkdir rm rmdir chmod cat grep awk sed find curl wget tar unzip nano vim rsync scp sftp; do
			path=$(command -v $cmd)
			if [[ -n "$path" ]]; then
				echo "Copying: $cmd"
				sudo cp "$path" "/home/$username/bin/"
				sudo ldd "$path" 2>/dev/null | awk '{print $3}' | grep -E '^/' | xargs -I '{}' sudo cp '{}' "/home/$username/bin/" 2>/dev/null
			fi
		done

        # Optimize PHP-FPM 
        for php_version in $(ls /etc/php/ | grep -E '^[0-9]+\.[0-9]+$'); do
            pool_file="/etc/php/$php_version/fpm/pool.d/$username.conf"
		
if [[ "$username" == "$admin_username" ]]; then	
            echo "Creating PHP-FPM pool for PHP $php_version $admin_username"
            cat > "$pool_file" <<EOF

[$username]
user =  $username
group = www-data
listen = /run/php/php-$username-$php_version.sock
listen.owner = $username
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 20
pm.process_idle_timeout = 60s
pm.max_requests = 2000
php_admin_value[open_basedir] = /home/$username/:/usr/share/php/:/usr/share/phpmyadmin/:/usr/share/roundcube/:/etc/roundcube/:/var/lib/roundcube/:/var/log/roundcube/
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,mysql,mysqldump
php_admin_value[max_execution_time] = 300
php_admin_value[memory_limit] = 1024M
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 128M
EOF

else


            echo "Creating PHP-FPM pool for PHP $php_version"
            cat > "$pool_file" <<EOF
[$username]
user = $username
group = www-data
listen = /run/php/php-$username-$php_version.sock
listen.owner = $username
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 20
pm.process_idle_timeout = 60s
pm.max_requests = 2000
php_admin_value[open_basedir] = /home/$username/:/usr/share/php/
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,mysql,mysqldump
php_admin_value[max_execution_time] = 300
php_admin_value[memory_limit] = 1024M
php_admin_value[upload_max_filesize] = 128M
php_admin_value[post_max_size] = 128M
EOF
 
	fi
		done


		sudo systemctl reload apache2
		sudo systemctl reload nginx
		sudo systemctl reload php$php_version-fpm

        # Restart SSH to apply chroot jail
        sudo systemctl reload ssh


		# Create account info file
		local account_info_file="/home/$username/$ACC_INFO_FILE"
		cat > "$account_info_file" <<EOF
Acount domain: $domain
Acount User: $username
Acount Password: $password
EOF

		setup_database_user "$username"
		
		if [[ "$username" != "$admin_username" ]]; then	
			setup_ftp_user "$username"
		fi
		
		echo "User $username created and restricted!"
		fi

}
		



# Function to set up the main domain with SSL
setup_domain() {
	local domain=$1
	local php_version=$2
    local username=$3

	sudo mkdir -p "/home/$username/domains/$domain"
	sudo mkdir -p "/home/$username/mail/$domain"
	sudo chown -R "$username":"$username" "/home/$username/domains/$domain"
	sudo chown -R "$username":"$username" "/home/$username/mail/$domain"
	sudo chmod -R 755 "/home/$username/domains/$domain"
	sudo chmod -R 755 "/home/$username/mail/$domain"
	
	local document_home="/home/$username"
    local document_ssl="$document_home/ssl"
    local document_mail="$document_home/mail"
    local document_logs="$document_home/logs"
	local account_info_file="/home/$username/$ACC_INFO_FILE"
	local document_root="/home/$username/domains/$domain/public_html"
	
	if [[ "$domain" == "$mail_domain" ]]; then	
		local apache_config_file="/etc/apache2/sites-available/roundcube.conf"
		local nginx_config_file="/etc/nginx/sites-available/roundcube"
		local apache_config_enable="/etc/apache2/sites-enabled/roundcube.conf"
		local nginx_config_enable="/etc/nginx/sites-enabled/roundcube"
		sudo ln -sf "/usr/share/roundcube" "$document_root"
		
	elif [[ "$domain" == "$db_domain" ]]; then	
		local apache_config_file="/etc/apache2/sites-available/phpmyadmin.conf"
		local nginx_config_file="/etc/nginx/sites-available/phpmyadmin"
		local apache_config_enable="/etc/apache2/sites-enabled/phpmyadmin.conf"
		local nginx_config_enable="/etc/nginx/sites-enabled/phpmyadmin"
		sudo ln -sf "/usr/share/phpmyadmin" "$document_root"
		
	elif [[ "$domain" == "$server_domain" ]]; then	
		local apache_config_file="/etc/apache2/sites-available/server.conf"
		local nginx_config_file="/etc/nginx/sites-available/server"
		local apache_config_enable="/etc/apache2/sites-enabled/server.conf"
		local nginx_config_enable="/etc/nginx/sites-enabled/server"		
		sudo ln -sf "/var/www/html" "$document_root"
		
	else
		sudo mkdir -p "/home/$username/domains/$domain/public_html"
		sudo chown -R "$username":"$username" "/home/$username/domains/$domain/public_html"
		sudo chmod -R 755 "/home/$username/domains/$domain/public_html"
		
		# Generate Default Web Files for the domain	
		create_web_files "$domain" "$username" "$document_root" "$php_version" 
			
		local apache_config_file="/etc/apache2/sites-available/$domain.conf"
		local nginx_config_file="/etc/nginx/sites-available/$domain"
		local apache_config_enable="/etc/apache2/sites-enabled/$domain.conf"
		local nginx_config_enable="/etc/nginx/sites-enabled/$domain"
		

	fi
	
    # Generate DNS Zone File for the domain
	setup_dns "$domain" "$username"
	
    # Generate SSL certificate for the domain
    generate_ssl_certificate "$username" "$domain" "$php_version" "$document_root" "$document_home" "$document_ssl" "$document_mail" "$document_logs" "$apache_config_file" "$nginx_config_file"	
	
    # Generate apache and nginx  Virtual Host for the domain
	setup_apache_nginx_vhost "$username" "$domain" "$php_version" "$document_root" "$document_home" "$document_ssl" "$document_mail" "$document_logs" "$apache_config_file" "$nginx_config_file"

	if [[ "$domain" != "$mail_domain" && "$domain" != "$server_domain" && "$domain" != "$db_domain" ]]; then
	
		# Generate Mail for the domain			
		add_mail_user "$domain" "$username" "$username"
		add_mail_user "$domain" "$username" "info"
		
	fi
	
	
	
	echo "Setup completed : Mail , FTP , DNS , Apache , Nginx , SSL , PHP ;) "
	cat "$account_info_file"
}


setup_database_user (){
    local database_user="$1"	
    local database_password=$(generate_password)
	# Check if the user already exists
	user_exists=$(mysql -e "SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user='${database_user}' AND host='localhost');" -s -N)

	if [ "$user_exists" -eq 1 ]; then
		echo "User ${database_user} already exists."
	else
		echo "User ${database_user} does not exist. Creating now..."
	
		# Create the MySQL user
		mysql -e "CREATE USER '${database_user}'@'localhost' IDENTIFIED BY '${database_password}';"

		# Grant global CREATE privilege (necessary to allow database creation)
		mysql -e "GRANT CREATE ON *.* TO '${database_user}'@'localhost';"

		# Grant all privileges for databases that match the pattern `username_%`
		mysql -e "GRANT ALL PRIVILEGES ON \`${database_user}\\_%\`.* TO '${database_user}'@'localhost';"

		# Remove unnecessary global privileges
		mysql -e "REVOKE ALL PRIVILEGES ON *.* FROM '${database_user}'@'localhost';"

		# Flush privileges to ensure all changes take effect
		mysql -e "FLUSH PRIVILEGES;"

		# Create account info file
		local account_info_file="/home/$username/$ACC_INFO_FILE"
		cat >> "$account_info_file" <<EOF
DB URL: $db_domain
DB User: $database_user
DB Password: $database_password
EOF
	
		fi
}



setup_ftp_user (){
	local username="$1"
    local ftp_password=$(generate_password)
	
	if ! pure-pw show "$username" &>/dev/null; then	
		echo "$username Ftp Creating ..."
		
		#sudo pure-pw useradd "$username"  -u "$username" -d "/home/$username"	| 		
		#echo -e "$ftp_password\n$ftp_password"
	
		sudo pure-pw useradd "$username" -u "$username" -d "/home/$username/domains" -m
	
		sudo pure-pw mkdb
		sudo systemctl restart pure-ftpd

		# Create account info file
		local account_info_file="/home/$username/$ACC_INFO_FILE"
		cat >> "$account_info_file" <<EOF
FTP  SERVER: $public_ip
FTP User: $username
FTP Password: No Set default $DEFAULT_FTP_PASS
EOF

	else
		echo "User $username already exists. Skipping user creation."
	fi
}






	
generate_ssl_certificate() {
    local username=$1  
    local domain=$2  
    local document_ssl=$6
    local document_root=$4

    if [ "$letsencrypt" -eq 1 ]; then
        # If letsencrypt is 1, use Let's Encrypt
		sudo certbot certonly --webroot -w "$document_root" \
		-d "$domain" \
		-d "www.$domain" \
		--email ssl@$domain \
		--agree-tos \
		--non-interactive && \
		sudo mkdir -p "$document_ssl" && \
		sudo ln -sf /etc/letsencrypt/live/$domain/fullchain.pem "$document_ssl/$domain.crt" && \
		sudo ln -sf /etc/letsencrypt/live/$domain/privkey.pem "$document_ssl/$domain.key" &&
        echo "Let's Encrypt SSL certificate will be saved in: $document_ssl"
    elif [ "$letsencrypt" -eq 0 ]; then
        # If letsencrypt is 0, generate a Self-Signed certificate
        echo "Self-Signed SSL certificate will be saved in: $document_ssl"
        sudo mkdir -p "$document_ssl"
			sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$document_ssl/$domain.key" -out "$document_ssl/$domain.crt" \
			-subj "/C=IR/ST=Tehran/L=Tehran/O=MyOrg/OU=IT Department/CN=$domain" \
			-addext "subjectAltName = DNS:$domain,DNS:www.$domain"
			sudo openssl x509 -in "$document_ssl/$domain.crt" -out "$document_ssl/$domain.pem" -outform PEM

		else
        # If letsencrypt is not 1 or 0, show an error message
        echo "Invalid letsencrypt value. Use 1 for Let's Encrypt or 0 for Self-Signed."
        exit 1
    fi
}




# Function to set up domain Apache and Nginx config file
setup_apache_nginx_vhost() {
    local username="$1"
    local domain="$2"
    local php_version="$3"
    local document_root="$4"
    local document_home="$5"
    local document_ssl="$6"
    local document_mail="$7"
    local document_logs="$8"

    # Apache Configuration
    if [ -f "$apache_config_file" ]; then
        echo "[INFO] Apache config for $domain already exists. Skipping creation."
    else
        cat > "$apache_config_file" <<EOF
<VirtualHost *:$apache_port>
    ServerName $domain
    DocumentRoot $document_root
    ServerAlias www.$domain

    # Allow .htaccess overrides
    <Directory "$document_root">
        AllowOverride All
        Require all granted
    </Directory>

    # Only process PHP files
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:/run/php/php-$username-$php_version.sock|fcgi://localhost"
    </FilesMatch>

    # Custom error pages
    ErrorDocument 404 /404.html
    ErrorDocument 403 /403.html
    ErrorDocument 500 /500.html

    RemoteIPHeader X-Forwarded-For
    RemoteIPTrustedProxy 127.0.0.1

    # Set HTTPS variable
    SetEnvIf X-Forwarded-Proto https HTTPS=on

    # Set REQUEST_SCHEME to https
    RequestHeader set REQUEST_SCHEME "https" env=HTTPS
	
    # Disable serving other file types
    <FilesMatch "\.(html|css|js|jpg|jpeg|png|gif|ico|svg)$">
        Require all denied
    </FilesMatch>

    ErrorLog $document_logs/$domain-error.log
    CustomLog $document_logs/$domain-access.log combined

</VirtualHost>
EOF
        sudo ln -sf "$apache_config_file" "$apache_config_enable"
        sudo apachectl configtest && sudo systemctl reload apache2
        echo "[INFO] Apache config created for $domain on port $apache_port."
    fi

    # Nginx Configuration
    if [ -f "$nginx_config_file" ]; then
        echo "[INFO] Nginx config for main domain $domain already exists. Skipping creation."
    else
        cat > "$nginx_config_file" <<EOF
server {
    listen 80;
    server_name $domain www.$domain;
    return 301 https://\$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain www.$domain;

    ssl_certificate $document_ssl/$domain.crt;
    ssl_certificate_key $document_ssl/$domain.key;

    root $document_root;
    index index.php index.html index.htm;

    # Custom error pages
    error_page 404 /404.html;
    error_page 403 /403.html;
    error_page 500 /500.html;

	
	    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }


    # Static files handled by Nginx
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2|ttf|svg|mp4|webm|ogg|webp|zip|rar|tar|gz)$ {
        expires max;
        log_not_found off;
    }

    # PHP requests handled via FastCGI
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php-$username-$php_version.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }

    # Prevent access to hidden files (like .htaccess)
    location ~ /\.ht {
        deny all;
    }

    # Log errors
    error_log $document_logs/$domain-nginx-error.log;
    access_log $document_logs/$domain-nginx-access.log combined;
}
EOF
        sudo ln -sf "$nginx_config_file" "$nginx_config_enable"
        sudo nginx -t && sudo systemctl reload nginx
        echo "[INFO] Nginx config created for $domain with SSL."
    fi
    echo "[INFO] .htaccess file created for $domain with PHP version and mail logging."

    # Restart services to apply changes
    sudo systemctl reload apache2
    sudo systemctl reload nginx
    sudo systemctl restart php$php_version-fpm
}





setup_dns() {
    local domain=$1
    local username=$2
    local zone_path="/etc/bind/db.$domain"
    local named_conf_local="/etc/bind/named.conf.local"
    local dkim_selector="default"
    local dkim_key_path="/etc/opendkim/keys/$domain/$dkim_selector.txt"
	echo "$public_ip $domain" | sudo tee -a /etc/hosts
	echo "$public_ip www.$domain" | sudo tee -a /etc/hosts

    if [ ! -f "$dkim_key_path" ]; then
        sudo mkdir -p "/etc/opendkim/keys/$domain"
        cd "/etc/opendkim/keys/$domain"
        sudo opendkim-genkey -r -s "$dkim_selector" -d "$domain"
        sudo mv "$dkim_selector.private" "$dkim_selector"
        sudo chown opendkim:opendkim "$dkim_selector"
        echo "[INFO] DKIM key generated for $domain."
    else
        echo "[INFO] DKIM key for $domain already exists."
    fi


    local dkim_public_key=$(grep "p=" "$dkim_key_path" | cut -d'"' -f2)

	local serial_file="/home/$admin_username/bind.serial"
	touch "$serial_file"

	# Check if the file exists and its content is a number
	if [ -f "$serial_file" ] && [[ $(cat "$serial_file") =~ ^[0-9]+$ ]]; then
		local current_serial=$(cat "$serial_file")
		local new_serial=$((current_serial + 1))  # Increment by 1
	else
		# If the file is empty or contains non-numeric data, use the current date
		local new_serial=$(date +"%Y%m%d")"02"
	fi

	# If new_serial is greater than current_serial, increment new_serial by 1
	if [ "$new_serial" -gt "$current_serial" ]; then
		new_serial=$((new_serial + 1))
	fi

	# Save the new serial to the file
	echo "$new_serial" > "$serial_file"
	echo "[INFO] SOA serial incremented to $new_serial and saved to $serial_file."

	
	if [[ "$domain" == "$base_domain" ]]; then

    cat > "$zone_path" <<EOF
\$TTL 86400
@       IN      SOA     $nameserver1. admin.$domain. (
                              $new_serial         ; Serial
                           3600         ; Refresh
                            900         ; Retry
                        1209600         ; Expire
                           3600 )       ; Negative Cache TTL
;
@       IN      NS      $nameserver1.
@       IN      NS      $nameserver2.
@       IN      A       $public_ip
mail    IN      A       $public_ip
$dns1   IN      A       $public_ip
$dns2   IN      A       $public_ip
www     IN      CNAME   @

; Mail Server Configuration
@       IN      MX      10 mail.$domain.

; SPF Record
@       IN      TXT     "v=spf1 a mx ip4:$public_ip ~all"

; DMARC Record
_dmarc  IN      TXT     "v=DMARC1; p=none; rua=mailto:admin@$domain; ruf=mailto:admin@$domain; fo=1"

; DKIM Record
$dkim_selector._domainkey IN TXT "$dkim_public_key"
EOF
else

    cat > "$zone_path" <<EOF
\$TTL 86400
@       IN      SOA    $nameserver1. admin.$domain. (
                              $new_serial         ; Serial
                           3600         ; Refresh
                            900         ; Retry
                        1209600         ; Expire
                           3600 )       ; Negative Cache TTL
;
@       IN      NS      $nameserver1.
@       IN      NS      $nameserver2.
@       IN      A       $public_ip
mail    IN      A       $public_ip
www     IN      CNAME   @

; Mail Server Configuration
@       IN      MX      10 mail.$domain.

; SPF Record
@       IN      TXT     "v=spf1 a mx ip4:$public_ip ~all"

; DMARC Record
_dmarc  IN      TXT     "v=DMARC1; p=none; rua=mailto:admin@$domain; ruf=mailto:admin@$domain; fo=1"

; DKIM Record
$dkim_selector._domainkey IN TXT "$dkim_public_key"
EOF

fi
    echo "[INFO] DNS zone file created or updated for $domain."

    # Update named.conf.local
    if ! grep -q "zone \"$domain\"" "$named_conf_local"; then
        cat >> "$named_conf_local" <<EOF
zone "$domain" {
    type master;
    file "/etc/bind/db.$domain";
};
EOF
        echo "[INFO] DNS zone added to named.conf.local."
    fi

    # Restart BIND9
    sudo systemctl reload bind9
    echo "DNS records set up successfully for $domain."
}




cleanup_system() {
    echo "====================================================="    
    echo "Start Cleaning and Setup Again ..."    
    echo "====================================================="

    # Define the list of packages to be removed
    local packages=(
        apache2 nginx mariadb-server bind9 phpmyadmin mailutils roundcube
        exim4 exim4-base exim4-config exim4-daemon-light sasl2-bin
        dovecot-mysql dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd
        dovecot-sieve pure-ftpd pure-ftpd-common php*
    )

    # Remove packages and their dependencies
    for pkg in "${packages[@]}"; do
        echo "Removing: $pkg"
        sudo apt remove -y "$pkg"
        sudo apt purge -y "$pkg"
    done

    # Remove unnecessary dependencies
    echo "Running autoremove..."
    sudo apt autoremove -y

    # Clean package cache
    echo "Cleaning up..."
    sudo apt autoclean
    sudo apt clean

    # Remove users and groups related to removed services
    echo "Removing related users and groups..."
    local service_users=(
        www-data  # Apache & Nginx
        mysql     # MariaDB
        bind      # Bind9
        exim      # Exim4
        dovecot   # Dovecot
        ftp       # Pure-FTPd
    )

    for user in "${service_users[@]}"; do
        if id "$user" &>/dev/null; then
            echo "Deleting user: $user"
            sudo deluser --remove-home "$user"
        fi
    done

    for group in "${service_users[@]}"; do
        if getent group "$group" &>/dev/null; then
            echo "Deleting group: $group"
            sudo delgroup "$group"
        fi
    done

    # Remove unauthorized users (excluding allowed ones)
    local allowed_users=("root" "ubuntu" "info" "administrator")  
    local all_users
    all_users=$(ls /home/)

    for user in $all_users; do
        if [[ " ${allowed_users[@]} " =~ " $user " ]]; then
            echo "Skipping allowed user: $user"
            continue
        fi

        echo "Deleting user: $user"
        sudo userdel -r "$user"
        sudo groupdel "$user"
        echo "User $user and their group have been removed!"
    done

    # Remove leftover directories
    echo "Cleaning Script Directory ..."            
    local dirs_to_remove=(
        /var/log/taniweb/
        /etc/nginx/
        /etc/apache2
        /etc/php
        /etc/mysql
        /etc/bind
        /etc/exim4
        /etc/dovecot
        /etc/pure-ftpd
    )

    for dir in "${dirs_to_remove[@]}"; do
        if [ -d "$dir" ]; then
            echo "Removing: $dir"
            sudo rm -rf "$dir"
        fi
    done
	
    echo "====================================================="    
    echo "Cleanup completed!" 
    echo "====================================================="
    
}





# Function to set up the server with SSL
setup_server() {

    # Update DNS resolvers
    update_dns_resolvers "/etc/netplan/$netplan_config_file" "$resolver1" "$resolver2" "$selected_interface"

    # Set hostname
    sudo hostnamectl set-hostname "$hostname"
    echo "Hostname set to $hostname"

    # Update system packages
    export DEBIAN_FRONTEND=noninteractive
    sudo apt update -y

    # Install UFW and enable firewall
    sudo apt install ufw -y
    setup_firewall_rules

    # Install Apache
    sudo apt install apache2 -y
    #sudo sed -i "/^Listen [0-9]\+$/c\Listen $apache_port" /etc/apache2/ports.conf
	#mv /etc/apache2/ports.conf /root/port.apache2.bk
	echo "Listen $apache_port" > /etc/apache2/ports.conf
    sudo systemctl restart apache2

    # Install required packages
    sudo apt install nginx mariadb-server bind9 acl tar unzip wget net-tools certbot openssl python3-certbot-nginx python3-certbot-apache opendkim opendkim-tools libapache2-mod-fcgid -y

    # Enable Apache modules
	a2enmod rewrite headers proxy_fcgi setenvif remoteip ssl

	
    # Install multiple PHP versions
    sudo add-apt-repository ppa:ondrej/php -y
    sudo apt update -y
    priority=1 

	# Main loop to install PHP versions and extensions
	for version in "${php_versions[@]}"; do
		echo "Installing PHP $version..."

		# Install PHP packages
		sudo apt install -y php"$version" php"$version"-fpm php"$version"-cli \
		php"$version"-mysql php"$version"-curl php"$version"-mbstring php"$version"-xml php"$version"-soap \
		php"$version"-gd php"$version"-zip php"$version"-imap php"$version"-intl php"$version"-tokenizer \
		php"$version"-bcmath php"$version"-xmlrpc php"$version"-readline php"$version"-opcache \
		php"$version"-redis php"$version"-memcached php"$version"-imagick php"$version"-exif


		# Enable and start php-fpm service
		echo "Enabling and starting php$version-fpm..."
		sudo systemctl enable php"$version"-fpm
		sudo systemctl start php"$version"-fpm

		# Set up alternatives for php-fpm
		echo "Setting up alternatives for php-fpm..."
		sudo update-alternatives --install /usr/sbin/php-fpm php-fpm /usr/sbin/php-fpm"$version" $priority
		((priority++))

		# Install IonCube Loader
		install_ioncube "$version"

		# Install SourceGuardian
		install_sourceguardian "$version"

		# Restart php-fpm to apply changes
		echo "Restarting php$version-fpm to apply changes..."
		sudo systemctl reload php"$version"-fpm
	done

    # Set the default PHP version
    sudo update-alternatives --set php /usr/bin/php"$default_php_version"
	echo "All PHP versions and extensions have been installed successfully."

    # Install PHPMyadmin & Mail Packages
    sudo apt install phpmyadmin  roundcube  -y
	
	#Install FTP Packages
	sudo apt install  pure-ftpd pure-ftpd-common -y
	
	
	#Install Mil Packages	
	sudo apt install  exim4 exim4-base exim4-config exim4-daemon-heavy spf-tools-perl sasl2-bin dovecot-mysql dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-sieve -y
	
	# Create Admin User
	create_user "$admin_username" "$base_domain"
	
	# Configure FTP server
	config_ftp_server	
	
	# Configure Mail server
	setup_mail_server	
	
	#Set up Main Domain and subdomains
	for first_domain in "$base_domain"  "$mail_domain" "$db_domain" "$server_domain"  ; do
		setup_domain  "${first_domain}" "$default_php_version" "$admin_username"
	done

    # Secure MariaDB
	secure_mariadb

    # Restart services
    sudo systemctl reload apache2 nginx bind9
    sudo systemctl restart mariadb


    echo "Nginx and Apache default pages set up successfully with SSL."
    touch "$CONFIG_FILE"
    echo "Server setup is complete with SSL!"
}




# Main function
main() {
    if [ -f "$CONFIG_FILE" ]; then
	
		load_config "$CONFIG_DATA"
		echo ""
        echo "Server setup already completed. Now managing users and domains."
		echo "Please enter 1 for a new user or 2 for adding a domain to an existing user or 3 for clean up and setup again."
		
		read action

		while [[ "$action" != "1" && "$action" != "2" && "$action" != "3" ]]; do
			echo "Invalid input."
			read action
		done

		if [ "$action" == "1" ]; then
			action="new"
		elif [ "$action" == "2" ]; then
			action="exist"
		elif [ "$action" == "3" ]; then
			action="clean"	
		fi

		
        if [ "$action" == "new" ]; then

			# Prompt for a new username until a valid one is entered (not already in username_all)
			while true; do
			echo "Enter a Linux username to create:"
			read username
			if validate_input "$username" "$(get_all_usernames)"; then
				echo "Username already exists. Please choose another one."
			else
				break
			fi
			done	
			echo "User $username Entered."

			
			# Prompt for a new domain until a valid one is entered
			while true; do
			echo "Enter the domain for this user (e.g., example.com):"
			read user_domain
			# First, validate the domain format
			if ! validate_domain "$user_domain"; then
				echo "Invalid domain format. Please enter a valid domain (e.g., example.com)."
			# Then, check if the domain already exists in the DOMAINS_LIST
			elif validate_input "$user_domain" "$(gather_domains)"; then
				echo "Domain already exists. Please choose another one."
			else
				break  # Valid and non-duplicate domain, exit the loop
			fi
			done
			echo "User $user_domain Entered."
			

			# Prompt the user for input, and set a default value if empty
			echo -e -n "Enable letsencrypt? 0/1 (default: $DEFAULT_LETSENCRYPT):"
			read letsencrypt
			letsencrypt=${letsencrypt:-$DEFAULT_LETSENCRYPT}  # If the user didn't enter anything, default to DEFAULT_LETSENCRYPT
				if [ "$letsencrypt" -eq 1 ]; then
					echo "letsencrypt SSL Enabled"
				else
					echo "letsencrypt SSL Disbaled [use Self Sign]"
				fi
			echo ""
			
			
			echo -e -n "Enter the  PHP version fot this user (default: $DEFAULT_PHP_VERSION):"
			read default_php_version
			default_php_version=${default_php_version:-$DEFAULT_PHP_VERSION}
			if [[ ! " ${php_versions[@]} " =~ " ${default_php_version} " ]]; then
				echo "PHP version must be one of the installed versions: ${php_versions[*]}"
				return
			fi
			echo "Set PHP Version  : $default_php_version "
			echo ""

			
			create_user "$username" "$user_domain"
			setup_domain  "$user_domain" "$default_php_version" "$username"
		
		elif [ "$action" == "exist" ]; then
		
			# Prompt for an allowed user until a valid one is selected (must be in allowed_usernames)
			while true; do
			echo "Select an Allowed user to add a domain :"
			# Display the list of allowed users with numbers
			allowed_usernames=($(get_allowed_usernames))  # Get the list of allowed usernames from the function
			for i in "${!allowed_usernames[@]}"; do
				echo "$((i+1)). ${allowed_usernames[$i]}"
			done
			# Ask the user to enter a number corresponding to the user
			read -p "Enter the number of the user you want to select: " selected_number
			# Check if the entered number is valid
			if [[ "$selected_number" -ge 1 && "$selected_number" -le ${#allowed_usernames[@]} ]]; then
				selected_user="${allowed_usernames[$((selected_number - 1))]}"  # Adjust for 0-based indexing
				break
			else
				echo "Invalid selection. Please choose a valid number."
			fi
			done
			echo "User $selected_user Selected."

		
			# Prompt for a new domain until a valid one is entered
			while true; do
			echo "Enter the domain for this user (e.g., example.com):"
			read user_domain
			# First, validate the domain format
			if ! validate_domain "$user_domain"; then
				echo "Invalid domain format. Please enter a valid domain (e.g., example.com)."
			# Then, check if the domain already exists in the DOMAINS_LIST
			elif validate_input "$user_domain" "$(gather_domains)"; then
				echo "Domain already exists. Please choose another one."
			else
				break  # Valid and non-duplicate domain, exit the loop
			fi
			done
			echo "User $user_domain Entered."


			# Prompt the user for input, and set a default value if empty
			echo -e -n "Enable letsencrypt? 0/1 (default: $DEFAULT_LETSENCRYPT):"
			read letsencrypt
			letsencrypt=${letsencrypt:-$DEFAULT_LETSENCRYPT}  # If the user didn't enter anything, default to DEFAULT_LETSENCRYPT
				if [ "$letsencrypt" -eq 1 ]; then
					echo "letsencrypt SSL Enabled"
				else
					echo "letsencrypt SSL Disbaled [use Self Sign]"
				fi
			echo ""
					
			setup_domain  "$user_domain" "$default_php_version" "$selected_user"
	
		else
		
			# Execute the function
			cleanup_system

			# Execute the main function
			main
			
        fi
		
    else
	
		#make script Directory
		sudo mkdir -p "$CONFIG_DIRECTORY"
	
        # Collect all inputs upfront
        echo -e -n "Enter the base domain for the main site (default: $DEFAULT_BASE_DOMAIN):"
        read base_domain
        base_domain=${base_domain:-$DEFAULT_BASE_DOMAIN}
        validate_domain "$base_domain" || return
		echo "$base_domain"
		echo ""

        # Collect all inputs upfront
        echo -e -n "Enter the server domain for the server hostname (default: $DEFAULT_SERVER_DOMAIN):"
        read server_domain
        server_domain=${server_domain:-$DEFAULT_SERVER_DOMAIN}
        validate_domain "$server_domain" || return
		echo "$server_domain"
		hostname="$server_domain"
		echo ""
		
        # Collect all inputs upfront
        echo -e -n "Enter the db domain for the phpmyadmin (default: $DEFAULT_DB_DOMAIN):"
        read db_domain
        db_domain=${db_domain:-$DEFAULT_DB_DOMAIN}
        validate_domain "$db_domain" || return
		echo "$db_domain"
		echo ""
		
        # Collect all inputs upfront
        echo -e -n "Enter the mail domain for the roundcube (default: $DEFAULT_MAIL_DOMAIN):"
        read mail_domain
        mail_domain=${mail_domain:-$DEFAULT_MAIL_DOMAIN}
        validate_domain "$mail_domain" || return
		echo "$mail_domain"
		echo ""

		# Prompt for a Admin username until a valid one is entered (not already in username_all)
		while true; do
		echo -e -n "Enter a Linux Admin Username to create:(default: $DEFAULT_ADMIN):"
		read admin_username
        admin_username=${admin_username:-$DEFAULT_ADMIN}
		if validate_input "$admin_username" "$(get_all_usernames)"; then
			echo "Username already exists. Please choose another one."
		else
			break
		fi
		done	
		echo "User $admin_username Entered."
		echo ""
		
        echo -e -n "Enter desired PHP versions (space-separated, default: ${DEFAULT_INSTALL_PHP_VERSIONS[*]}):"
        read -a php_versions
        if [ ${#php_versions[@]} -eq 0 ]; then
            php_versions=("${DEFAULT_INSTALL_PHP_VERSIONS[@]}")
        fi
		echo "PHP Versions Will Installed  : ${php_versions[*]} "
		echo ""
	
        echo -e -n "Enter the default PHP version (default: $DEFAULT_PHP_VERSION):"
        read default_php_version
        default_php_version=${default_php_version:-$DEFAULT_PHP_VERSION}
        if [[ ! " ${php_versions[@]} " =~ " ${default_php_version} " ]]; then
            echo "Default PHP version must be one of the installed versions: ${php_versions[*]}"
            return
        fi
		echo "Default PHP Version  : $default_php_version "
		echo ""
		
        echo -e -n "Enter the public IP address of the server (default: $DEFAULT_PUBLIC_IP):"
        read public_ip
        public_ip=${public_ip:-$DEFAULT_PUBLIC_IP}
        validate_ip "$public_ip" || return
		echo "Public IP  : $public_ip "
		echo ""
		
        echo -e -n "Enter the first resolver (default: $DEFAULT_RESOLVER1):"
        read resolver1
        resolver1=${resolver1:-$DEFAULT_RESOLVER1}
        validate_ip "$resolver1" || return
		echo "First Resolver  : $resolver1 "
		echo ""
		
        echo -e -n "Enter the second resolver (default: $DEFAULT_RESOLVER2):"
        read resolver2
        resolver2=${resolver2:-$DEFAULT_RESOLVER2}
        validate_ip "$resolver2" || return
		echo "Second Resolver  : $resolver2 "
		echo ""

		# Prompt the user for input, and set a default value if empty
        echo -e -n "type nameserver1 ? (default: $DEFAULT_NANESERVER1.$base_domain):"
		read dns1
		dns1=${dns1:-$DEFAULT_NANESERVER1}  # If the user didn't enter anything, default to DEFAULT_NANESERVER1
		nameserver1="${dns1}.${base_domain}"
		echo "First Nameserver  : $nameserver1 "
		echo ""

		# Prompt the user for input, and set a default value if empty
        echo -e -n "type nameserver2 ? (default: $DEFAULT_NANESERVER2.$base_domain):"
		read dns2
		dns2=${dns2:-$DEFAULT_NANESERVER2}  # If the user didn't enter anything, default to DEFAULT_NANESERVER2
		nameserver2="${dns2}.${base_domain}"
		echo "Second Nameserver  : $nameserver2 "
		echo ""
		
		# Prompt the user for input, and set a default value if empty
        echo -e -n "Enable letsencrypt? 0/1 (default: $DEFAULT_LETSENCRYPT):"
		read letsencrypt
		letsencrypt=${letsencrypt:-$DEFAULT_LETSENCRYPT}  # If the user didn't enter anything, default to DEFAULT_LETSENCRYPT
			if [ "$letsencrypt" -eq 1 ]; then
				echo "letsencrypt SSL Enabled"
			else
				echo "letsencrypt SSL Disbaled [use Self Sign]"
			fi
		echo ""

        echo -e -n "Enter the Apache port (default: $DEFAULT_APACHE_PORT):"
        read custom_apache_port
        apache_port=${custom_apache_port:-$DEFAULT_APACHE_PORT}
        validate_port "$apache_port" || return
		echo "selected Port : $apache_port"
		echo ""
	  
		# Call the function to select network interface
		select_network_interface			

		# Call the function to select Netplan configuration file
		select_netplan_config

		# Check if the file exists and remove it if it does
		if [ -f "$FIRST_ENTRY_FLAG" ]; then
			rm "$FIRST_ENTRY_FLAG"
			echo "The file $FIRST_ENTRY_FLAG has been removed."
		fi
		allowed_ports=("465" "143" "110" "21" "25" "587" "990" "993" "995" "22" "443" "80" "$apache_port")
		#"30000:50000"
		
		testmail="ganje.id24@gmail.com"
		sc_postmaster="admin@miniservice.ir"
		
		# Print and save values without $ for variable names
		save_and_display "allowed_ports:$(IFS=,; echo "${allowed_ports[*]}")"
		save_and_display "base_domain:$base_domain"
		save_and_display "mail_domain:$mail_domain"
		save_and_display "db_domain:$db_domain"
		save_and_display "server_domain:$server_domain"
		save_and_display "admin_username:$admin_username"
		save_and_display "php_versions:$(IFS=,; echo "${php_versions[*]}")"
		save_and_display "default_php_version:$default_php_version"
		save_and_display "public_ip:$public_ip"
		save_and_display "resolver1:$resolver1"
		save_and_display "resolver2:$resolver2"
		save_and_display "dns1:$dns1"
		save_and_display "dns2:$dns2"
		save_and_display "nameserver1:$nameserver1"
		save_and_display "nameserver2:$nameserver2"
		save_and_display "apache_port:$apache_port"
		save_and_display "letsencrypt:$letsencrypt"
		save_and_display "netplan_config_file:$netplan_config_file"
		save_and_display "selected_interface:$selected_interface"
		save_and_display "hostname:$hostname"
		save_and_display "testmail:$testmail"
		
        # Setup server with SSL
        setup_server  

	fi	
}

# Execute the main function
main

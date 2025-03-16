#!/bin/bash
# ------------------------------
# Initial configuration (User will provide IPs during script execution)
LOG_FILE="/root/change_ip_log.txt"

# ------------------------------
# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root."
  exit 1
fi

# ------------------------------
# Get old and new IP addresses from user input
read -p "Enter the OLD IP address: " OLD_IP
read -p "Enter the NEW IP address: " NEW_IP

if [ -z "$OLD_IP" ] || [ -z "$NEW_IP" ]; then
  echo "Both OLD IP and NEW IP must be provided."
  exit 1
fi

# ------------------------------
# Log the operation
echo "Changing IPs from $OLD_IP to $NEW_IP" > $LOG_FILE

# ------------------------------
# Step 1: Update shared IP in WHM configuration
echo "Updating shared IP in WHM configuration..." >> $LOG_FILE
sed -i "s/$OLD_IP/$NEW_IP/g" /var/cpanel/cpanel.config >> $LOG_FILE 2>&1
/scripts/updateuserdomains >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Failed to update shared IP in WHM configuration." >> $LOG_FILE
fi

# ------------------------------
# Step 2: Update network configuration
echo "Updating network configuration..." >> $LOG_FILE
NETWORK_CONFIG_FILE="/etc/sysconfig/network-scripts/ifcfg-$(ip route | grep default | awk '{print $5}')"
sed -i "s/$OLD_IP/$NEW_IP/g" $NETWORK_CONFIG_FILE >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Failed to update network configuration. Please check $NETWORK_CONFIG_FILE manually." >> $LOG_FILE
fi

# Restart the network service
echo "Restarting network service..." >> $LOG_FILE
systemctl restart network >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Failed to restart network service. Check network configuration." >> $LOG_FILE
  exit 1
fi

# ------------------------------
# Step 3: Update main cPanel IP
echo "Updating main cPanel IP..." >> $LOG_FILE
/scripts/mainipcheck >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Failed to update main cPanel IP." >> $LOG_FILE
fi

# ------------------------------
# Step 4: Update /etc/hosts
echo "Updating /etc/hosts file..." >> $LOG_FILE
/scripts/fixetchosts >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "Failed to update /etc/hosts file." >> $LOG_FILE
fi

# ------------------------------
# Step 5: Update NAT configuration (if applicable)
echo "Updating NAT configuration (if applicable)..." >> $LOG_FILE
/scripts/build_cpnat >> $LOG_FILE 2>&1

# ------------------------------
# Step 6: Restart IP aliases
echo "Restarting IP aliases..." >> $LOG_FILE
/scripts/restartsrv_ipaliases >> $LOG_FILE 2>&1

# ------------------------------
# Step 7: Update IP addresses for all users
echo "Updating IP addresses for all users..." >> $LOG_FILE
ALL_USERS=$(ls /var/cpanel/users)
for user in $ALL_USERS; do
  echo "Processing user: $user" >> $LOG_FILE
  /usr/local/cpanel/bin/setsiteip $NEW_IP $(/usr/local/cpanel/bin/listdomains --user=$user | grep -Eo '^[^ ]+') >> $LOG_FILE 2>&1
  if [ $? -ne 0 ]; then
    echo "Failed to update IP for user: $user. Check the log file for details." >> $LOG_FILE
  else
    echo "Successfully updated IP for user: $user." >> $LOG_FILE
  fi

done

# ------------------------------
# Step 8: Update DNS records
echo "Updating DNS records..." >> $LOG_FILE
/scripts/rebuilddnsconfig >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "An error occurred while updating DNS records. Check the log file for details."
  exit 1
fi

# ------------------------------
# Step 9: Rebuild and restart web server configuration
echo "Rebuilding web server configuration..." >> $LOG_FILE
/scripts/rebuildhttpdconf >> $LOG_FILE 2>&1
service httpd restart >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "An error occurred while rebuilding the web server configuration. Check the log file for details."
  exit 1
fi

# ------------------------------
# Step 10: Verify new IP configuration
echo "Verifying new IP configuration..." >> $LOG_FILE
ifconfig | grep $NEW_IP >> $LOG_FILE 2>&1
if [ $? -ne 0 ]; then
  echo "New IP address verification failed. Please check the network configuration." >> $LOG_FILE
else
  echo "New IP address verified successfully." >> $LOG_FILE
fi

# ------------------------------
# Finalizing
echo "IP address change completed successfully!"
echo "Details can be found in the log file: $LOG_FILE"

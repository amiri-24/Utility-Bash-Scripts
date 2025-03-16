# Set MySQL root password manually
mysql_root_password=$(grep 'password' /root/.my.cnf | grep -o '[^=]*$' | xargs)

# Color codes
RED='\033[0;31m'        # Red
GREEN='\033[0;32m'      # Green
NC='\033[0m'            # No Color

# Function to delete database using MySQL
function delete_database {
    local db_name="$1"

    echo -e "${RED}Are you sure you want to delete the database '$db_name'? (y/n)${NC}"
    read -r confirmation
    if [[ "$confirmation" == "y" ]]; then
        mysql -u root -p"$mysql_root_password" -e "DROP DATABASE IF EXISTS $db_name;"
        echo -e "${GREEN}Database '$db_name' has been deleted.${NC}"
    else
        echo -e "${RED}Skipping deletion for database '$db_name'.${NC}"
    fi
}

# Get list of databases excluding system databases
databases=$(mysql -u root -p"$mysql_root_password" -e "SHOW DATABASES;" | grep -Ev '^(information_schema|mysql|performance_schema|Database)$')

# Loop through each database and prompt for deletion
for db_name in $databases; do
    delete_database "$db_name"
done

#!/bin/bash

# Prompt the user for the target directory name
read -rp "Enter the directory name to set permissions for (e.g., backups): " target_dir

# Loop through each user directory in /home
for user_dir in /home/*; do
    # Check if the path is a directory
    if [ -d "$user_dir" ]; then
        # Extract the username from the directory path
        username=$(basename "$user_dir")

        # Define the target directory path
        target_path="$user_dir/$target_dir"

        # Check if the target directory exists
        if [ -d "$target_path" ]; then
            echo "Do you want to set permissions for $target_path? (y/n)"
            read -r response

            # Check the user's response
            if [[ "$response" == "y" || "$response" == "Y" ]]; then
                # Execute chown command to change ownership
                chown -R "$username:$username" "$target_path"
                echo "✅ Permissions set for $target_path."
            else
                echo "❌ Skipped $target_path."
            fi
        else
            echo "⚠️ No $target_dir directory found for user $username."
        fi
    fi
done

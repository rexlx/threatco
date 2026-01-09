#!/bin/bash

# --- Configuration ---
# Replace these with your actual ThreatCo server details
SERVER_URL="http://localhost:8080/tools/npm-check"
USER_EMAIL="user@example.com"
API_KEY="your_api_key_here"

# --- Script Logic ---

# Check if find and curl are installed
if ! command -v find &> /dev/null || ! command -v curl &> /dev/null; then
    echo "Error: This script requires 'find' and 'curl' to be installed."
    exit 1
fi

echo "Starting recursive search for package.json files..."
echo "Excluding node_modules directories..."

# Initialize an array to hold our curl form arguments
upload_args=()
count=0

# Find all package.json files, excluding node_modules
# We use a while loop with a null-terminated string to handle spaces in filenames safely
while IFS= read -r -d '' path; do
    # Get the name of the parent directory to use as the project name
    project_folder=$(dirname "$path")
    project_name=$(basename "$project_folder")
    
    # If the package.json is in the root, 'basename' might return '.'
    # We'll default to 'root-project' in that case.
    if [ "$project_name" == "." ] || [ "$project_name" == "/" ]; then
        project_name="root-project"
    fi

    # Create a unique filename for the server to report back
    # Format: project-name-package.json
    remote_filename="${project_name}-package.json"
    
    echo "Found: $path -> Mapping to: $remote_filename"
    
    # Append the curl form flags to our array
    # The syntax -F "field=@local_path;filename=remote_name" allows renaming during upload
    upload_args+=("-F" "files=@${path};filename=${remote_filename}")
    
    ((count++))
done < <(find . -name "package.json" -not -path "*/node_modules/*" -print0)

# Check if we found anything
if [ $count -eq 0 ]; then
    echo "No package.json files found (outside of node_modules)."
    exit 0
fi

echo "------------------------------------------------"
echo "Uploading $count files in a single batch request..."

# Execute the curl command using the accumulated arguments
# We include the Authorization header as required by the server
response=$(curl -s -X POST \
     -H "Authorization: ${USER_EMAIL}:${API_KEY}" \
     "${upload_args[@]}" \
     "$SERVER_URL")

# Check for successful execution
if [ $? -eq 0 ]; then
    echo "Upload Complete. Results:"
    # If you have 'jq' installed, this will pretty-print the JSON output
    if command -v jq &> /dev/null; then
        echo "$response" | jq .
    else
        echo "$response"
    fi
else
    echo "Error: Failed to connect to the ThreatCo server."
    exit 1
fi
#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} $2"
    else
        echo -e "${RED}[FAILED]${NC} $2"
    fi
}

retry_prompt() {
    local step="$1"
    while true; do
        read -p "Error occurred during $step. Do you want to retry? (y/n): " choice
        case "$choice" in
            y|Y ) return 0;;
            n|N ) return 1;;
            * ) echo "Please answer y or n.";;
        esac
    done
}

# Clone node_ops repository
clone_repo() {
    if [ -d "node_ops" ]; then
        echo "node_ops directory already exists. Skipping git clone."
    else
        echo "Cloning node_ops repository..."
        if git clone https://github.com/daasi-ai/node_ops.git; then
            print_status 0 "Cloning node_ops repository"
        else
            print_status 1 "Cloning node_ops repository"
            if retry_prompt "cloning repository"; then
                clone_repo
            else
                exit 1
            fi
        fi
    fi
}

# Create and activate virtual environment
create_venv() {
    local venv_name="daasi_node_ops"
    echo "Checking for virtual environment..."
    if [ ! -d "$venv_name" ]; then
        echo "Creating virtual environment..."
        if python3 -m venv $venv_name; then
            print_status 0 "Creating virtual environment"
        else
            print_status 1 "Creating virtual environment"
            if retry_prompt "creating virtual environment"; then
                create_venv
            else
                exit 1
            fi
        fi
    else
        echo "Virtual environment already exists."
    fi

    echo "Activating virtual environment..."
    if source $venv_name/bin/activate; then
        print_status 0 "Activating virtual environment"
    else
        print_status 1 "Activating virtual environment"
        if retry_prompt "activating virtual environment"; then
            create_venv
        else
            exit 1
        fi
    fi
}

# Install Python dependencies
install_dependencies() {
    echo "Installing Python dependencies..."
    if pip install -r requirements.txt; then
        print_status 0 "Installing Python dependencies"
    else
        print_status 1 "Installing Python dependencies"
        if retry_prompt "installing dependencies"; then
            install_dependencies
        else
            exit 1
        fi
    fi
}

# Fetch attestation report
fetch_attestation_report() {
    echo "Fetching attestation report..."
    read -p "Please enter the IP address of your server: " SERVER_IP
    
    # Try to fetch the report with a timeout
    if curl --location "http://${SERVER_IP}:8090/report" \
        --output attestation_report.json \
        --connect-timeout 10 \
        --max-time 30 \
        --retry 3 \
        --retry-delay 5 \
        --silent --show-error --fail; then
        print_status 0 "Fetching attestation report"
    else
        print_status 1 "Fetching attestation report"
        echo "Error details:"
        curl --location "http://${SERVER_IP}:8090/report" \
            --connect-timeout 10 \
            --max-time 30 \
            --retry 3 \
            --retry-delay 5 \
            --verbose
        if retry_prompt "fetching attestation report"; then
            fetch_attestation_report
        else
            exit 1
        fi
    fi

    # Verify that the file is not empty and contains valid JSON
    if [ -s attestation_report.json ] && jq empty attestation_report.json >/dev/null 2>&1; then
        print_status 0 "Attestation report is valid JSON"
    else
        print_status 1 "Attestation report is empty or not valid JSON"
        if retry_prompt "fetching valid attestation report"; then
            fetch_attestation_report
        else
            exit 1
        fi
    fi
}

# Check for Rust and Cargo installation
check_rust_installation() {
    if ! command -v rustc &> /dev/null || ! command -v cargo &> /dev/null; then
        echo -e "${YELLOW}Rust and Cargo are required but not found. Installing...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
        print_status 0 "Rust and Cargo installed"
    else
        print_status 0 "Rust and Cargo are already installed"
    fi
}

# Run attestation server
run_attestation_server() {
    echo "Starting attestation server..."
    check_rust_installation
    cd Attestation-server || exit

    # Aggressively kill any process using port 8080
    echo "Ensuring port 8080 is free..."
    sudo lsof -ti:8080 | xargs -r sudo kill -9
    sleep 2

    # Double-check if the port is free
    if lsof -i:8080 > /dev/null 2>&1; then
        echo -e "${RED}Failed to free up port 8080. Please check manually.${NC}"
        exit 1
    fi

    # Set RUST_BACKTRACE for more detailed error information
    export RUST_BACKTRACE=1

    if cargo run &> attestation_server.log & then
        ATTESTATION_PID=$!
        sleep 5 # Give some time for the server to start
        if ps -p $ATTESTATION_PID > /dev/null; then
            print_status 0 "Attestation server is running"
        else
            print_status 1 "Failed to start attestation server"
            echo "Error details:"
            cat attestation_server.log
            if retry_prompt "starting attestation server"; then
                run_attestation_server
            else
                exit 1
            fi
        fi
    else
        print_status 1 "Failed to start attestation server"
        echo "Error details:"
        cat attestation_server.log
        if retry_prompt "starting attestation server"; then
            run_attestation_server
        else
            exit 1
        fi
    fi
}

# Process db.json to remove duplicates
process_db_json() {
    local db_path="Attestation-server/db.json"
    if [ -s "$db_path" ]; then
        echo "Processing db.json to remove duplicates"
        # Create a temporary file
        temp_file=$(mktemp)
        # Use jq to remove duplicates based on IP, keeping the last entry for each IP
        jq -s 'flatten | group_by(.ip) | map(.[0])' "$db_path" > "$temp_file"
        # Replace original db.json with processed content
        mv "$temp_file" "$db_path"
        echo "Finished processing db.json"
    else
        echo "db.json is empty or doesn't exist. Skipping duplicate removal."
    fi
}

# Verify certificate
verify_certificate() {
    echo "Verifying certificate..."
    local db_path="Attestation-server/db.json"
    local cert_found=false

    if [ -s "$db_path" ]; then
        # Check if certificate exists for the IP
        if jq -e ".[] | select(.ip == \"$SERVER_IP\")" "$db_path" > /dev/null; then
            cert_found=true
            echo "Certificate found for $SERVER_IP in db.json"
        fi
    fi

    if [ "$cert_found" = false ]; then
        echo "No certificate found for $SERVER_IP. Fetching new attestation report..."
        fetch_attestation_report
    fi

    local max_attempts=3
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        response=$(curl --location --write-out "%{http_code}" --silent --output /dev/null \
            'http://localhost:8080/report' \
            --header 'Content-Type: application/json' \
            --data @attestation_report.json)

        if [ "$response" -eq 200 ]; then
            print_status 0 "Certificate verification"
            return 0
        else
            echo "Attempt $attempt failed. HTTP response: $response"
            if [ $attempt -eq $max_attempts ]; then
                echo "Fetching new attestation report..."
                fetch_attestation_report
            fi
            attempt=$((attempt+1))
            [ $attempt -le $max_attempts ] && sleep 5
        fi
    done

    print_status 1 "Certificate verification failed after $max_attempts attempts"
    return 1
}

# Register node
register_node() {
    echo "Registering node..."
    read -p "Please enter your hotkey: " HOTKEY
    
    # Change to the directory containing register.py
    cd "${HOME}/node_ops" || exit
    
    if [ -f "register.py" ]; then
        if python3 register.py --ip "$SERVER_IP" --hotkey "$HOTKEY"; then
            print_status 0 "Node registration"
        else
            print_status 1 "Node registration"
            if retry_prompt "registering node"; then
                register_node
            else
                exit 1
            fi
        fi
    else
        print_status 1 "register.py not found"
        echo "Current directory: $(pwd)"
        echo "Contents of current directory:"
        ls -la
        if retry_prompt "locating register.py"; then
            register_node
        else
            exit 1
        fi
    fi
    
    # Change back to the original directory
    cd - || exit
}

# Run main API
run_main_api() {
    echo "Starting main API..."
    
    # Ensure port 8088 is free
    echo "Ensuring port 8088 is free..."
    sudo lsof -ti:8088 | xargs -r sudo kill -9
    sleep 2

    # Double-check if the port is free
    if lsof -i:8088 > /dev/null 2>&1; then
        echo -e "${RED}Failed to free up port 8088. Please check manually.${NC}"
        exit 1
    fi

    # Create and activate virtual environment if it doesn't exist
    if [ ! -d "daasi_node_ops" ]; then
        echo "Creating virtual environment daasi_node_ops..."
        python3 -m venv daasi_node_ops
    fi

    # Activate the virtual environment
    echo "Activating virtual environment..."
    source daasi_node_ops/bin/activate

    # Install required packages
    echo "Installing required packages..."
    pip install fastapi uvicorn aiohttp aiofiles cryptography

    python3 main.py --ip "$SERVER_IP" &
    MAIN_API_PID=$!
    sleep 5 # Give some time for the API to start
    if ps -p $MAIN_API_PID > /dev/null; then
        print_status 0 "Main API is running"
    else
        print_status 1 "Failed to start main API"
        echo "Error details:"
        cat main_api.log
        if retry_prompt "starting main API"; then
            run_main_api
        else
            exit 1
        fi
    fi
}

# Run benchmark
run_benchmark() {
    echo "Running benchmark..."
    response=$(curl --location --silent 'http://localhost:8088/run-benchmark')
    if [ $? -eq 0 ]; then
        print_status 0 "Running benchmark"
        echo "Benchmark results:"
        echo "$response" | jq '.' | sed 's/^/    /' # Pretty-print JSON and indent
    else
        print_status 1 "Running benchmark"
        if retry_prompt "running benchmark"; then
            run_benchmark
        else
            exit 1
        fi
    fi
}

# Fetch token usage
fetch_token_usage() {
    echo "Fetching token usage..."
    response=$(curl --location --silent 'http://localhost:8088/fetch_token_usage/')
    if [ $? -eq 0 ]; then
        print_status 0 "Fetching token usage"
        echo "Token usage summary:"
        echo "$response" | jq '.usage_summary' | sed 's/^/    /' # Pretty-print JSON and indent

        echo -e "\nHourly usage visualization:"
        providers=("openai" "groq" "gemini" "claude")
        for provider in "${providers[@]}"; do
            echo "  $provider:"
            echo -n "    Tokens:   "
            for hour in {1..24}; do
                tokens=$(echo "$response" | jq -r ".hourly_usage.$provider.hour_$hour.tokens")
                if [ "$tokens" -eq 0 ]; then
                    echo -n " "
                elif [ "$tokens" -lt 100 ]; then
                    echo -n "▂"
                elif [ "$tokens" -lt 500 ]; then
                    echo -n "▃"
                elif [ "$tokens" -lt 1000 ]; then
                    echo -n "▄"
                elif [ "$tokens" -lt 5000 ]; then
                    echo -n "▅"
                else
                    echo -n "▇"
                fi
            done
            echo ""
            echo -n "    Requests: "
            for hour in {1..24}; do
                requests=$(echo "$response" | jq -r ".hourly_usage.$provider.hour_$hour.requests")
                if [ "$requests" -eq 0 ]; then
                    echo -n " "
                elif [ "$requests" -lt 10 ]; then
                    echo -n "▂"
                elif [ "$requests" -lt 50 ]; then
                    echo -n "▃"
                elif [ "$requests" -lt 100 ]; then
                    echo -n "▄"
                elif [ "$requests" -lt 500 ]; then
                    echo -n "▅"
                else
                    echo -n "▇"
                fi
            done
            echo ""
        done
        echo "    (Each column represents one hour, from oldest to newest)"

        echo -e "\nBenchmark data:"
        echo "$response" | jq '.benchmark_data' | sed 's/^/    /' # Pretty-print JSON and indent
    else
        print_status 1 "Fetching token usage"
        if retry_prompt "fetching token usage"; then
            fetch_token_usage
        else
            exit 1
        fi
    fi
}

# New function to handle API key management
manage_api_keys() {
    while true; do
        echo "Select an option:"
        echo "1. Groq"
        echo "2. OpenAI"
        echo "3. Gemini"
        echo "4. Claude"
        echo "5. Exit"
        read -p "Enter your choice (1-5): " choice

        case $choice in
            1) handle_api_key "groq" ;;
            2) handle_api_key "openai" ;;
            3) handle_api_key "gemini" ;;
            4) handle_api_key "claude" ;;
            5) break ;;
            *) echo "Invalid option. Please try again." ;;
        esac
    done
}

handle_api_key() {
    local provider=$1
    local json_file="${provider}.json"
    
    if [ -f "$json_file" ]; then
        echo "Sending ${provider} API keys to the server..."
        response=$(curl --location --request PUT "http://localhost:8088/apikeys/${provider}" \
            --header 'accept: application/json' \
            --header 'Content-Type: application/json' \
            --header "api_key: $API_KEY" \
            --data @"$json_file")
        echo "Server response:"
        echo "$response" | jq '.'
    else
        echo "${json_file} not found. Please create this file with your API keys."
    fi
}

# Modify the main execution
main() {
    clone_repo
    cd node_ops || exit
    create_venv
    install_dependencies
    
    # Process db.json to remove duplicates
    process_db_json

    # Fetch SERVER_IP only once
    read -p "Please enter the IP address of your server: " SERVER_IP

    # Store the node_ops directory path
    NODE_OPS_DIR=$(pwd)

    run_attestation_server
    cd "$NODE_OPS_DIR" || exit

    if verify_certificate; then
        echo "Certificate verification successful. Skipping registration."
    else
        echo "Certificate verification failed. Attempting registration."
        register_node
    fi

    # Ensure we're in the node_ops directory before continuing
    cd "$NODE_OPS_DIR" || exit

    # Run main API before entering the choice
    run_main_api

    echo -e "\n${YELLOW}Setup and initialization complete!${NC}"
    echo -e "Your API key can be found in the ${GREEN}apikey.json${NC} file."

    while true; do
        echo -e "\nSelect an option:"
        echo "1. Run benchmark and fetch token usage"
        echo "2. Manage API keys"
        echo "3. Exit"
        read -p "Enter your choice (1-3): " choice

        case $choice in
            1)
                run_benchmark
                fetch_token_usage
                ;;
            2) manage_api_keys ;;
            3) break ;;
            *) echo "Invalid option. Please try again." ;;
        esac
    done

    # Cleanup
    kill $ATTESTATION_PID
    kill $MAIN_API_PID
}

# Run the main function
main

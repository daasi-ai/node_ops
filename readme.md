# DAASI-Node_ops

This repository contains the necessary components for setting up and running the node enclave ( if you dont have the node enclave runnning, Its recommended to run it first) . Follow these detailed, step-by-step instructions to get your node_ops operational.

## Quick Install

Follow these steps to quickly set up your node:

1. Create a file named `ops.sh` and copy the following code into it:

2. Make the script executable:
   ```bash
   chmod +x ops.sh
   ```

3. Run the script:
   ```bash
   ./ops.sh
   ```

4. When prompted, enter your enclave IP address and hotkey.

5. To add your API keys (e.g., Groq), create a JSON file named `groq.json` with your API key:
   ```json
   {
     "api_key": "your-groq-api-key-here"
   }
   ```

6. Use the script's menu to manage API keys and run benchmarks.

   - Choose "Manage API keys" to add your Groq keys from the `groq.json` file.
   - You can add other API keys (OpenAI, Gemini, Claude) in a similar manner.

## Prerequisites
- Have the Enclave Running and verify if its generating a report first with a known IP address
- Rust (latest stable version)
- Python 3.8 or higher
- Your unique hotkey registered on the subnet, You will insert the hotkey inside the enclave

## Detailed Setup Process

### Step 1: Fetch the Attestation Report from the Enclave

1. Ensure your enclave is running and you have its IP address.

2. Use curl to fetch the attestation report from your enclave:
   ```bash
   curl --location 'http://<YOUR_ENCLAVE_IP>:8090/report' > attestation_report.json
   ```
   Replace `<YOUR_ENCLAVE_IP>` with your actual enclave IP address.

3. Verify that the `attestation_report.json` file has been created and contains the report data.

### Step 2: Set Up and Run the Attestation Server

1. Navigate to the Attestation Server directory:
   ```bash
   cd Node_ops/Attestation-server
   ```

2. Before running the server, ensure the `measurement.json` file is up to date:
   ```bash
   nano measurement.json
   ```
   Update the measurement value if necessary:
   ```json
   {
       "measurement":"bb9f42ca8fd81c7394d615df0de6ba71579f80e0aadd0d7011b8ac1263d729c4c481cc2af9bef05473191cc4f3f60a78"
   }
   ```

3. Build and run the Rust server:
   ```bash
   cargo run
   ```
   This will compile and start the verifier, which listens on port 8080 for attestation reports.

4. Keep this terminal window open to keep the server running.

### Step 3: Submit the Attestation Report

1. Open a new terminal window.

2. Submit the attestation report to the Attestation Server:
   ```bash
   curl --location 'http://localhost:8080/report' \
   --header 'Content-Type: application/json' \
   --data @attestation_report.json
   ```

3. If successful, you'll receive an "Ok" response, and the certificate will be saved in `db.json`. 
   If you receive an error, check the Attestation Server logs for details and try again.

### Step 4: Prepare the Registration Script

1. Open the `register.py` file in a text editor:
   ```bash
   nano register.py
   ```

2. Locate the section where the hotkey is defined. It might look something like this:
   ```python
   hotkey = "your_hotkey_here"
   ```

3. Replace `"your_hotkey_here"` with your actual hotkey. For example:
   ```python
   hotkey = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJMxx4ty"
   ```

4. Save and close the file.

### Step 5: Register Your Node

1. Run the registration script, providing your enclave IP:
   ```bash
   python3 register.py --ip <YOUR_ENCLAVE_IP>
   ```
   Replace `<YOUR_ENCLAVE_IP>` with your actual enclave IP address.

2. The script will use the hotkey you added in Step 4 and the provided IP to register your node.

3. If successful, an API key will be generated and saved in `apikey.json`.

### Step 6: Configure and Start the Main API

1. Open `main.py` in a text editor:
   ```bash
   nano main.py
   ```

2. Locate the `API_KEY` variable and update it with the key from `apikey.json`:
   ```python
   API_KEY = "your_generated_api_key_here"
   ```

3. Save and close the file.

4. Run the main API:
   ```bash
   python3 main.py
   ```

### Step 7: Benchmark and Verify

1. Run the benchmark:
   ```bash
   curl --location 'http://localhost:8088/run-benchmark'
   ```
   This may take several minutes to complete.

2. Once the benchmark is complete, verify the results and node status:
   ```bash
   curl --location 'http://localhost:8088/fetch_token_usage/'
   ```

### Step 8: Update API Keys with limits to start getting queries

If you need to update API keys for different providers, you can use PUT requests. Here's an example for updating Groq API keys:

```bash
curl --location --request PUT 'http://localhost:8088/apikeys/groq' \
--header 'accept: application/json' \
--header 'Content-Type: application/json' \
--header 'api_key: your_api_key_here' \
--data '{
    "keys": {
      "gsk_example1xxxxxYourActualKeyHerexxxxx": 5000,
      "gsk_example2xxxxxYourActualKeyHerexxxxx": 10000
    }
  }'
```

Replace `your_api_key_here` with the API key from `apikey.json`, and update the Groq keys and their associated rate limits as needed.

## Troubleshooting

If you encounter issues during setup or operation, try these steps:

1. **Attestation Server Issues:**
   - Ensure Rust is properly installed and up to date.
   - Check that the `measurement.json` file contains the correct measurement.
   - Verify that port 8080 is not being used by another application.

2. **Registration Problems:**
   - Double-check that your hotkey is correctly entered in `register.py`.
   - Ensure your enclave IP is correct and the enclave is running.

3. **API Key Issues:**
   - Verify that `apikey.json` was generated and contains a valid key.
   - Ensure you're using the correct API key in `main.py` and when making requests.

4. **Benchmark or Token Usage Fetch Failures:**
   - Check that the main API is running (`python3 main.py`).
   - Ensure your network connection is stable.

5. **General Troubleshooting:**
   - Check the logs of each component for detailed error messages.
   - Ensure all prerequisites are correctly installed and up to date.
   - Verify that you're using the correct IP addresses throughout the process.

If problems persist after trying these steps, please send a message on discord with detailed information about the error and the steps you've taken.

## Additional Information

- The Attestation Server verifies the integrity of new miner instances using AMD SEV-SNP technology.
- Keep your API keys and hotkey secure and never share them publicly, If the API Key is leaked anyone can steal or access your enclave. The API key can only be created once and its first come - first serve once the enclave start if have issues getting the API Keys the only option is to restart the Enclave and try again
- Regularly check for updates to this repository to ensure you're running the latest version of the node-ops.

For more advanced configuration options or detailed information about the node's operation, please messages on discord

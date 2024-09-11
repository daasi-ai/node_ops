import ssl
import json
import logging
import asyncio
import aiohttp
import aiofiles
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import os
import base64
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import uvicorn
import re
import argparse

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global dictionary to store pinned certificates
pinned_certs = {}

app = FastAPI()

# Configuration
PORT = 8080
API_KEY = None  # We'll set this based on the IP address

async def load_api_key(ip_address):
    try:
        async with aiofiles.open('apikey.json', 'r') as f:
            content = await f.read()
            api_keys = json.loads(content)
            if ip_address in api_keys:
                return api_keys[ip_address]
            else:
                raise ValueError(f"No API key found for IP: {ip_address}")
    except FileNotFoundError:
        raise FileNotFoundError("apikey.json file not found")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON in apikey.json")

async def get_api_key():
    if API_KEY is None:
        raise HTTPException(status_code=500, detail="API key not set")
    return API_KEY

async def load_cert_from_db(host):
    db_path = os.path.join(os.path.dirname(__file__), 'Attestation-server', 'db.json')
    try:
        async with aiofiles.open(db_path, 'r') as f:
            content = await f.read()
        logger.debug(f"Raw content of db.json: {content}")

        # Split the content into separate JSON objects/arrays
        json_parts = content.strip().split('\n')
        
        all_entries = []
        for part in json_parts:
            try:
                parsed = json.loads(part)
                if isinstance(parsed, list):
                    all_entries.extend(parsed)
                elif isinstance(parsed, dict):
                    all_entries.append(parsed)
            except json.JSONDecodeError:
                logger.warning(f"Skipping invalid JSON: {part}")

        logger.debug(f"Parsed JSON data: {all_entries}")

        for entry in all_entries:
            if entry.get('ip') == host:
                cert = entry.get('cert')
                if cert:
                    logger.info(f"Certificate found in db.json for {host}")
                    return cert
        
        logger.warning(f"No certificate found in db.json for {host}")
        return None

    except FileNotFoundError:
        logger.warning(f"db.json not found at {db_path}")
    except Exception as e:
        logger.error(f"Unexpected error while loading cert from db: {str(e)}")
    
    return None

async def verify_cert(cert_der, trusted_cert_pem):
    logger.info("Starting certificate verification")
    try:
        if isinstance(cert_der, dict):
            logger.error("Received certificate data is not in the expected format")
            return False
        
        if not cert_der:
            logger.error("No certificate data available")
            return False

        cert = x509.load_der_x509_certificate(cert_der)
        trusted_cert = x509.load_pem_x509_certificate(trusted_cert_pem.encode())

        logger.debug(f"Received certificate subject: {cert.subject}")
        logger.debug(f"Trusted certificate subject: {trusted_cert.subject}")

        # Compare the entire certificate, not just the public key
        if cert == trusted_cert:
            logger.info("Certificate verification successful: Certificates match")
            return True
        else:
            logger.error("Certificate verification failed: Certificates do not match")
            return False
    except Exception as e:
        logger.error(f"Error during certificate verification: {e}")
        return False

async def fetch_from_server(endpoint: str, method: str, api_key: str = None, data: dict = None):
    global pinned_certs

    logger.info(f"Fetching from server: {method} {endpoint}")

    if HOST in pinned_certs:
        trusted_cert_pem = pinned_certs[HOST]
        logger.info(f"Using pinned certificate for {HOST}")
    else:
        trusted_cert_pem = await load_cert_from_db(HOST)
        if trusted_cert_pem:
            pinned_certs[HOST] = trusted_cert_pem
            logger.info(f"Loaded certificate for {HOST} from db.json")
        else:
            logger.error(f"IP missing: No trusted certificate found for {HOST}")
            print(f"IP missing: {HOST}")
            return None

    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification

    # Load the trusted certificate into the SSL context
    try:
        cert = x509.load_pem_x509_certificate(trusted_cert_pem.encode())
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        ssl_context.load_verify_locations(cadata=cert_der)
    except Exception as e:
        logger.error(f"Error loading certificate: {e}")
        return None

    # Set a longer timeout for benchmark requests
    timeout = aiohttp.ClientTimeout(total=300 if endpoint == "/run-benchmark" else 60)

    url = f"https://{HOST}:{PORT}{endpoint}"
    headers = {"Host": HOST}
    if api_key:
        headers["api_key"] = api_key

    logger.info(f"Sending request to: {url}")
    logger.debug(f"Headers: {headers}")
    logger.debug(f"Data: {data}")

    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.request(method, url, ssl=ssl_context, headers=headers, json=data) as response:
                logger.debug("Request sent successfully")
                
                # Certificate verification is now handled by the SSL context
                logger.info("Certificate verification completed by SSL context")

                body = await response.text()
                logger.debug("Response body retrieved")

                if response.status == 200:
                    logger.info("Request successful")
                    try:
                        return json.loads(body)
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse JSON response: {body}")
                        return None
                else:
                    logger.error(f"Request failed with status code: {response.status}")
                    return None

        except ssl.SSLCertVerificationError as ssl_error:
            logger.error(f"SSL Certificate Verification Error: {ssl_error}")
            return None
        except aiohttp.ClientConnectorError as e:
            logger.error(f"Connection error: {e}")
            return None
        except asyncio.TimeoutError:
            logger.error("Request timed out")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during request: {e}")
            logger.error(traceback.format_exc())
            return None

@app.get("/run-benchmark")
async def api_run_benchmark(api_key: str = Depends(get_api_key)):
    logger.info("Starting benchmark run")
    try:
        result = await fetch_from_server("/run-benchmark", "GET", api_key)
        if result:
            logger.info("Benchmark completed successfully")
            return result
        else:
            logger.error("Benchmark failed to run or return results")
            raise HTTPException(status_code=500, detail="Failed to run benchmark: No results returned")
    except Exception as e:
        logger.error(f"Exception in api_run_benchmark: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An error occurred while running the benchmark: {str(e)}")

@app.get("/fetch_token_usage/")
async def api_fetch_token_usage(api_key: str = Depends(get_api_key)):
    result = await fetch_from_server("/fetch_token_usage/", "GET", api_key)
    if result:
        return result
    else:
        raise HTTPException(status_code=500, detail="Failed to fetch token usage data")

@app.get("/apikeys/{api_name}")
async def api_get_apikeys(api_name: str, api_key: str = Depends(get_api_key)):
    result = await fetch_from_server(f"/apikeys/{api_name}", "GET", api_key)
    if result:
        return result
    else:
        raise HTTPException(status_code=500, detail=f"Failed to get API keys for {api_name}")

@app.put("/apikeys/{api_name}")
async def api_update_apikeys(api_name: str, api_keys: dict, api_key: str = Depends(get_api_key)):
    result = await fetch_from_server(f"/apikeys/{api_name}", "PUT", api_key, api_keys)
    if result:
        return result
    else:
        raise HTTPException(status_code=500, detail=f"Failed to update API keys for {api_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the main API server.")
    parser.add_argument("--ip", required=True, help="IP address of the node")
    args = parser.parse_args()

    HOST = args.ip

    try:
        API_KEY = asyncio.run(load_api_key(HOST))
        logger.info(f"API key loaded for IP: {HOST}")
        
        # Check if port 8088 is in use
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 8088))
        if result == 0:
            logger.error("Port 8088 is already in use. Please free the port and try again.")
            exit(1)
        sock.close()

        uvicorn.run(app, host="0.0.0.0", port=8088)
    except Exception as e:
        logger.error(f"Failed to start the server: {str(e)}")
        exit(1)
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
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import uvicorn
import re

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global dictionary to store pinned certificates
pinned_certs = {}

app = FastAPI()

# Configuration
HOST = "103.46.xx.xx"
PORT = 8080
API_KEY = "c5fdxb48-0axa-418x-8c08-92xx71148bxx"  # Replace with your actual API key for benchmark and API key update

async def load_cert_from_db(host):
    db_path = os.path.join(os.path.dirname(__file__), 'Attestation-server', 'db.json')
    try:
        async with aiofiles.open(db_path, 'r') as f:
            content = await f.read()
            data = json.loads(content)
            if data['ip'] == host:
                cert = data['cert']
                # Clean up the certificate
                cert = re.sub(r'\s+', '\n', cert)
                cert = f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"
                logger.info(f"Certificate found in db.json for {host}")
                return cert
    except FileNotFoundError:
        logger.warning(f"db.json not found at {db_path}")
    except json.JSONDecodeError:
        logger.error("Error decoding db.json")
    logger.warning(f"No certificate found in db.json for {host}")
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
async def api_run_benchmark():
    logger.info("Starting benchmark run")
    try:
        result = await fetch_from_server("/run-benchmark", "GET", API_KEY)
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
async def api_fetch_token_usage():
    result = await fetch_from_server("/fetch_token_usage/", "GET")
    if result:
        return result
    else:
        raise HTTPException(status_code=500, detail="Failed to fetch token usage data")

@app.get("/apikeys/{api_name}")
async def api_get_apikeys(api_name: str):
    result = await fetch_from_server(f"/apikeys/{api_name}", "GET", API_KEY)
    if result:
        return result
    else:
        raise HTTPException(status_code=500, detail=f"Failed to get API keys for {api_name}")

@app.put("/apikeys/{api_name}")
async def api_update_apikeys(api_name: str, api_keys: dict):
    result = await fetch_from_server(f"/apikeys/{api_name}", "PUT", API_KEY, api_keys)
    if result:
        return result
    else:
        raise HTTPException(status_code=500, detail=f"Failed to update API keys for {api_name}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8088)
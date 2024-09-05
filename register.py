import ssl
import socket
import json
import hashlib
import OpenSSL.crypto
import aiofiles
import asyncio
import logging
import argparse
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ensure_pem_format(cert_pem):
    """Ensure the certificate has proper PEM formatting with newlines."""
    cert_pem = cert_pem.strip()
    if "-----BEGIN CERTIFICATE-----" not in cert_pem or "-----END CERTIFICATE-----" not in cert_pem:
        raise ValueError("Invalid certificate: missing BEGIN or END markers")
    
    cert_pem = cert_pem.replace("\n", "")
    cert_pem = cert_pem.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
    cert_pem = cert_pem.replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----\n")
    
    # Split the certificate content into lines of 64 characters
    parts = cert_pem.split('\n')
    formatted_cert = parts[0] + '\n'
    cert_content = ''.join(parts[1:-2])
    formatted_cert += '\n'.join([cert_content[i:i+64] for i in range(0, len(cert_content), 64)])
    formatted_cert += '\n' + parts[-2] + '\n' + parts[-1] + '\n'
    
    return formatted_cert

async def load_cert_from_db(host):
    db_path = os.path.join(os.path.dirname(__file__), 'Attestation-server', 'db.json')
    try:
        async with aiofiles.open(db_path, 'r') as f:
            content = await f.read()
            for line in content.splitlines():
                entry = json.loads(line)
                if entry['ip'] == host:
                    return entry['cert']
    except FileNotFoundError:
        print(f"db.json not found at {db_path}")
    except json.JSONDecodeError:
        print("Error decoding db.json")
    print(f"No certificate found in db.json for {host}")
    return None

async def get_cert_hash_from_db(host):
    cert_pem = await load_cert_from_db(host)
    if cert_pem is None:
        raise FileNotFoundError(f"Certificate for {host} not found in database")
    
    # Ensure the certificate has the correct PEM format
    cert_pem = ensure_pem_format(cert_pem)
    
    cert_data = cert_pem.encode()
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
    return hashlib.sha256(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509)).hexdigest()

async def make_api_request(host, port, endpoint, hotkey):
    try:
        logging.info(f"Starting API request to {host}:{port}{endpoint}")
        pinned_cert_hash = await get_cert_hash_from_db(host)
        logging.info(f"Pinned cert hash: {pinned_cert_hash}")

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        logging.info("SSL context created")

        trusted_cert_pem = await load_cert_from_db(host)
        if trusted_cert_pem is None:
            raise FileNotFoundError(f"Trusted certificate for {host} not found in database")
        logging.info("Trusted certificate loaded from database")

        trusted_cert_pem = ensure_pem_format(trusted_cert_pem)
        logging.info("Certificate PEM format ensured")

        trusted_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, trusted_cert_pem.encode())
        trusted_cert_der = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, trusted_cert)
        context.load_verify_locations(cadata=trusted_cert_der)
        logging.info("Trusted certificate loaded into SSL context")

        logging.info(f"Attempting to connect to {host}:{port}")
        with socket.create_connection((host, port)) as sock:
            logging.info("TCP connection established")
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                logging.info("SSL connection established")
                cert = secure_sock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                cert_hash = hashlib.sha256(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509)).hexdigest()
                logging.info(f"Received certificate hash: {cert_hash}")

                if cert_hash != pinned_cert_hash:
                    raise ssl.SSLError(f"Certificate hash mismatch. Expected {pinned_cert_hash}, got {cert_hash}")
                logging.info("Certificate hash verified")

                data = json.dumps({"hotkey": hotkey}).encode('utf-8')
                request = f"POST {endpoint} HTTP/1.1\r\n"
                request += f"Host: {host}\r\n"
                request += "Content-Type: application/json\r\n"
                request += f"Content-Length: {len(data)}\r\n"
                request += "\r\n"
                request = request.encode('utf-8') + data

                logging.info("Sending request")
                secure_sock.sendall(request)
                logging.info("Request sent")

                response = b""
                while True:
                    chunk = secure_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                logging.info("Response received")

                headers, body = response.split(b'\r\n\r\n', 1)
                logging.info("Response parsed")
                return body.decode('utf-8')
    except socket.error as e:
        logging.error(f"Socket error: {e}")
        raise
    except ssl.SSLError as e:
        logging.error(f"SSL error: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise

async def save_api_key(ip, api_key):
    try:
        async with aiofiles.open('apikey.json', 'r') as f:
            content = await f.read()
            data = json.loads(content) if content else {}
    except FileNotFoundError:
        data = {}

    data[ip] = api_key

    async with aiofiles.open('apikey.json', 'w') as f:
        await f.write(json.dumps(data, indent=2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Register a node and get an API key.")
    parser.add_argument("--ip", required=True, help="IP address of the node to register")
    args = parser.parse_args()

    host = args.ip
    port = 8101
    endpoint = "/register"
    hotkey = "xxxx"

    try:
        result = asyncio.run(make_api_request(host, port, endpoint, hotkey))
        logging.info(f"Response: {result}")
        json_result = json.loads(result)
        if 'api_key' in json_result:
            api_key = json_result['api_key']
            logging.info(f"API Key received: {api_key}")
            asyncio.run(save_api_key(host, api_key))
            logging.info(f"API Key saved for {host}")
        else:
            logging.warning("Failed to get API key")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

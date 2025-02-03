import logging
import datetime
from time import sleep
from kubernetes import client, config
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import base64
import os

# Read synchronization interval from environment variables (default: 300 seconds)
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", 300))

# Read logging levels from environment variables or use defaults
DEFAULT_LOGGING_LEVEL = os.getenv("DEFAULT_LOGGING_LEVEL", "INFO").upper()
AZURE_LOGGING_LEVEL = os.getenv("AZURE_LOGGING_LEVEL", "WARNING").upper()

# Configure the main logging system
logging.basicConfig(
    level=getattr(logging, DEFAULT_LOGGING_LEVEL, logging.INFO),
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Suppress general Azure SDK logs unless explicitly enabled
logging.getLogger("azure").setLevel(getattr(logging, AZURE_LOGGING_LEVEL, logging.WARNING))

# Restrict HTTP request/response logs to DEBUG level
http_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
http_logger.setLevel(logging.DEBUG if DEFAULT_LOGGING_LEVEL == "DEBUG" else logging.WARNING)

# Suppress unnecessary logs from `urllib3` unless debugging is enabled
logging.getLogger("urllib3").setLevel(AZURE_LOGGING_LEVEL)


def timestamp():
    """
    Returns the current timestamp as a string.
    Can be used manually if required.
    """
    return str(datetime.datetime.now())


def get_certificates(namespace):
    """
    Fetch all Certificate resources from the specified namespace.
    """
    logging.debug(f"Fetching certificates from namespace: {namespace}")
    config.load_kube_config()
    custom_objects_api = client.CustomObjectsApi()
    certificates = custom_objects_api.list_namespaced_custom_object(
        group="cert-manager.io",
        version="v1",
        namespace=namespace,
        plural="certificates"
    )
    logging.info(f"Fetched {len(certificates['items'])} certificates from namespace: {namespace}")
    return certificates["items"]


def get_secret(namespace, secret_name):
    """
    Fetch the Kubernetes secret by name from the specified namespace.
    """
    logging.debug(f"Fetching secret '{secret_name}' from namespace: {namespace}")
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(secret_name, namespace)
    logging.info(f"Fetched secret '{secret_name}' successfully.")
    return secret


# Feature toggle for dry run mode
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("true", "1", "yes", "enabled")


def upload_to_key_vault(vault_url, certificate_name, cert, key):
    """
    Upload a certificate to Azure Key Vault if it doesn't already exist.
    If DRY_RUN is enabled, log the intended action but do not upload.
    """
    logging.debug(f"Starting upload process for certificate: {certificate_name}")
    credential = DefaultAzureCredential()
    certificate_client = CertificateClient(vault_url=vault_url, credential=credential)

    private_key = load_pem_private_key(key.encode("utf-8"), password=None, backend=default_backend())
    certificate = load_pem_x509_certificate(cert.encode("utf-8"), backend=default_backend())
    cert_thumbprint = certificate.fingerprint(SHA1()).hex()

    try:
        existing_cert = certificate_client.get_certificate(certificate_name)
        existing_cert_thumbprint = existing_cert.properties.x509_thumbprint.hex()
        if cert_thumbprint == existing_cert_thumbprint:
            logging.info(f"Certificate {certificate_name} already exists in Key Vault with the same thumbprint. Skipping upload.")
            return False
    except Exception:
        logging.warning(f"Certificate {certificate_name} not found in Key Vault. Proceeding with upload...")

    if DRY_RUN:
        logging.info(f"[DRY RUN] Would upload certificate '{certificate_name}' to Key Vault.")
        return True  # Simulate success in dry run mode

    # Create PFX data without encryption
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=certificate_name.encode("utf-8"),
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )

    # Upload the certificate to Key Vault
    certificate_client.import_certificate(certificate_name=certificate_name, certificate_bytes=pfx_data)
    logging.info(f"Certificate {certificate_name} successfully uploaded to Key Vault.")
    return True


# Define a mapping matrix for AKS secret names to Key Vault certificate names
NAME_MAPPING = {
    "acme-crt-wildcard-test-currys-app-secret": "wildcard-test-currys-app",
    "acme-crt-wildcard-test-elcare-com-secret": "wildcard-test-elcare-com",
    # Add more mappings as needed
}

# Feature toggle for enabling/disabling name mapping
USE_NAME_MAPPING = os.getenv("USE_NAME_MAPPING", "false").lower() in ("true", "1", "yes", "enabled")

# If strict mapping is enabled, only secrets from NAME_MAPPING will be used
STRICT_NAME_MAPPING = os.getenv("STRICT_NAME_MAPPING", "false").lower() in ("true", "1", "yes", "enabled")


def get_certificate_name(secret_name):
    """
    Get the corresponding Key Vault certificate name for the given Kubernetes secret name.

    - If USE_NAME_MAPPING is False -> return original secret_name.
    - If STRICT_NAME_MAPPING is True -> only return mapped names, ignore others.
    - If STRICT_NAME_MAPPING is False -> return mapped names where available, otherwise return original.
    """
    if not USE_NAME_MAPPING:
        return secret_name.replace(".", "-")  # Default behavior

    if STRICT_NAME_MAPPING:
        return NAME_MAPPING.get(secret_name)  # Return mapped name or None if not found

    return NAME_MAPPING.get(secret_name, secret_name.replace(".", "-"))  # Return mapped name or fallback


def main():
    namespace = "ingresscontrollers"
    vault_url = os.getenv("AZURE_KEYVAULT_URL")
    if not vault_url:
        logging.error("Missing environment variable AZURE_KEYVAULT_URL. Exiting.")
        return

    logging.info(f"Starting certificate sync process. Running every {SYNC_INTERVAL} seconds.")

    while True:
        certificates = get_certificates(namespace)
        for certificate in certificates:
            secret_name = certificate["spec"]["secretName"]
            certificate_name = get_certificate_name(secret_name)

            if STRICT_NAME_MAPPING and certificate_name is None:
                logging.warning(f"Skipping secret '{secret_name}' because it is not in NAME_MAPPING.")
                continue

            logging.info(f"Processing certificate: {certificate['metadata']['name']}")
            secret = get_secret(namespace, secret_name)
            cert = base64.b64decode(secret.data["tls.crt"]).decode("utf-8")
            key = base64.b64decode(secret.data["tls.key"]).decode("utf-8")

            logging.debug(f"Uploading certificate {certificate_name} to Key Vault...")
            if upload_to_key_vault(vault_url, certificate_name, cert, key):
                logging.info(f"Certificate {certificate_name} successfully uploaded to Key Vault.")

        logging.info(f"Sync completed. Sleeping for {SYNC_INTERVAL} seconds.")
        sleep(SYNC_INTERVAL)  # Wait before next sync


if __name__ == "__main__":
    try:
        logging.info("Starting certificate sync process.")
        main()
        logging.info("Certificate sync process completed.")
    except Exception as e:
        logging.exception("An unexpected error occurred during execution.")

import json
import logging
import datetime
from time import sleep
from kubernetes import client, config
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import load_pem_x509_certificates
from cryptography.hazmat.backends import default_backend
import base64
import os

# Read logging levels from environment variables or use defaults
DEFAULT_LOGGING_LEVEL = os.getenv("DEFAULT_LOGGING_LEVEL", "INFO").upper()
AZURE_LOGGING_LEVEL = os.getenv("AZURE_LOGGING_LEVEL", "WARNING").upper()

# Configure the main logging system
logging.basicConfig(
    level=getattr(logging, DEFAULT_LOGGING_LEVEL, logging.INFO),
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Feature toggle for dry run mode
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("true", "1", "yes", "enabled")

# Read synchronization interval from environment variables (default: 300 seconds)
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", 300))

# Configurable options
USE_NAME_MAPPING = os.getenv("USE_NAME_MAPPING", "true").lower() in ("true", "1", "yes", "enabled")
STRICT_NAME_MAPPING = os.getenv("STRICT_NAME_MAPPING", "true").lower() in ("true", "1", "yes", "enabled")

# Default tags (used if no specific tags are defined)
DEFAULT_TAGS = {"created-by": "cert-manager-kv-syncer"}

CERTIFICATE_CONFIG = {}
config_file_path = "/etc/cert-manager-kv-syncer/certificate-config.json"

if USE_NAME_MAPPING:
    if os.path.exists(config_file_path):
        logging.info(f"Loading configuration from {config_file_path}")
        try:
            with open(config_file_path, "r") as f:
                CERTIFICATE_CONFIG = json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {e}")
            exit(1)
    else:
        CERTIFICATE_CONFIG_PATH = os.getenv("CERTIFICATE_CONFIG_PATH")

        if not CERTIFICATE_CONFIG_PATH:
            logging.error("CERTIFICATE_CONFIG_PATH environment variable is not set or is empty")
            exit(1)

        try:
            with open(CERTIFICATE_CONFIG_PATH, "r") as file:
                CERTIFICATE_CONFIG = json.load(file)
            logging.info(f"Configuration file {CERTIFICATE_CONFIG_PATH} loaded successfully.")
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {CERTIFICATE_CONFIG_PATH}")
            exit(1)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {e}")
            exit(1)

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


def parse_namespaces(env_value):
    """
    Parses the SEARCH_NAMESPACES environment variable.
    - If empty, it searches in all namespaces.
    - If it contains "!namespace", that namespace will be excluded (only if no specific namespaces are defined).
    - If specific namespaces are defined, "!namespace" logic is ignored.
    """
    raw_list = os.getenv(env_value, "").split(",") if os.getenv(env_value) else []

    include_namespaces = {ns for ns in raw_list if not ns.startswith("!")}
    exclude_namespaces = {ns[1:] for ns in raw_list if ns.startswith("!")}

    # If specific namespaces are defined, ignore `!namespace` exclusion logic
    if include_namespaces:
        return include_namespaces, set()

    return set(), exclude_namespaces


def get_all_namespaces():
    """
    Retrieves a list of all namespaces in the cluster.
    """
    v1 = client.CoreV1Api()
    namespaces = v1.list_namespace()
    return [ns.metadata.name for ns in namespaces.items]


def load_kubernetes_config():
    """
    Automatically loads Kubernetes configuration based on the environment.
    - If running inside AKS, it loads in-cluster config.
    - Otherwise, it falls back to local kubeconfig.
    """
    try:
        config.load_incluster_config()
        logging.info("Running inside AKS - Using in-cluster Kubernetes config.")
    except config.ConfigException:
        config.load_kube_config()
        logging.info("Running locally - Using kubeconfig.")


def get_certificates():
    """
    Fetches certificates based on SEARCH_NAMESPACES settings.
    """
    load_kubernetes_config()
    custom_objects_api = client.CustomObjectsApi()

    include_namespaces, exclude_namespaces = parse_namespaces("SEARCH_NAMESPACES")

    if not include_namespaces:
        # If no specific namespaces are defined, fetch all and apply `!namespace` exclusion logic
        all_namespaces = get_all_namespaces()
        namespaces_to_search = [ns for ns in all_namespaces if ns not in exclude_namespaces]
    else:
        namespaces_to_search = list(include_namespaces)  # Use only specified namespaces

    logging.info(f"Searching certificates in defined namespaces...")

    all_certificates = []
    for ns in namespaces_to_search:
        logging.debug(f"Fetching certificates from namespace '{ns}'...")
        try:
            certs = custom_objects_api.list_namespaced_custom_object(
                group="cert-manager.io",
                version="v1",
                namespace=ns,
                plural="certificates"
            )
            all_certificates.extend(certs["items"])
        except Exception as e:
            logging.error(f"Failed to fetch certificates from namespace '{ns}': {str(e)}")

    return all_certificates


def get_secret(namespace, secret_name):
    """
    Fetch the Kubernetes secret by name from the specified namespace.
    """
    logging.debug(f"Fetching secret '{secret_name}' from namespace: {namespace}")
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(secret_name, namespace)
    logging.info(f"Fetched secret '{secret_name}' successfully from namespace '{namespace}'.")
    return secret


def upload_to_key_vault(vault_url, certificate_name, cert, key, tags):
    """
    Upload a certificate to Azure Key Vault if it doesn't already exist.
    If DRY_RUN is enabled, log the intended action but do not upload.
    """
    logging.debug(f"Starting upload process for certificate: {certificate_name} with tags: {tags}")
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
    certificate_client = CertificateClient(vault_url=vault_url, credential=credential)

    private_key = load_pem_private_key(key.encode("utf-8"), password=None, backend=default_backend())
    certificates = load_pem_x509_certificates(cert.encode("utf-8"))

    # Find the primary certificate (the one that corresponds to the private key)
    # The serialize_key_and_certificates function distinguishes between the main certificate that matches
    # the private key and the rest that is part of the chain
    main_certificate = None
    chain_certificates = []

    for cert in certificates:
        if cert.public_key().public_numbers() == private_key.public_key().public_numbers():
            main_certificate = cert
        else:
            chain_certificates.append(cert)

    if main_certificate is None:
        raise ValueError("Could not find a certificate matching the private key.")

    # This value must match the value in the X.509 SHA-1 Thumbprint (in hex) in Azure portal
    cert_thumbprint = main_certificate.fingerprint(SHA1()).hex()

    try:
        existing_cert = certificate_client.get_certificate(certificate_name)
        # Value visible in Azure portal as X.509 SHA-1 Thumbprint (in hex) attribute
        existing_cert_thumbprint = existing_cert.properties.x509_thumbprint.hex()
        if cert_thumbprint == existing_cert_thumbprint:
            logging.info(
                f"Certificate {certificate_name} already exists in Key Vault with the same thumbprint. Skipping upload.")
            return False
    except Exception:
        logging.warning(f"Certificate {certificate_name} not found in Key Vault. Proceeding with upload...")

    if DRY_RUN:
        logging.info(f"[DRY RUN] Would upload certificate '{certificate_name}' to Key Vault with tags: {tags}")
        return True  # Simulate success in dry run mode

    # Create PFX data without encryption
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=certificate_name.encode("utf-8"),
        key=private_key,
        cert=main_certificate,
        cas=chain_certificates if chain_certificates else None,
        encryption_algorithm=NoEncryption(),
    )

    # Upload the certificate to Key Vault
    try:
        certificate_client.import_certificate(
            certificate_name=certificate_name,
            certificate_bytes=pfx_data,
            tags=tags
        )
        return True
    except Exception as e:
        logging.error(f"Failed to upload certificate '{certificate_name}' to Key Vault: {str(e)}")
        return False


def get_certificate_name(secret_name):
    """
    Determines the Key Vault certificate name based on the configuration.

    - If `USE_NAME_MAPPING=False` → Always return the AKS secret name.
    - If `STRICT_NAME_MAPPING=True` → Only use mapped names, ignore others.
    - If `STRICT_NAME_MAPPING=False` → Use mapped names where available, otherwise fallback to AKS secret name.
    """
    if not USE_NAME_MAPPING:
        logging.info(f"Name mapping disabled, using AKS secret name '{secret_name}' as Key Vault certificate name.")
        return secret_name  # Ignore mapping and use AKS secret name

    config_entry = CERTIFICATE_CONFIG.get(secret_name)

    if STRICT_NAME_MAPPING and config_entry is None:
        logging.warning(f"Strict name mapping enabled, skipping secret '{secret_name}' as it's not in CERTIFICATE_CONFIG.")
        return None  # Strict mode → Ignore unmapped secrets

    if config_entry:
        kv_cert_name = config_entry.get("cert_name", secret_name)
        logging.info(f"Using mapped name '{kv_cert_name}' for AKS secret '{secret_name}'.")
        return kv_cert_name
    else:
        logging.info(f"No mapping found for secret '{secret_name}', using AKS secret name as Key Vault certificate name.")
        return secret_name


def get_key_vaults_for_secret(certificate_config, secret_name):
    """
    Returns list of Key Vault URLs for a given secret based on configuration.
    Supports both string (single KV) and list (multiple KVs) configurations.
    """
    config_entry = certificate_config.get(secret_name)
    if not config_entry:
        return []

    key_vaults = config_entry.get("keyVaults")

    if not key_vaults:
        return []

    # Normalize to list - if it's a string, convert to single-item list
    if isinstance(key_vaults, str):
        return [key_vaults]
    elif isinstance(key_vaults, list):
        return key_vaults
    else:
        logging.warning(f"Invalid keyVaults format for secret '{secret_name}': {type(key_vaults)}")
        return []


def get_certificate_tags(secret_name):
    """
    Retrieves the tags for a given certificate.

    - If a mapping exists in `CERTIFICATE_CONFIG`, use those tags.
    - Otherwise, apply `DEFAULT_TAGS`.
    """
    config_entry = CERTIFICATE_CONFIG.get(secret_name)

    if config_entry and "tags" in config_entry:
        tags = config_entry["tags"]
        logging.info(f"Using custom tags from configuration for secret '{secret_name}': {tags}")
        return tags

    # Apply default tags if no custom tags are defined
    default_tags = DEFAULT_TAGS
    logging.info(f"Using default tags for secret '{secret_name}': {default_tags}")
    return default_tags


def main():
    logging.info(f"Starting certificate sync process. Running every {SYNC_INTERVAL} seconds.")

    while True:
        certificates = get_certificates()

        for certificate in certificates:
            secret_name = certificate["spec"]["secretName"]
            namespace = certificate["metadata"]["namespace"]
            certificate_name = get_certificate_name(secret_name)

            if STRICT_NAME_MAPPING and certificate_name is None:
                logging.warning(f"Skipping secret '{secret_name}' because it is not in CERTIFICATE_CONFIG.")
                continue

            # Get list of Key Vault URLs for this secret
            key_vault_urls = get_key_vaults_for_secret(CERTIFICATE_CONFIG, secret_name)
            if not key_vault_urls:
                logging.warning(f"No Key Vault specified for secret '{secret_name}', skipping.")
                continue

            tags = get_certificate_tags(secret_name)

            logging.info(f"Processing certificate: {certificate['metadata']['name']} (secret: {secret_name}) in namespace {namespace} for Key Vaults: {key_vault_urls}")
            secret = get_secret(namespace, secret_name)
            cert = base64.b64decode(secret.data["tls.crt"]).decode("utf-8")
            key = base64.b64decode(secret.data["tls.key"]).decode("utf-8")

            # Process for each Key Vault
            for vault_url in key_vault_urls:
                logging.debug(f"Uploading certificate {certificate_name} to Key Vault {vault_url} with tags {tags}...")
                if upload_to_key_vault(vault_url, certificate_name, cert, key, tags):
                    logging.info(f"Certificate {certificate_name} successfully uploaded to Key Vault {vault_url} with tags {tags}.")
                else:
                    logging.error(f"Failed to upload certificate {certificate_name} to Key Vault {vault_url}")

        logging.info(f"Sync completed. Sleeping for {SYNC_INTERVAL} seconds.")
        sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    try:
        logging.info("Starting certificate sync process.")
        main()
        logging.info("Certificate sync process completed.")
    except Exception as e:
        logging.exception("An unexpected error occurred during execution.")

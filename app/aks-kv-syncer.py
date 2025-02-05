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


# Feature toggle for dry run mode
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("true", "1", "yes", "enabled")

# Read synchronization interval from environment variables (default: 300 seconds)
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", 300))

# Configurable options
USE_NAME_MAPPING = os.getenv("USE_NAME_MAPPING", "true").lower() in ("true", "1", "yes", "enabled")
STRICT_NAME_MAPPING = os.getenv("STRICT_NAME_MAPPING", "true").lower() in ("true", "1", "yes", "enabled")

# Default tags (used if no specific tags are defined)
DEFAULT_TAGS = {"managed_by": "sre-cert-sync-tool"}

# Certificate configuration (maps AKS secrets to Key Vault certificates with optional tags)
CERTIFICATE_CONFIG = {
    "acme-crt-wildcard-test-elcare-com-secret": {
        "cert_name": "wildcard-elcare-com",
        "tags": {"owner": "team-networking", "project": "elcare"}
    }
}

# Read logging levels from environment variables or use defaults
DEFAULT_LOGGING_LEVEL = os.getenv("DEFAULT_LOGGING_LEVEL", "DEBUG").upper()
AZURE_LOGGING_LEVEL = os.getenv("AZURE_LOGGING_LEVEL", "DEBUG").upper()

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

    logging.info(f"Searching certificates in namespaces: {namespaces_to_search}")

    all_certificates = []
    for ns in namespaces_to_search:
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
    logging.info(f"Fetched secret '{secret_name}' successfully.")
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
    certificate = load_pem_x509_certificate(cert.encode("utf-8"), backend=default_backend())
    cert_thumbprint = certificate.fingerprint(SHA1()).hex()

    try:
        existing_cert = certificate_client.get_certificate(certificate_name)
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
        cert=certificate,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )

    # Upload the certificate to Key Vault
    try:
        certificate_client.import_certificate(
            certificate_name=certificate_name,
            certificate_bytes=pfx_data,
            tags=tags  # Přidání tagů k certifikátu
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
        return secret_name  # Ignore mapping and use AKS secret name

    config_entry = CERTIFICATE_CONFIG.get(secret_name)

    if STRICT_NAME_MAPPING and config_entry is None:
        return None  # Strict mode → Ignore unmapped secrets

    return config_entry.get("cert_name", secret_name) if config_entry else secret_name


def get_certificate_tags(secret_name):
    """
    Retrieves the tags for a given certificate.

    - If a mapping exists in `CERTIFICATE_CONFIG`, use those tags.
    - Otherwise, apply `DEFAULT_TAGS`.
    """
    config_entry = CERTIFICATE_CONFIG.get(secret_name)

    if config_entry and "tags" in config_entry:
        return config_entry["tags"]

    return DEFAULT_TAGS  # Apply default tags if no custom tags are defined


def main():
    vault_url = os.getenv("AZURE_KEYVAULT_URL")
    if not vault_url:
        logging.error("Missing environment variable AZURE_KEYVAULT_URL. Exiting.")
        return

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

            tags = get_certificate_tags(secret_name)

            logging.info(f"Processing certificate: {certificate['metadata']['name']} in namespace {namespace}")
            secret = get_secret(namespace, secret_name)
            cert = base64.b64decode(secret.data["tls.crt"]).decode("utf-8")
            key = base64.b64decode(secret.data["tls.key"]).decode("utf-8")

            logging.debug(f"Uploading certificate {certificate_name} to Key Vault with tags {tags}...")
            if upload_to_key_vault(vault_url, certificate_name, cert, key, tags):
                logging.info(f"Certificate {certificate_name} successfully uploaded to Key Vault with tags {tags}.")

        logging.info(f"Sync completed. Sleeping for {SYNC_INTERVAL} seconds.")
        sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    try:
        logging.info("Starting certificate sync process.")
        main()
        logging.info("Certificate sync process completed.")
    except Exception as e:
        logging.exception("An unexpected error occurred during execution.")

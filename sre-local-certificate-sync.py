import logging
import datetime
from kubernetes import client, config
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import base64
import os

# Configure logging for the script
logging.basicConfig(
    level=logging.INFO,  # Set the default level for your application
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Suppress specific library debug logs
logging.getLogger("azure.identity").setLevel(logging.WARNING)


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


def upload_to_key_vault(vault_url, certificate_name, cert, key):
    """
    Upload a certificate to Azure Key Vault if it doesn't already exist.
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
    except Exception as e:
        logging.warning(f"Certificate {certificate_name} not found in Key Vault. Proceeding with upload. Error: {e}")

    pfx_data = pkcs12.serialize_key_and_certificates(
        name=certificate_name.encode("utf-8"),
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=NoEncryption(),
    )

    certificate_client.import_certificate(certificate_name=certificate_name, certificate_bytes=pfx_data)
    logging.info(f"Certificate {certificate_name} successfully uploaded to Key Vault.")
    return True


# Define a mapping matrix for AKS secret names to Key Vault certificate names
NAME_MAPPING = {
    "acme-crt-wildcard-test-elcare-com-secret": "wildcard-elcare-com",
    "acme-crt-wildcard-test-currys-app-secret": "wildcard-currys-app",
    # Add more mappings as needed
}


def get_certificate_name(secret_name):
    """
    Get the corresponding Key Vault certificate name for the given Kubernetes secret name.
    If no mapping is found, use the secret name directly.
    """
    return NAME_MAPPING.get(secret_name, secret_name.replace(".", "-"))


def main():
    namespace = "ingresscontrollers"
    vault_url = os.getenv("AZURE_KEYVAULT_URL")
    if not vault_url:
        logging.error("Missing environment variable AZURE_KEYVAULT_URL. Exiting.")
        return

    certificates = get_certificates(namespace)
    for certificate in certificates:
        secret_name = certificate["spec"]["secretName"]
        certificate_name = get_certificate_name(secret_name)

        logging.info(f"Processing certificate: {certificate['metadata']['name']}")
        secret = get_secret(namespace, secret_name)
        cert = base64.b64decode(secret.data["tls.crt"]).decode("utf-8")
        key = base64.b64decode(secret.data["tls.key"]).decode("utf-8")

        logging.debug(f"Uploading certificate {certificate_name} to Key Vault...")
        if upload_to_key_vault(vault_url, certificate_name, cert, key):
            logging.info(f"Certificate {certificate_name} successfully uploaded to Key Vault.")


if __name__ == "__main__":
    try:
        logging.info("Starting certificate sync process.")
        main()
        logging.info("Certificate sync process completed.")
    except Exception as e:
        logging.exception("An unexpected error occurred during execution.")

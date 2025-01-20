# pip install azure-identity azure-keyvault-certificates
from kubernetes import client, config
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key, NoEncryption
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.backends import default_backend
import base64
import os


# Function to fetch a Kubernetes secret
# Challenges:
# - Ensuring Kubernetes API authentication worked correctly.
# - Properly configuring kubeconfig for local testing.
# - Debugging issues with secret fetching due to namespace or name mismatches.
def get_secret(namespace, secret_name):
    # Load Kubernetes configuration from kubeconfig
    # If running in-cluster, use config.load_incluster_config().
    config.load_kube_config()
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(secret_name, namespace)
    return secret


# Function to upload a certificate to Azure Key Vault
# Challenges:
# - Correctly formatting the certificate and key into PFX format.
# - Handling PEM to PFX conversion issues due to incompatible key formats.
# - Ensuring the `import_certificate` method had valid arguments, particularly `certificate_name`.
# - Avoiding invalid certificate names for Azure Key Vault (e.g., containing dots or other forbidden characters).
def upload_to_key_vault(vault_url, certificate_name, cert, key):
    # Authenticate with Azure Key Vault
    credential = DefaultAzureCredential()
    certificate_client = CertificateClient(vault_url=vault_url, credential=credential)

    # Load private key and certificate from PEM format
    private_key = load_pem_private_key(key.encode("utf-8"), password=None, backend=default_backend())
    certificate = load_pem_x509_certificate(cert.encode("utf-8"), backend=default_backend())

    # Extract the thumbprint of the certificate for comparison
    cert_thumbprint = certificate.fingerprint(SHA1()).hex()

    # Check if a certificate with the same name exists in Key Vault
    try:
        existing_cert = certificate_client.get_certificate(certificate_name)

        # Compare thumbprints to determine if the certificate is already present
        existing_cert_thumbprint = existing_cert.properties.x509_thumbprint.hex()
        if cert_thumbprint == existing_cert_thumbprint:
            print(f"Certificate {certificate_name} already exists in Key Vault with the same thumbprint. Skipping upload.")
            return False  # Skip upload
    except Exception:
        # If the certificate doesn't exist, log and proceed
        print(f"Certificate {certificate_name} not found in Key Vault. Proceeding with upload...")

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
    return True  # Certificate was uploaded


def main():
    # Define namespace and Kubernetes secret name
    namespace = "ingresscontrollers"
    secret_name = "tinkerlab.online-tls"

    # Transform secret name to a valid Key Vault certificate name
    certificate_name = secret_name.replace(".", "-")

    # Get Azure Key Vault URL from environment variables
    vault_url = os.getenv("AZURE_KEYVAULT_URL")
    if not vault_url:
        print("ERROR: Missing environment variable AZURE_KEYVAULT_URL")
        return

    # Fetch the secret from Kubernetes
    secret = get_secret(namespace, secret_name)
    cert = base64.b64decode(secret.data["tls.crt"]).decode("utf-8")
    key = base64.b64decode(secret.data["tls.key"]).decode("utf-8")

    # Upload the certificate to Azure Key Vault
    print(f"Uploading certificate {certificate_name} to Key Vault...")
    if upload_to_key_vault(vault_url, certificate_name, cert, key):
        print(f"Certificate {certificate_name} successfully uploaded to Key Vault.")  # Only appears if uploaded


if __name__ == "__main__":
    main()

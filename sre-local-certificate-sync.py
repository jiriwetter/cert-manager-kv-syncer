from kubernetes import client, config

# pip install azure-identity azure-keyvault-certificates
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient

from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key, NoEncryption
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

import base64
import os


def get_secret(namespace, secret_name):
    # Načtení kubeconfig
    config.load_kube_config()
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(secret_name, namespace)
    return secret


def upload_to_key_vault(vault_url, certificate_name, cert, key):
    # Připojení k Azure Key Vault
    credential = DefaultAzureCredential()
    certificate_client = CertificateClient(vault_url=vault_url, credential=credential)

    # Načtení privátního klíče z PEM formátu
    private_key = load_pem_private_key(key.encode("utf-8"), password=None, backend=default_backend())

    # Načtení certifikátu z PEM formátu
    certificate = load_pem_x509_certificate(cert.encode("utf-8"), backend=default_backend())

    # Vytvoření PFX dat s nezašifrovaným klíčem
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=certificate_name.encode("utf-8"),
        key=private_key,
        cert=certificate,
        cas=None,  # Pokud nemáte certifikační autority
        encryption_algorithm=NoEncryption(),  # Žádné šifrování PFX
    )

    # Nahrání certifikátu do Key Vault
    certificate_client.import_certificate(certificate_name=certificate_name, certificate_bytes=pfx_data)


def main():
    # Namespace a název secretu
    namespace = "ingresscontrollers"
    secret_name = "tinkerlab.online-tls"

    # Transformace názvu certifikátu pro Key Vault
    certificate_name = secret_name.replace(".", "-")

    # URL Azure Key Vault
    vault_url = os.getenv("AZURE_KEYVAULT_URL")

    if not vault_url:
        print("ERROR: Chybí proměnná prostředí AZURE_KEYVAULT_URL")
        return

    # Načtení secretu z Kubernetes
    secret = get_secret(namespace, secret_name)
    cert = base64.b64decode(secret.data["tls.crt"]).decode("utf-8")
    key = base64.b64decode(secret.data["tls.key"]).decode("utf-8")

    # Nahrání certifikátu do Key Vault
    print(f"Nahrávám certifikát {certificate_name} do Key Vault...")
    upload_to_key_vault(vault_url, certificate_name, cert, key)
    print("Certifikát byl úspěšně nahrán!")


if __name__ == "__main__":
    main()

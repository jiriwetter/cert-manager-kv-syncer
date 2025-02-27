# cert-manager-kv-syncer

## Overview
The tool automates the synchronization of TLS certificates from Kubernetes Secrets to Azure Key Vault, ensuring consistency across environments. It addresses a gap in the [external-secret](https://github.com/external-secrets/external-secrets/discussions/4199) tool by enabling secure and reliable certificate propagation. The primary goal is to synchronize certificates generated by [cert-manager](https://github.com/cert-manager/cert-manager), ensuring they are always up-to-date in Key Vault.

### How it works
* **Scanning for Certificate CRD**: The tool periodically scans Kubernetes for `Certificate` resources created by cert-manager in the configured namespaces. It retrieves the associated TLS secrets containing certificate and key data.
* **Determining target name & tags**: Based on the configuration (`USE_NAME_MAPPING`, `STRICT_NAME_MAPPING`), the tool determines the correct certificate name and associated metadata (tags) before uploading it to Key Vault.
* **Checking for existing certificates**: Before uploading, the tool queries Azure Key Vault to check if the certificate already exists. It compares the stored fingerprint with the new certificate to prevent unnecessary updates.
* **Uploading certificates**: If a new or updated certificate is detected, it is converted into the correct format and securely uploaded to Azure Key Vault. Tags are assigned based on the provided configuration or default.
* **Continuous synchronization**: The process runs continuously based on the `SYNC_INTERVAL` value, ensuring all certificates remain synchronized between Kubernetes and Azure Key Vault.


![Diagram](assets/cert-manager-kv-syncer.gif)

## Features
- **Automatic synchronization** – Periodically syncs Kubernetes secrets to Azure Key Vault.
- **Namespace filtering** – Define where to search for certificates using `SEARCH_NAMESPACES`.
- **Exclusion support** – Exclude namespaces using `!namespace` syntax.
- **Custom certificate mapping** – Rename certificates before storing them in Key Vault.
- **Tag management** – Assign custom tags to Key Vault certificates.
- **Dry Run mode** – Test without making real changes (`DRY_RUN=True`).
- **Configurable sync interval** – Control how often sync runs (`SYNC_INTERVAL`).
- **Automatic environment detection** – Runs seamlessly both locally and inside AKS.

## Installation & Requirements

### AKS
To install the syncer, run:

```sh
helm install cert-manager-kv-syncer cert-manager-kv-syncer \
  --values cert-manager-kv-syncer/values.yaml \
  --namespace cert-manager-kv-syncer \
  --create-namespace
```
This command installs the syncer in the cert-manager-kv-syncer namespace using the provided configuration values.

#### Upgrade

Upgrades and installs in case it does not exist.

```sh
helm upgrade --install cert-manager-kv-syncer cert-manager-kv-syncer \
  --values cert-manager-kv-syncer/values.yaml
```


The tool can also be run locally without the need for Helm installation. This allows for manual synchronization by simply executing the script, making it useful for on-demand certificate updates or debugging purposes.

### Local

#### Prerequisites
- **Python 3.11+**
- **Kubernetes Access** – Ensure you have a working `kubeconfig`.
- **Azure Key Vault Access** – Configure authentication using `DefaultAzureCredential`.

#### Installation
```bash
# Clone the repository
git clone https://github.com/jiriwetter/cert-manager-kv-syncer.git
cd cert-manager-kv-syncer/app

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

## Configuration
Set the following environment variables:

| Variable                  | Default                                               | Description                                                                                                                                                                    |
|---------------------------|-------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `AZURE_KEYVAULT_URL`      | *Required*                                            | Azure Key Vault URL                                                                                                                                                            |
| `SYNC_INTERVAL`           | `300`                                                 | Sync interval in seconds                                                                                                                                                       |
| `SEARCH_NAMESPACES`       | `""`                                                  | Namespaces to search (`"ingresscontrollers,production"` or `"!production"` or `""` for all)                                                                                    |
| `USE_NAME_MAPPING`        | `True`                                                | Maps AKS secret names to custom Azure Key Vault certificate names using a predefined matrix. Those without mapping set will be transferred with the same name and default tag. |
| `STRICT_NAME_MAPPING`     | `True`                                                | Only sync mapped certificates. Requires all secrets to have a defined mapping; otherwise, they will not be synchronized.                                                       |
| `DEFAULT_TAGS`            | `{created-by: cert-manager-kv-syncer}`                | Tags applied to certificates. Currenctly hardcoded.                                                                                                                            |
| `DRY_RUN`                 | `False`                                               | Allows testing the synchronization process without making actual changes.                                                                                                      |
| `CERTIFICATE_CONFIG_PATH` | `/etc/cert-manager-kv-syncer/certificate-config.json` | Path to the name mapping matrix between AKS and Key Vault                                                                                                                      |

## Usage

### Run the script
```bash
export AZURE_KEYVAULT_URL=https://example-kv.vault.azure.net/
export CERTIFICATE_CONFIG_PATH=certificate-meta-config.json
python cert-manager-kv-syncer.py
```

### Example: Search in all namespaces except `kube-system`
```bash
export SEARCH_NAMESPACES="!kube-system"
```

### Example: Use name mapping with strict mode
```bash
export CERTIFICATE_CONFIG_PATH=certificate-meta-config.json
```

### Example: No mapping - sync all
```bash
export USE_NAME_MAPPING=False
export STRICT_NAME_MAPPING=False
```

### Example: Use name mapping without strict mode
```bash
export USE_NAME_MAPPING=True
export STRICT_NAME_MAPPING=False
```

## Logs & Debugging
By default, logs are at `INFO` level. To enable debug mode:
```bash
export DEFAULT_LOGGING_LEVEL=DEBUG
```

## Planned Features
- **Notifications** – Alerts via Slack, Teams, or email when certificates are updated.
- **Automatic cleanup** – Remove stale certificates from Key Vault.
- **Multi Key Vault support** – Allow different vaults for different certificates.
- **Audit logging** – Store sync history in a database.

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit changes & submit a PR

## License
MIT License


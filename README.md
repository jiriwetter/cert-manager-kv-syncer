# Certificate Sync Tool

## Overview
Tool automates the synchronization of TLS certificates from Kubernetes Secrets to Azure Key Vault. It ensures that certificates stored in Kubernetes are securely propagated to Key Vault, maintaining consistency across environments.

## Features
- **Automatic Synchronization** – Periodically syncs Kubernetes secrets to Azure Key Vault.
- **Namespace Filtering** – Define where to search for certificates using `SEARCH_NAMESPACES`.
- **Exclusion Support** – Exclude namespaces using `!namespace` syntax.
- **Custom Certificate Mapping** – Rename certificates before storing them in Key Vault.
- **Tag Management** – Assign custom tags to Key Vault certificates.
- **Dry Run Mode** – Test without making real changes (`DRY_RUN=True`).
- **Configurable Sync Interval** – Control how often sync runs (`SYNC_INTERVAL`).

## Installation & Requirements
### Prerequisites
- **Python 3.8+**
- **Kubernetes Access** – Ensure you have a working `kubeconfig`.
- **Azure Key Vault Access** – Configure authentication using `DefaultAzureCredential`.

### Installation
```bash
# Clone the repository
git clone https://github.com/your-repo/sre-certificate-sync.git
cd sre-certificate-sync

# Install dependencies
pip install -r requirements.txt
```

## Configuration
Set the following environment variables:

| Variable | Default | Description                                                                                 |
|----------|---------|---------------------------------------------------------------------------------------------|
| `AZURE_KEYVAULT_URL` | *Required* | Azure Key Vault URL                                                                         |
| `SYNC_INTERVAL` | `300` | Sync interval in seconds                                                                    |
| `SEARCH_NAMESPACES` | `""` | Namespaces to search (`"ingresscontrollers,production"` or `"!production"` or `""` for all) |
| `USE_NAME_MAPPING` | `False` | Whether to use certificate mapping                                                          |
| `STRICT_NAME_MAPPING` | `False` | Only sync mapped certificates                                                               |
| `DEFAULT_TAGS` | `{managed_by: cert-sync-tool}` | Tags applied to certificates                                                                |
| `DRY_RUN` | `False` | If enabled, logs actions without modifying Key Vault                                        |

## Usage
### Run the script
```bash
python sre-local-certificate-sync.py
```

### Example: Search in all namespaces except `kube-system`
```bash
export SEARCH_NAMESPACES="!kube-system"
python sre-local-certificate-sync.py
```

### Example: Use name mapping with strict mode
```bash
export USE_NAME_MAPPING=true
export STRICT_NAME_MAPPING=true
python sre-local-certificate-sync.py
```

## How It Works
1. Fetches `Certificate` resources from Kubernetes.
2. Extracts secrets and transforms names based on `USE_NAME_MAPPING`.
3. Checks if the certificate already exists in Key Vault.
4. If different or missing, uploads the certificate with tags.
5. Repeats based on `SYNC_INTERVAL`.

## Logs & Debugging
By default, logs are at `INFO` level. To enable debug mode:
```bash
export DEFAULT_LOGGING_LEVEL=DEBUG
python sre-local-certificate-sync.py
```

## Planned Features
- **Notifications** – Alerts via Slack, Teams, or email when certificates are updated.
- **Automatic Cleanup** – Remove stale certificates from Key Vault.
- **Multi-Key Vault Support** – Allow different vaults for different certificates.
- **Audit Logging** – Store sync history in a database.

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit changes & submit a PR

## License
MIT License


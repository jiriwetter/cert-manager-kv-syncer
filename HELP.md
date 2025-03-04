## Potential problems and solutions

### The request URI contains an invalid name

This error means that the name of the secret cannot be used as the name of the certificate in Azure Key Vault. In this case, it is an illegal "." character in the name.

*Object identifiers*: https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#object-identifiers
```sh
2025-03-04 09:52:38 - INFO - Starting certificate sync process.
2025-03-04 09:52:38 - INFO - Starting certificate sync process. Running every 300 seconds.
2025-03-04 09:52:39 - INFO - Running locally - Using kubeconfig.
2025-03-04 09:52:39 - INFO - Searching certificates in defined namespaces...
2025-03-04 09:52:42 - INFO - Name mapping disabled, using AKS secret name 'tinkerlab.online-tls' as Key Vault certificate name.
2025-03-04 09:52:42 - INFO - Using default tags for secret 'tinkerlab.online-tls': {'created-by': 'cert-manager-kv-syncer'}
2025-03-04 09:52:42 - INFO - Processing certificate: tinkerlab.online (secret: tinkerlab.online-tls) in namespace ingresscontrollers
2025-03-04 09:52:42 - INFO - Fetched secret 'tinkerlab.online-tls' successfully from namespace 'ingresscontrollers'.
2025-03-04 09:52:44 - WARNING - Certificate tinkerlab.online-tls not found in Key Vault. Proceeding with upload...
2025-03-04 09:52:44 - ERROR - Failed to upload certificate 'tinkerlab.online-tls' to Key Vault: (BadParameter) The request URI contains an invalid name: tinkerlab.online-tls
Code: BadParameter
Message: The request URI contains an invalid name: tinkerlab.online-tls
2025-03-04 09:52:44 - INFO - Sync completed. Sleeping for 300 seconds.
```
In order not to have to modify the AKS secret settings, it is possible to use `USE_NAME_MAPPING` and also in combination with `STRICT_NAME_MAPPING`. This will allow you to modify the name of the secret according to the Azure Key Vault requirement. In both cases, it is then necessary to provide the settings for this mapping.

#### Fix

```sh
export USE_NAME_MAPPING=True
export CERTIFICATE_CONFIG_PATH=certificate-meta-config.json
```

```json
{
  "tinkerlab.online-tls": {
    "cert_name": "tinkerlab-online-tls",
    "tags": {
      "owner": "jiri.wetter@gmail.com",
      "team": "sre"
    }
  }
}
```

```sh
2025-03-04 10:11:09 - INFO - Configuration file certificate-meta-config.json loaded successfully.
2025-03-04 10:11:09 - INFO - Starting certificate sync process.
2025-03-04 10:11:09 - INFO - Starting certificate sync process. Running every 300 seconds.
2025-03-04 10:11:10 - INFO - Running locally - Using kubeconfig.
2025-03-04 10:11:11 - INFO - Searching certificates in defined namespaces...
2025-03-04 10:11:13 - INFO - Using mapped name 'tinkerlab-online-tls' for AKS secret 'tinkerlab.online-tls'.
2025-03-04 10:11:13 - INFO - Using custom tags from configuration for secret 'tinkerlab.online-tls': {'owner': 'jiri.wetter@gmail.com', 'team': 'sre'}
2025-03-04 10:11:13 - INFO - Processing certificate: tinkerlab.online (secret: tinkerlab.online-tls) in namespace ingresscontrollers
2025-03-04 10:11:13 - INFO - Fetched secret 'tinkerlab.online-tls' successfully from namespace 'ingresscontrollers'.
2025-03-04 10:11:15 - WARNING - Certificate tinkerlab-online-tls not found in Key Vault. Proceeding with upload...
2025-03-04 10:11:16 - INFO - Certificate tinkerlab-online-tls (AKS secret: 'tinkerlab.online-tls') successfully uploaded to Key Vault with tags {'owner': 'jiri.wetter@gmail.com', 'team': 'sre'}.
2025-03-04 10:11:16 - INFO - Sync completed. Sleeping for 300 seconds.
```
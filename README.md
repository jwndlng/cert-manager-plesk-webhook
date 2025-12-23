# Cert Manager Webhook for Plesk XML API

A custom DNS-01 challenge solver webhook for [cert-manager](https://cert-manager.io) that integrates with the Plesk XML API. This webhook handles DNS TXT record creation and cleanup via Plesk to automate ACME DNS-01 challenges for certificate issuance.

## Features

- **DNS-01 Challenge Automation**: Automatically creates and deletes DNS TXT records in Plesk.
- **Multiple Hostname Support**: Can handle concurrent challenges for different hostnames.
- **Self-Signed TLS**: Generates its own certificate for secure communication with cert-manager.
- **HTTPS Support**: Listens on both ports 8080 (HTTP) and 8443 (HTTPS), but 8080 is not implemented yet.

## Limitations

- **Single TLD per instance**: Currently supports one top-level domain per deployment (configured via Plesk Site ID).
- Can issue certificates for multiple subdomains or SAN certificates within that TLD.

## Prerequisites

- Kubernetes cluster with cert-manager v1.0+ installed
- Plesk server with:
  - XML API access enabled
  - A site/domain configured for DNS management
  - API credentials (username and password)
  - The Site ID for your domain

### Finding Your Plesk Site ID

1. Log into your Plesk admin panel
2. Navigate to **Websites & Domains**
3. Click on DNS in the "Hosting and DNS" menu
4. Check the browser URL bar: `https://your-plesk.com:8443/smb/dns-zone/records-list/id/3839/type/domain`
5. The number after `/id/` is your Site ID (e.g., `123`)

## Installation

### Step 1: Create Secret with Plesk Credentials

```bash
kubectl create secret generic custom-plesk-solver-secret \
  --namespace cert-manager \
  --from-literal=cmpw_plesk_username='your-plesk-username' \
  --from-literal=cmpw_plesk_password='your-plesk-password'
```

Recommended alternative: Use an external secret provider such as HashiCorp Vault.

### Step 2: Deploy the Webhook

Create the following Kubernetes resources:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: custom-plesk-solver-webhook
  namespace: cert-manager
spec:
  replicas: 1
  selector:
    matchLabels:
      app: custom-plesk-solver-webhook
  template:
    metadata:
      labels:
        app: custom-plesk-solver-webhook
    spec:
      serviceAccountName: custom-plesk-solver-sa
      containers:
      - name: custom-plesk-solver
        image: ghcr.io/jwndlng/cert-manager-plesk-webhook:latest
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8080
        - name: https
          containerPort: 8443
        env:
        - name: CMPW_PLESK_SITEID
          value: "123"  # Your Plesk Site ID
        - name: CMPW_PLESK_URL
          value: "https://your-plesk-server.com:8443"  # Your Plesk API URL
        - name: CMPW_COMMON_GROUPNAME
          value: "acme.example.com"  # Must match Issuer groupName
        - name: CMPW_COMMON_SOLVERNAME
          value: "plesk-solver"  # Must match Issuer solverName
        - name: CMPW_COMMON_SOLVERVERSION
          value: "v1"  # Must match APIService version
        - name: CMPW_PLESK_USERNAME
          valueFrom:
            secretKeyRef:
              name: custom-plesk-solver-secret
              key: cmpw_plesk_username
        - name: CMPW_PLESK_PASSWORD
          valueFrom:
            secretKeyRef:
              name: custom-plesk-solver-secret
              key: cmpw_plesk_password
```
Create the Service:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: custom-plesk-solver-webhook
  namespace: cert-manager
spec:
  selector:
    app: custom-plesk-solver-webhook
  ports:
  - name: https
    protocol: TCP
    port: 443
    targetPort: 8443
```

### Step 3: Finish your Cert-Manager and Certificate configuration

Please review official guides and documentation on how to configure your cert-manager and certificate configuration.

## Configuration Reference

| Environment Variable | Required | Description | Example |
|---------------------|----------|-------------|----------|
| `CMPW_PLESK_URL` | Yes | Plesk API endpoint URL (including port) | `https://plesk.example.com:8443` |
| `CMPW_PLESK_SITEID` | Yes | Plesk Site ID for your domain | `123` |
| `CMPW_PLESK_USERNAME` | Yes | Plesk API username | `admin` |
| `CMPW_PLESK_PASSWORD` | Yes | Plesk API password | (from secret) |
| `CMPW_COMMON_GROUPNAME` | Yes | API group name - must match Issuer `groupName` and APIService `group` | `acme.example.com` |
| `CMPW_COMMON_SOLVERNAME` | Yes | Solver name - must match Issuer `solverName` | `plesk-solver` |
| `CMPW_COMMON_SOLVERVERSION` | Yes | API version - must match APIService `version` | `v1` |

**Important:** The `CMPW_COMMON_GROUPNAME`, `CMPW_COMMON_SOLVERNAME`, and `CMPW_COMMON_SOLVERVERSION` must be consistent across:
- Webhook deployment environment variables
- APIService manifest
- Your Issuer/ClusterIssuer webhook solver configuration

## Development

### Building from Source

```bash
# Build the binary
cargo build --release

# Build Docker image
docker build -t cert-manager-plesk-webhook:dev .
```

### Running Locally

```bash
# Set environment variables
export CMPW_PLESK_URL="https://your-plesk.com:8443"
export CMPW_PLESK_SITEID="123"
export CMPW_PLESK_USERNAME="admin"
export CMPW_PLESK_PASSWORD="your-password"
export CMPW_COMMON_GROUPNAME="acme.example.com"
export CMPW_COMMON_SOLVERNAME="plesk-solver"
export CMPW_COMMON_SOLVERVERSION="v1"

# Run the webhook
cargo run
```

The webhook will listen on:
- HTTP: `http://localhost:8080` (Not implemented)
- HTTPS: `https://localhost:8443`


## Contributing
Contributions are welcome! Feel free to submit a PR if you think the project is missing something or has a bug :-).

## License
This project is licensed under the Apache 2.0 License. See the [LICENSE](/LICENSE) file for more details.

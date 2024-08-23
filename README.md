# Cert Manager Webhook Server for Plesk XML API

## Overview

`cert-manager-plesk-webhook` is a custom DNS-01 challenge solver for [cert-manager](https://cert-manager.io) that integrates with the Plesk XML API. This project is implemented in Rust and packaged as a Docker container for easy deployment. The webhook server handles DNS record creation and cleanup via Plesk to automate the issuance of Let's Encrypt certificates.

## Features

- **DNS-01 Challenge Support**: Automatically create and delete DNS records in Plesk to complete the DNS-01 challenge for Let's Encrypt certificates.

## Prerequisites

- `cert-manager` installed in your environment
- Access to a Plesk server with DNS management via the XML API

## Configuring Cert-Manager

Update the ClusterIssuer or Issuer configuration in cert-manager to use this webhook:

```yaml
TBD
```

## Contributing
Contributions are welcome! Feel free to submit a PR if you think the project is missing something or has a bug :-).

## License
This project is licensed under the Apache 2.0 License. See the [LICENSE](/LICENSE) file for more details.

# sentinel-syslog-tls-collector

[![Infra CI](https://github.com/x3nc0n/sentinel-syslog-tls-collector/actions/workflows/ci.yml/badge.svg)](https://github.com/x3nc0n/sentinel-syslog-tls-collector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A scalable **Syslog / CEF over TLS** collector for **Microsoft Sentinel**, deployable to any Azure subscription with one click. A modernized, hardened reimplementation of the upstream [Azure/Azure-Sentinel — Syslog-VMSS-AMA](https://github.com/Azure/Azure-Sentinel/tree/master/DataConnectors/Syslog-VMSS-AMA) data connector.

## Deploy to Azure

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fx3nc0n%2Fsentinel-syslog-tls-collector%2Fmain%2Fazuredeploy.json)
[![Visualize](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.svg?sanitize=true)](https://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fx3nc0n%2Fsentinel-syslog-tls-collector%2Fmain%2Fazuredeploy.json)

The button deploys to a **resource group** you choose. You will be prompted for parameters — at minimum an **SSH public key** (`adminSshPublicKey`) for break-glass admin access.

## What it provisions

| Resource | Purpose |
|---|---|
| **VM Scale Set** (Ubuntu 24.04 LTS) | Runs `rsyslog` with a GnuTLS listener on TCP **6514** (RFC 5425) |
| **Azure Monitor Agent** + **Data Collection Rule** | Forwards Syslog/CEF to Log Analytics / Microsoft Sentinel |
| **Log Analytics workspace** (+ optional Sentinel onboarding) | Destination for collected events |
| **Standard Load Balancer** (internal or public) | Fronts the VMSS listener |
| **NAT Gateway** | Guaranteed outbound egress (Key Vault, AAD, AMA) |
| **Key Vault** | Stores the TLS server cert, key, and CA cert as secrets |
| **User-Assigned Managed Identity** | Least-privilege Key Vault read for cert delivery via cloud-init |
| **Autoscale rules** | Scales the VMSS on CPU |

## TLS certificates

The rsyslog TLS listener needs three PEM secrets in Key Vault:
`syslog-ca-cert`, `syslog-server-cert`, `syslog-server-key`.

You can either:

1. **Inject at deploy time** — pass the PEM contents to the optional `secureString` parameters `syslogCaCertPem`, `syslogServerCertPem`, `syslogServerKeyPem`. They land in Key Vault before the VMSS boots (single-shot deploy).
2. **Upload after deploy** — leave those parameters empty and upload the secrets manually.

See **[docs/tls-setup.md](docs/tls-setup.md)** for certificate generation and rotation.

## Manual / CLI deployment

```bash
az group create -n rg-syslog-collector -l eastus2

az deployment group create \
  --resource-group rg-syslog-collector \
  --template-file bicep/main.bicep \
  --parameters bicep/main.bicepparam \
  --parameters adminSshPublicKey="$(cat ~/.ssh/id_ed25519.pub)"
```

`bicep/` contains the modular Bicep source; `azuredeploy.json` is the compiled single-file ARM template used by the Deploy-to-Azure button.

## Public-facing & security guidance

Exposing a syslog listener to the Internet is a deliberate decision. See **[docs/deployment-patterns.md](docs/deployment-patterns.md)** for escalating patterns — private/internal, IP-allowlisted public, mutual-TLS, and ALZ hub-spoke + Azure Firewall — each with topology, NSG controls, threat model, and residual risk.

## How this differs from upstream

This template modernizes and hardens the upstream Sentinel connector: Bicep modules instead of monolithic ARM, Ubuntu 24.04 (upstream uses EOL 18.04), current Azure API versions, TLS syslog on 6514, least-privilege NSG rules, a deprecated-NAT-pool fix, and a fix for an upstream subnet-reference bug. The full list is in **[docs/deviation-log.md](docs/deviation-log.md)**.

## Repository layout

```
bicep/              Modular Bicep source (main + modules + cloud-init)
azuredeploy.json    Compiled ARM template (Deploy-to-Azure button target)
docs/               Architecture, TLS setup, deployment patterns, deviation log
.github/workflows/  CI: offline Bicep lint + build (no Azure credentials)
```

> **Note:** This public repository contains **no deployment credentials and no CD pipeline**. CI only validates the template offline. Deployment is performed by you, in your own subscription, via the button or the CLI.

## License

[MIT](LICENSE) © John Spaid ([@x3nc0n](https://github.com/x3nc0n))

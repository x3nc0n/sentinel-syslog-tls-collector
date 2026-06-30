# TLS Setup Guide — Syslog Collector

> **Owner:** Ash (Security & Identity Engineer)  
> **Date:** 2026-06-29  
> **Relates to:** deviation-log items 4, 5, 7; architecture.md section 3

---

## Overview

The syslog collector receives CEF/syslog events from network devices and servers
over **TLS on port 6514** (RFC 5425 — Syslog over TLS). Plain-text port 514 is
disabled by default and may be enabled only for legacy senders with NSG source
restrictions.

> **Deployment patterns and mTLS:** For a complete guide to deployment topologies
> (private VNet, hybrid, public IP-allowlisted, and full mutual TLS), threat models,
> and the mTLS certificate lifecycle, see **[docs/deployment-patterns.md](deployment-patterns.md)**.
> The present document covers server-side certificate generation and rotation only.

---

## 1. Certificate Architecture

### Key Vault as Source of Truth

All TLS certificate material is stored in **Azure Key Vault** as plain-text PEM
secrets. At VM boot, `cloud-init` runs `/usr/local/bin/fetch-kv-certs.sh`, which
acquires an OAuth token from the Instance Metadata Service (IMDS) using the
VMSS's User-Assigned Managed Identity, then calls the Key Vault REST API
(`https://{kvName}.vault.azure.net/secrets/{name}?api-version=7.4`) for each
secret. The Key Vault name and UAMI client ID are **baked into the cloud-init
script at Bicep compile time** (via `loadTextContent + replace + base64` in
`bicep/modules/vmss.bicep`) — no manual configuration is required on the VM.

| Key Vault Secret Name | Content | Path on VM | Permissions |
|---|---|---|---|
| `syslog-ca-cert` | CA certificate (PEM) | `/etc/rsyslog.d/certs/ca.pem` | 0644 |
| `syslog-server-cert` | Server certificate (PEM) | `/etc/rsyslog.d/certs/server.pem` | 0644 |
| `syslog-server-key` | Server private key (PEM) | `/etc/rsyslog.d/certs/server-key.pem` | 0600 |

The Key Vault is provisioned by `bicep/modules/keyvault.bicep`. The AMA
User-Assigned Managed Identity is granted **Key Vault Secrets User** on the
vault — read-only, minimum required permission.

> ⚠️ **The `KeyVaultForLinux` VM extension is intentionally NOT used.** It
> writes secrets with opaque, non-canonical filenames that are incompatible
> with rsyslog's explicit `DefaultNetstreamDriverCertFile` paths. The IMDS
> fetch is the single, deterministic cert-delivery mechanism.
> See deviation-log item 21.

---

## 2. Self-Signed CA Bootstrap

Use this procedure when you do not yet have a PKI. Generate once, store in
Key Vault, then use Key Vault as the ongoing source of truth.

### 2a. Generate the CA

```bash
# Generate CA private key (4096-bit RSA; EC P-384 is also acceptable)
openssl genrsa -out ca-key.pem 4096

# Self-sign the CA cert — valid 10 years
openssl req -new -x509 -key ca-key.pem \
  -days 3650 \
  -subj "/CN=Syslog Collector CA/O=Example Org/C=US" \
  -out ca.pem
```

### 2b. Generate the Server Certificate

```bash
# Server private key
openssl genrsa -out server-key.pem 4096

# Certificate Signing Request
# CN should match the FQDN / DNS label of the Load Balancer PIP
# (e.g., sc-syslog.eastus2.cloudapp.azure.com)
openssl req -new -key server-key.pem \
  -subj "/CN=sc-syslog.eastus2.cloudapp.azure.com/O=Example Org/C=US" \
  -out server.csr

# Sign with the CA
openssl x509 -req -in server.csr \
  -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 365 \
  -extfile <(printf "subjectAltName=DNS:sc-syslog.eastus2.cloudapp.azure.com\n\
extendedKeyUsage=serverAuth") \
  -out server.pem
```

### 2c. Upload to Key Vault

```bash
KV_NAME=$(az deployment group show \
  --resource-group rg-sc-syslog-collector-eastus2 \
  --name deploy-<run-number> \
  --query "properties.outputs.keyVaultUri.value" -o tsv | sed 's|https://||;s|.vault.azure.net/||')
# Or from bicep output: keyVaultUri → strip https:// prefix and .vault.azure.net/ suffix

az keyvault secret set --vault-name "$KV_NAME" \
  --name "syslog-ca-cert"     --file ca.pem
az keyvault secret set --vault-name "$KV_NAME" \
  --name "syslog-server-cert" --file server.pem
az keyvault secret set --vault-name "$KV_NAME" \
  --name "syslog-server-key"  --file server-key.pem

# Securely delete local key files after upload
shred -u ca-key.pem server-key.pem server.csr
```

> ⚠️ **Never commit private keys to source control.** Store them in Key Vault
> immediately after generation and destroy local copies.

---

## 3. Certificate Rotation

> **Automation:** This section covers the manual rotation baseline. For concrete
> automation approaches (systemd timer re-fetch, scheduled CI re-issue, KV-side
> renewal with Event Grid bridge, and expiry alerting), see
> **[docs/deployment-patterns.md §4.5](deployment-patterns.md#cert-rotation-automation)**.
> Decision tracked in **a tracked enhancement**.

1. Generate a new server cert signed by the same CA (or a new CA if rotating both).
2. Upload the new cert and key as new Key Vault secret versions:
   ```bash
   az keyvault secret set --vault-name "$KV_NAME" \
     --name "syslog-server-cert" --file server-new.pem
   az keyvault secret set --vault-name "$KV_NAME" \
     --name "syslog-server-key"  --file server-key-new.pem
   ```
3. Trigger a rolling VMSS instance refresh (or run `az vmss reimage`) so new
   instances boot with the updated cert. On next cloud-init run, `fetch-kv-certs.sh`
   will pull the latest secret version automatically.
4. To force a cert refresh on running instances without reimaging, run via Azure
   Run Command:
   ```bash
   az vmss run-command invoke \
     --resource-group rg-sc-syslog-collector-eastus2 \
     --name sc-syslog-vmss \
     --command-id RunShellScript \
     --scripts "/usr/local/bin/fetch-kv-certs.sh && systemctl restart rsyslog"
   ```

If rotating the CA, you must also distribute the new `ca.pem` to all senders
**before** deploying the new server cert (to avoid trust chain breaks).

---

## 4. What a Syslog Sender Must Do

To send events to port 6514 over TLS:

### Required sender-side configuration

1. **Install `ca.pem`** (the Syslog Collector CA certificate) on the sending device.
   - Linux/rsyslog: copy to `/etc/rsyslog.d/certs/ca.pem`
   - Syslog-ng: reference in `tls(ca-file(...))` block
   - Network appliances: install via PKI / trust store settings

2. **Point the sender to port 6514** on the Load Balancer public IP or DNS label:
   ```
   Host: sc-syslog.eastus2.cloudapp.azure.com   (or the PIP DNS label)
   Port: 6514
   Protocol: TCP with TLS (RFC 5425)
   ```

3. **rsyslog sender example** (`/etc/rsyslog.d/99-forward-tls.conf`):
   ```
   global(
     DefaultNetstreamDriver="gtls"
     DefaultNetstreamDriverCAFile="/etc/rsyslog.d/certs/ca.pem"
   )
   action(
     type="omfwd"
     target="sc-syslog.eastus2.cloudapp.azure.com"
     port="6514"
     protocol="tcp"
     StreamDriver="gtls"
     StreamDriverMode="1"
     StreamDriverAuthMode="anon"
   )
   ```

4. **Mutual TLS (optional)**: If the collector is configured with
   `AuthMode="x509/name"`, the sender must also present a client certificate
   signed by a CA trusted by the collector. Contact Ash to enable this mode and
   obtain a signed client cert.

### What NOT to do

- Do **not** send on port 514 unless explicitly approved and NSG is scoped to
  your source IP range.
- Do **not** skip CA verification (`StreamDriverAuthMode="anon"` on the sender
  side is OK — it means "I don't require a client cert from the server to
  authenticate the server's identity" but TLS encryption is still applied).

---

## 5. NSG / Load Balancer Configuration

The following ports must be open (configured in `bicep/modules/network.bicep`
and `bicep/modules/loadbalancer.bicep`):

| Port | Protocol | Purpose | Source |
|---|---|---|---|
| 6514 | TCP | Syslog-over-TLS (RFC 5425) — **primary** | Known sender CIDRs |
| 514 | UDP | Plaintext syslog fallback — **disabled by default** | Specific legacy CIDRs only |
| 514 | TCP | Plaintext syslog fallback — **disabled by default** | Specific legacy CIDRs only |

See deviation-log items 4 and 7.

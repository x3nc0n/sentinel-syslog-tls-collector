# Deployment Patterns & Security Guide — Syslog-VMSS-AMA Collector

> **Author:** Ash (Security & Identity Engineer)  
> **Date:** 2026-06-29  
> **Status:** Upstream-PR-ready — all organization-specific values scrubbed; use placeholders verbatim  
> **Relates to:** deviation-log items 4, 7, 22, 23; a tracked enhancement (cert rotation automation); a tracked enhancement (ALZ/Firewall topology); [docs/tls-setup.md](tls-setup.md); [docs/architecture.md](architecture.md)

---

## Overview

This document describes six escalating deployment patterns for the Syslog-VMSS-AMA
collector, from a fully private VNet-only deployment to a hardened public
internet-facing deployment via ALZ hub-spoke + Azure Firewall. Each pattern is analyzed
for its threat model, residual risks, and concrete configuration deltas.

The goal is to give operators the information they need to choose the appropriate
pattern for their environment, and to document the full mTLS path and public-internet
hardening path for teams that require them.

**Current implementation status:** This repository implements Pattern A (internal,
private) by default, with Pattern C (public, IP-allowlisted, server-only TLS) available
via `loadBalancerPublic = true`. Pattern E (public + mTLS) is fully documented but
not yet implemented in Bicep — see §2.5 and §6. Pattern F (ALZ hub-spoke + Azure
Firewall) is fully documented but references an existing hub/Firewall topology and
is not implemented in the template — see §2.6 and §6.

---

## 1. Threat Model Primer

### 1.1 What a syslog collector must defend

A syslog collector that ingests security events into a SIEM is itself a high-value
target. Compromise of the log stream — injection, suppression, or eavesdropping —
can undermine the security posture of the entire organization.

| Threat | Description | Impact |
|---|---|---|
| **Log eavesdropping** | An attacker captures syslog traffic in transit. | Disclosure of security events, credentials in logs, PII. |
| **Log injection / poisoning** | An unauthorized sender injects fabricated log entries. | False alerts, masking real attacks, SIEM pollution. |
| **Log suppression / replay** | A MITM drops or replays log packets. | Coverage gaps; incorrect timeline reconstruction. |
| **Sender impersonation** | An attacker sends logs that appear to originate from a trusted device. | False evidence of compliance; attacker concealment. |
| **Collector DoS** | Flooding the collector with high-volume connections or junk data. | Log loss for all legitimate senders; audit trail gaps. |
| **Collector host compromise** | RCE or privilege escalation on a VMSS instance. | Full access to the log stream and downstream SIEM pipeline. |
| **Credential / key leakage** | TLS private keys or client certs exfiltrated. | Decryption of captured traffic; sender impersonation. |

### 1.2 The critical distinction: TLS anon vs. mTLS vs. NSG

This is the most important conceptual point in this document. The three controls that
operators reach for — NSG rules, TLS with `AuthMode="anon"`, and mutual TLS — provide
fundamentally different guarantees. Conflating them leads to false confidence.

#### TLS `anon` — encryption only, NOT sender authentication

When rsyslog's `imtcp` module is configured with `StreamDriver.AuthMode="anon"`, the
TLS handshake authenticates only the **server to the client** (one-way TLS, the same
model as HTTPS in a browser). The client presents no certificate. The result:

- ✅ **Confidentiality:** Traffic is encrypted; passive eavesdropping is defeated.
- ✅ **Integrity:** Data cannot be tampered in transit without detection.
- ✅ **Server authenticity** (if the sender validates the server cert): the sender
  knows it is talking to the real collector.
- ❌ **Sender authentication:** The collector has **zero cryptographic proof** of who
  sent the data. **Any host that can reach port 6514 can inject logs.**

> "Encrypted" is not the same as "authenticated." TLS anon protects data in flight;
> it does not prove who launched the flight.

#### NSG source-IP scoping — network identity, NOT application identity

An NSG rule that restricts inbound connections to `<sender-subnet-cidr>` is a
**network-layer control**. It defends against external attackers who cannot reach the
collector port from outside the allowed range. It does **not** defend against:

- Any compromised host within the allowed CIDR range.
- IP spoofing within the allowed range (possible in misconfigured or large networks).
- An authorized sender being compromised and used to inject fabricated logs.
- Shared NAT: if multiple tenants share the egress IP, all can send logs.

**NSG is a perimeter fence, not a door lock.** It is a valuable defense-in-depth layer,
but it does not constitute sender authentication.

#### mTLS `x509/name` — cryptographic sender authentication

When rsyslog is configured with `StreamDriver.AuthMode="x509/name"`, the TLS handshake
requires the client to present an X.509 certificate signed by a CA trusted by the
collector. The collector verifies:

1. The client certificate is signed by a trusted client CA.
2. The certificate's CN or SAN matches a `PermittedPeers` pattern.
3. The certificate has not expired.

This provides everything TLS anon provides, plus:

- ✅ **Cryptographic sender authentication:** A sender cannot inject logs unless it
  possesses a private key whose certificate was signed by the trusted client CA and
  whose identity matches `PermittedPeers`.
- ✅ **Revocation** (with limitations — see §4.4).

#### Summary

| Control | Confidentiality | Integrity | Server auth | Sender auth | Spoofing defence |
|---|---|---|---|---|---|
| No TLS, no NSG | ❌ | ❌ | ❌ | ❌ | ❌ |
| NSG only | ❌ | ❌ | ❌ | ❌ (network) | ⚠️ (perimeter) |
| TLS anon | ✅ | ✅ | ✅ (if sender validates) | ❌ | ❌ |
| TLS anon + NSG | ✅ | ✅ | ✅ | ❌ | ⚠️ (perimeter) |
| mTLS (x509/name) | ✅ | ✅ | ✅ | ✅ | ✅ |
| mTLS + NSG | ✅ | ✅ | ✅ | ✅ | ✅✅ (layered) |

---

## 2. Deployment Patterns

### Pattern A — Private / internal-only (current default) {#pattern-a}

#### Topology

The collector is fronted by an **internal Standard Load Balancer** with no public IP.
All syslog senders reside on the same Azure VNet or a directly peered VNet. Traffic
never leaves the Azure backbone.

```
[Sender VNet / Peered VNet]
  Sender host → TCP :6514 (TLS)
        │ (VNet backbone — no public internet path)
        ▼
  Internal LB (private frontend IP)
        │
        ▼
  VMSS instances (rsyslog + AMA)
        │ HTTPS (always encrypted)
        ▼
  Azure Monitor ingestion → Log Analytics / Sentinel
```

#### Network controls

- NSG `Allow-Syslog-TLS`: source = `<sender-subnet-cidr>`, dest port = 6514, TCP.
- No public IP exists; there is no routable path from the internet to the collector.

#### TLS mode

`StreamDriver.AuthMode="anon"` — TLS encryption on; no client certificate required.

#### Sender authentication

None (cryptographic). Network-layer: NSG restricts source to `<sender-subnet-cidr>`.

#### Threat model & residual risk

| Threat | Mitigated? | Notes |
|---|---|---|
| External eavesdropping | ✅ | No external path; TLS also encrypts within VNet. |
| Log injection from external | ✅ | No routable path to the collector. |
| Log injection from within `<sender-subnet-cidr>` | ⚠️ | Any host in the allowed CIDR can inject logs. |
| Collector DoS | Low | Only senders on the peered VNet can reach the port. |
| Collector host compromise | Standard | Azure VMSS hardening; no SSH from internet; Bastion/Serial Console only. |

**Residual risk:** Within the allowed CIDR, log injection is possible without
cryptographic barriers. This is acceptable for trusted-VNet scenarios where the
network boundary is the organizational trust boundary.

#### When to use

All senders are Azure-native (VMs, AKS, App Services via VNet integration) on the same
or peered VNet. This is the **recommended default** for most Azure-native deployments.

#### Concrete config / param deltas

```bicep
// main.bicepparam — Pattern A defaults (no change from repo defaults)
param loadBalancerPublic         = false              // internal LB, no PIP
param enableTls                  = true               // TLS on port 6514
param tlsPort                    = 6514
param enablePlaintext            = false
param allowedSyslogSourceCidrs   = ['<sender-subnet-cidr>']
```

```conf
# bicep/scripts/rsyslog-tls.conf — no change from shipped default
module(load="imtcp"
       StreamDriver.Name="gtls"
       StreamDriver.Mode="1"
       StreamDriver.AuthMode="anon")   # encryption only
```

Key Vault secrets required: `syslog-ca-cert`, `syslog-server-cert`, `syslog-server-key`.

---

### Pattern B — Hybrid / on-prem private {#pattern-b}

#### Topology

Senders reside on-premises, reaching the collector over a **site-to-site VPN or
ExpressRoute** private peering connection. The LB remains internal (no public IP).
Traffic traverses the WAN link but never the public internet.

```
[On-premises network]
  Appliance / server → TCP :6514 (TLS)
        │ (VPN tunnel or ExpressRoute private peering)
        ▼
  Azure VPN / ExpressRoute Gateway
        │ (Azure backbone)
        ▼
  Internal LB (private frontend IP, Azure VNet)
        │
        ▼
  VMSS instances (rsyslog + AMA)
```

#### Network controls

- NSG `Allow-Syslog-TLS`: source = `<on-prem-site-cidr>` (the on-premises address
  range assigned on the Local Network Gateway or ExpressRoute circuit).
- The VPN Gateway or ExpressRoute circuit provides a separate network-level link
  identity. Only traffic originating from the authenticated WAN circuit arrives.

#### TLS mode

`StreamDriver.AuthMode="anon"` — same as Pattern A.

#### Sender authentication

None (cryptographic). Network-layer: NSG restricts to on-prem CIDRs; VPN/ER circuit
provides link-level authentication.

#### Threat model & residual risk

| Threat | Mitigated? | Notes |
|---|---|---|
| Public internet eavesdropping | ✅ | No internet path; VPN/ER tunnel + TLS = double encryption on the WAN segment. |
| Log injection from external | ✅ | No internet path. |
| Log injection from within `<on-prem-cidr>` | ⚠️ | Any host reachable via the VPN/ER circuit from that CIDR can inject logs. |
| Insider threat (on-prem) | ⚠️ | A compromised on-prem host is inside the allowed range. |

**Residual risk:** Slightly higher than Pattern A because on-premises networks are
often larger and less tightly controlled than Azure VNets. Use the narrowest possible
CIDRs (per-site or per-subnet, not a broad on-premises supernet).

#### When to use

Hybrid deployments where some senders are on-premises appliances (firewalls, routers,
network devices) that cannot send to a public endpoint. The organization has an existing
VPN or ExpressRoute to Azure.

#### Concrete config / param deltas

```bicep
param loadBalancerPublic         = false
param enableTls                  = true
param tlsPort                    = 6514
param enablePlaintext            = false
param allowedSyslogSourceCidrs   = ['<on-prem-site-a-cidr>', '<on-prem-site-b-cidr>']
```

No rsyslog config change from Pattern A.  
Key Vault secrets: same as Pattern A.

> **Note:** The VPN Gateway or ExpressRoute circuit is provisioned separately and is
> not part of this Bicep template. Adjust `allowedSyslogSourceCidrs` to match the
> on-premises address ranges configured on your Azure Gateway Local Network Gateway.

---

### Pattern C — Public, IP-allowlisted, server-only TLS (anon) {#pattern-c}

#### Topology

The collector is fronted by a **Standard Load Balancer with a public IP**. Access is
restricted by NSG to known sender egress IP ranges. TLS remains server-only (anon).

```
[Internet — sender at <known-sender-egress-ip>]
  Sender → TCP :6514 (TLS anon)
        │ (public internet, encrypted)
        ▼
  Azure Public IP (Standard SKU, static)
  Standard LB (public frontend)
        │
  NSG: Allow :6514 from <known-sender-egress-cidr> only
  NSG: Deny all other inbound  ← enforced before traffic reaches VMSS
        │
        ▼
  VMSS instances (rsyslog + AMA)
```

#### Network controls

- NSG `Allow-Syslog-TLS`: source = `<known-sender-egress-cidr>`, dest port = 6514, TCP.
  All other sources are implicitly denied.
- Azure DDoS Basic protection applies to the public IP automatically (free tier).
- For production-grade deployments, consider Azure DDoS Standard.

#### TLS mode

`StreamDriver.AuthMode="anon"` — TLS encryption only; no client certificate required.

#### Sender authentication

NSG source-IP allowlisting. No cryptographic sender authentication.

#### Threat model & residual risk

| Threat | Mitigated? | Notes |
|---|---|---|
| External eavesdropping | ✅ | TLS encrypts all traffic. |
| Log injection from outside allowlist | ✅ | NSG blocks at network layer. |
| **Log injection from inside allowlist** | ❌ | **Any host at `<known-sender-egress-cidr>` can inject logs.** No cryptographic barrier. |
| Allowlist drift | ⚠️ | If sender egress ranges expand without NSG update, the injection window grows silently. |
| Shared egress NAT | ⚠️ | If multiple organizations share the egress IP (corporate proxy, shared cloud NAT), all can inject logs. |
| Source IP spoofing | ⚠️ | TCP SYN spoofing is difficult but not impossible; TCP handshake makes it harder, not impossible. |
| Collector DoS | ⚠️ | Public IP is reachable from the allowlisted range; DDoS mitigation is recommended. |

**Residual risk — critical warning:** The allowlist provides a perimeter, but not
sender authentication. A single compromised host within the allowlisted egress range
can inject arbitrary log data. If the egress range is shared (a corporate NAT gateway
serving many users or organizations), the effective authentication boundary is the
entire NAT pool — not an individual device.

#### When to use

- Senders are on the public internet with stable, known egress IP addresses
  (dedicated egress NAT gateways, static IP appliances).
- Sender devices cannot present client TLS certificates (legacy appliances,
  embedded systems, third-party SaaS log forwarders).
- The operator accepts the residual injection risk and compensates with monitoring.

**Do not use** if the egress IP range is shared with untrusted tenants or large NAT
pools with many users. Escalate to Pattern E instead.

#### Concrete config / param deltas

```bicep
param loadBalancerPublic         = true       // ← creates public IP and public frontend
param enableTls                  = true
param tlsPort                    = 6514
param enablePlaintext            = false
param allowedSyslogSourceCidrs   = ['<known-sender-egress-cidr-1>', '<known-sender-egress-cidr-2>']
```

```conf
# rsyslog-tls.conf — no change from Pattern A (AuthMode stays "anon")
module(load="imtcp"
       StreamDriver.Name="gtls"
       StreamDriver.Mode="1"
       StreamDriver.AuthMode="anon")
```

Key Vault secrets: same as Pattern A.

**Additional operational requirements:**

- NSG allowlist must be reviewed regularly (quarterly minimum). Allowlist drift = growing
  injection window.
- Server TLS certificate CN/SAN must match the public IP DNS label or a custom DNS name
  pointing to the public IP (e.g., `collector.example.com`).
- Enable Azure Monitor alerts on NSG flow log anomalies (unexpected source IPs, volume
  spikes).

---

### Pattern D — Public, server-only TLS, broad/unknown sources — ANTI-PATTERN ⛔ {#pattern-d}

> **This pattern is documented as an anti-pattern. Do not deploy it.** This section
> exists to explain the risks so operators understand why Pattern E is required when
> public internet ingestion from unknown sources is needed.

#### What this looks like

```bicep
param loadBalancerPublic         = true
param allowedSyslogSourceCidrs   = ['0.0.0.0/0']  // ← DANGEROUS: allow any source IP
param enableTls                  = true             // encrypted, but not authenticated
```

#### Why it is dangerous

**1. Log injection from any host on the internet.**  
With no NSG source restriction, any host can connect to port 6514 and inject arbitrary
log data into your SIEM. `AuthMode="anon"` means no certificate is required. An
attacker can:

- Forge log entries that appear to come from legitimate systems.
- Inject "clean" events to cover up real attack activity.
- Create false-positive alerts to exhaust SOC analyst capacity (alert fatigue).
- Generate artificially high log volumes to inflate ingestion costs.

**2. Log poisoning attacks.**  
Fabricated CEF/syslog events with crafted field values can manipulate SIEM detection
rules, trigger false incidents, suppress real ones, or pollute compliance reports.

**3. DoS via connection exhaustion.**  
`imtcp` maintains TCP connection state per sender. With unrestricted access, an
attacker can open thousands of TLS connections simultaneously, exhausting file
descriptors and memory on collector VMs — starving legitimate senders of capacity.

**4. SIEM cost amplification.**  
Log Analytics Workspace and Sentinel are priced per GB ingested. An attacker with
unrestricted write access can arbitrarily inflate ingestion costs at negligible cost
to themselves.

**5. Total loss of evidential value.**  
Because `AuthMode="anon"` provides no sender verification, none of the log data in
Sentinel can be relied upon as authentic. The evidential and forensic value of the
SIEM is fundamentally compromised.

#### What an attacker does in 60 seconds

No special tooling required — rsyslog or `openssl s_client` suffices:

```bash
# Attacker machine — no cert required
# Any syslog over TLS client works; even raw openssl
openssl s_client -connect collector.example.com:6514 2>/dev/null
# Once connected, type a valid syslog/CEF line and press Enter
```

Or with an rsyslog `omfwd` action on any internet-connected server:

```conf
action(type="omfwd"
       target="collector.example.com"
       port="6514"
       protocol="tcp"
       StreamDriver="gtls"
       StreamDriverMode="1"
       StreamDriverAuthMode="anon")
```

Any entity on the internet can do this. TLS provides encryption, not authentication.

#### The correct alternative

If you need public internet ingestion from senders whose source IPs are not known
in advance, or whose source IPs are not reliably exclusive, the correct solution is
**Pattern E (mTLS)**. Require client certificates; make every authorized sender
identifiable and cryptographically verifiable.

---

### Pattern E — Public + mTLS (the culmination) {#pattern-e}

> **Implementation status:** This pattern is fully documented and designed but
> **not yet implemented** in Bicep. The rsyslog configuration stubs exist in
> comments in `bicep/scripts/rsyslog-tls.conf`. The Bicep parameters
> `enableMutualTls` and `permittedPeers` do not yet exist. See §2.5.6 for the
> explicit TODO list.

#### Topology

```
[Internet — sender with a valid client certificate]
  Sender (client cert: sender01.senders.example.com, signed by client CA)
        │ mTLS :6514 — BOTH server cert AND client cert required
        │ (public internet, mutual TLS)
        ▼
  Azure Public IP (Standard SKU, static)
  Standard LB (public frontend, TCP 6514)
        │
  NSG: Allow :6514 from <known-cidr> [defense-in-depth; can be broader than in Pattern C]
  NSG: Deny all other inbound
        │
        ▼
  VMSS (rsyslog — AuthMode="x509/name")
        │ Client cert verification:
        │  1. Signed by trusted client CA (syslog-client-ca-cert from Key Vault)
        │  2. CN or SAN matches PermittedPeers
        │  3. Not expired
        ▼
  AMA → Azure Monitor / Sentinel
```

NSG is still applied in Pattern E as **defense-in-depth**. Even if an attacker steals
a client certificate, the NSG can limit the attack surface. However, the primary
sender authentication mechanism is the client certificate, not the NSG.

#### 2.5.1 rsyslog configuration

The rsyslog `imtcp` module must be switched from `AuthMode="anon"` to
`AuthMode="x509/name"`. The `PermittedPeers` directive specifies which client cert
identities are allowed to connect.

```conf
# /etc/rsyslog.d/50-tls-listener.conf — Pattern E (mTLS enabled)
# NOTE: This is the target configuration. Currently not generated by Bicep.
# The shipped rsyslog-tls.conf stubs this in comments; enabling requires
# the Bicep TODO items in §2.5.6.

module(load="imtcp"
       StreamDriver.Name="gtls"
       StreamDriver.Mode="1"
       StreamDriver.AuthMode="x509/name")   # ← changed from "anon"

# PermittedPeers: allowed client certificate identities.
# Option 1 — exact names (recommended for high-assurance; one entry per device)
$ActionSendStreamDriverPermittedPeer sender01.senders.example.com
$ActionSendStreamDriverPermittedPeer sender02.senders.example.com
$ActionSendStreamDriverPermittedPeer firewall-prod-01.senders.example.com

# Option 2 — wildcard by subdomain (operationally simpler; relies on CA issuance controls)
# $ActionSendStreamDriverPermittedPeer *.senders.example.com

global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/certs/client-ca.pem"    # ← client CA for sender verification
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/certs/server.pem"     # server cert
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/certs/server-key.pem"  # server key (mode 0600)
)

input(type="imtcp" port="6514" name="tls-syslog")
```

> **Important rsyslog/gtls behavior:** In the gtls driver,
> `DefaultNetstreamDriverCAFile` is used both to verify the *server* certificate
> (from the sender's perspective) and to verify the *client* certificate (from the
> collector's perspective). For mTLS with a separate client CA, this file must
> contain the **client CA certificate**. Distribute the **server CA certificate**
> separately to senders so they can verify the collector. If using a single CA for
> both, this simplifies config but weakens separation of concerns.

#### 2.5.2 PermittedPeers: exact names vs. wildcards

The `PermittedPeers` directive compares against the certificate's subject CN and
Subject Alternative Names (SANs).

| Style | Example | Use case | Risk |
|---|---|---|---|
| **Exact name** | `sender01.senders.example.com` | High-assurance; one cert per device identity | Every new sender requires a config update and VMSS reimage |
| **Wildcard subdomain** | `*.senders.example.com` | Operationally simpler; one rule covers all CA-issued certs | Relies entirely on CA issuance controls; a compromised CA = full injection access |
| **Regex** (rsyslog 8.x+) | `~sender[0-9]+\.senders\.example\.com` | Pattern-based allowlisting | Still relies on CA controls; adds complexity |

**Recommendation:** Use exact names for the highest-sensitivity senders. Use wildcards
only when the client CA issuance process is strictly controlled (automated PKI with
per-device enrollment validation).

#### 2.5.3 Private client CA architecture

For mTLS, two separate certificate authorities are strongly recommended:

```
Server CA (existing, already in Key Vault as syslog-ca-cert)
  └── Signs: collector server certificate (CN = collector.example.com)
        Purpose: senders verify they are talking to the real collector

Client CA (NEW for mTLS — stored in Key Vault as syslog-client-ca-cert)
  └── Signs: per-sender client certificates
        CN / SAN: sender01.senders.example.com
        CN / SAN: firewall-prod-01.senders.example.com
        Purpose: collector verifies sender identity
```

**Why separate CAs:**

- A compromised server CA does not grant the ability to forge client certificates.
- A compromised client CA does not grant the ability to impersonate the collector.
- Rotation of one CA does not force rotation of the other.
- Separation of duties: the team that manages sender onboarding controls the client
  CA; the team that manages the collector controls the server CA.

#### 2.5.4 Key Vault additions for mTLS

In addition to the three existing secrets, mTLS requires a fourth:

| KV Secret Name | Content | Path on Collector VM | Mode | Purpose |
|---|---|---|---|---|
| `syslog-ca-cert` | Server CA certificate (PEM) | `/etc/rsyslog.d/certs/ca.pem` | 0644 | Senders use this to verify the collector; already exists |
| `syslog-server-cert` | Server certificate (PEM) | `/etc/rsyslog.d/certs/server.pem` | 0644 | Collector presents this to senders; already exists |
| `syslog-server-key` | Server private key (PEM) | `/etc/rsyslog.d/certs/server-key.pem` | 0600 | Server TLS key; already exists |
| **`syslog-client-ca-cert`** | **Client CA certificate (PEM)** | **`/etc/rsyslog.d/certs/client-ca.pem`** | **0644** | **NEW — collector uses this to verify sender client certs** |

The `fetch-kv-certs.sh` script embedded in `cloud-init.yaml` must be extended to
fetch this fourth secret and write it to the canonical path. The
`DefaultNetstreamDriverCAFile` directive in `rsyslog-tls.conf` must reference
`/etc/rsyslog.d/certs/client-ca.pem` (replacing the current reference to `ca.pem`)
when mTLS is enabled.

> **Alternative — combined CA bundle:** A single file
> (`/etc/rsyslog.d/certs/ca-bundle.pem`) containing both the server CA and client CA
> can be used as `DefaultNetstreamDriverCAFile`. The rsyslog/gtls driver will trust
> any chain anchored to any CA in the bundle. The trade-off: it combines trust anchors
> in a single file, making it harder to remove one CA without affecting the other.
> The separate path is cleaner for lifecycle management.

#### 2.5.5 Sender-side configuration (rsyslog omfwd with mTLS)

Each authorized sender must be configured with:

1. The **server CA certificate** (to verify the collector's server cert).
2. A **client certificate** (issued by the client CA) unique to this sender.
3. The **client private key** for this sender's client cert.

```conf
# Sender rsyslog config: /etc/rsyslog.d/99-forward-mtls.conf

global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/certs/server-ca.pem"    # server CA — verifies collector
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/certs/client.pem"     # this sender's client cert
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/certs/client-key.pem"  # client private key (mode 0600)
)

action(
  type="omfwd"
  target="collector.example.com"
  port="6514"
  protocol="tcp"
  StreamDriver="gtls"
  StreamDriverMode="1"
  StreamDriverAuthMode="x509/name"
  StreamDriverPermittedPeers="collector.example.com"  # must match collector server cert CN/SAN
)
```

**Client certificate generation (per sender):**

```bash
# Run on the CA workstation — keep the client CA key offline or in a secure HSM/vault

# 1. Generate the per-sender private key
openssl genrsa -out sender01-key.pem 4096

# 2. Create the Certificate Signing Request
#    CN must match your PermittedPeers pattern on the collector
openssl req -new -key sender01-key.pem \
  -subj "/CN=sender01.senders.example.com/O=Example Corp/C=US" \
  -out sender01.csr

# 3. Sign with the client CA
openssl x509 -req -in sender01.csr \
  -CA client-ca.pem -CAkey client-ca-key.pem -CAcreateserial \
  -days 365 \
  -extfile <(printf "extendedKeyUsage=clientAuth\nsubjectAltName=DNS:sender01.senders.example.com\n") \
  -out sender01.pem

# 4. Distribute sender01.pem + sender01-key.pem to the sender via a secure channel
#    (not email, not unencrypted HTTP; use ansible-vault, az keyvault, SCP over existing auth)

# 5. Upload client-ca.pem to the collector Key Vault as syslog-client-ca-cert
az keyvault secret set \
  --vault-name "<keyvault-name>" \
  --name "syslog-client-ca-cert" \
  --file client-ca.pem

# 6. Destroy local private key copies after secure distribution; never commit to source control
shred -u sender01-key.pem sender01.csr
```

> ⚠️ `extendedKeyUsage=clientAuth` is required. Some rsyslog/gtls versions reject
> client certificates that lack this EKU. Always set it explicitly.

#### 2.5.6 Bicep / parameter changes required (TODO — not yet implemented)

The following items must be built to fully operationalize Pattern E:

| Item | Current state | Change required |
|---|---|---|
| `enableMutualTls` param | Does not exist | Add `bool` param (default `false`); when `true`, generate rsyslog config with `AuthMode="x509/name"` |
| `permittedPeers` param | Does not exist | Add `array` param; inject as `$ActionSendStreamDriverPermittedPeer` lines in rsyslog conf |
| `syslog-client-ca-cert` KV fetch | Not fetched | Extend `fetch-kv-certs.sh` to fetch this secret → `/etc/rsyslog.d/certs/client-ca.pem` |
| `rsyslog-tls.conf` generation | Always generates `"anon"` | Bicep should conditionally generate `"x509/name"` block when `enableMutualTls = true` |
| `DefaultNetstreamDriverCAFile` path | Points to `ca.pem` (server CA) | For mTLS, must reference `client-ca.pem` (or a combined bundle); parameterize or generate in cloud-init |
| `keyvault.bicep` | Fetches 3 secrets | Add fetch call for `syslog-client-ca-cert`; ensure UAMI has Secrets User role on KV |

**Today's `rsyslog-tls.conf` already stubs the mTLS block in comments:**

```conf
# $ActionSendStreamDriverPermittedPeer *.yourdomain.example.com
```

The implementation path is clear. It has not been built because:

1. mTLS requires a client CA and a per-sender cert issuance and distribution process,
   which is an operational lift the team may not be ready for until Pattern A/B/C
   is stable.
2. `AuthMode="anon"` with NSG scoping is sufficient for private and hybrid deployments.
3. This document exists to define exactly what Pattern E requires so the team can
   implement it deliberately and correctly when the time comes.

---

### Pattern F — Public via ALZ hub-spoke + Azure Firewall {#pattern-f}

> **Implementation status:** Fully documented. **Not implemented** in this template.
> In most ALZ deployments the hub VNet and Azure Firewall already exist in the
> Connectivity subscription; the workload template would peer to them and add a DNAT
> rule rather than create a new firewall. Decision tracked in **a tracked enhancement**.
>
> **Cost note:** Azure Firewall Premium (~$2/hr + data processing) and Azure DDoS
> Network Protection (~$3,000/month base) are significant expenditures. Pattern F is
> the correct architecture when public internet ingestion is mandatory and the threat
> model justifies the cost. **The recommended default remains Pattern A or B (private
> ingress).** Pattern F is the "if public ingress is mandatory" tier.

#### Why a WAF does not apply

A common question: can an Azure WAF (Azure Application Gateway WAF, Azure Front Door)
protect the syslog collector? **It cannot, and it is the wrong tool.**

- **Application Gateway and Front Door are L7 HTTP/HTTPS proxies.** Their WAF
  capabilities inspect HTTP request headers, URI paths, and request bodies using
  rule sets (OWASP CRS, custom rules). They have no concept of a syslog connection.
- **Syslog-over-TLS (RFC 5425, RFC 6514) is raw L4 TCP.** There is no HTTP, no URL,
  no HTTP header — just a TLS-encrypted TCP byte stream carrying syslog framing. Neither
  Application Gateway nor Front Door support arbitrary TCP forwarding as a listener
  protocol. They cannot terminate or forward port 6514.

> **Protection model for syslog-over-TLS:** The applicable controls are
> **network-layer** (Azure Firewall DNAT + Threat Intelligence + IDPS, NSG allowlisting,
> Azure DDoS) and **application-layer authentication** (mTLS client certificates). HTTP
> content inspection does not apply — there is no HTTP to inspect.

**Azure Firewall Premium TLS inspection** is also not applicable here. Its TLS
inspection feature is designed for HTTP/HTTPS traffic: it acts as an SSL middlebox
so that IDPS signatures can match decrypted HTTP payloads. For a raw TCP syslog
connection, the Firewall passes the encrypted TCP stream and logs flow metadata
(src/dst IP, port, bytes) — it does not, and cannot, inspect the syslog content.
**Encryption is end-to-end to rsyslog; authenticity is mTLS's job.**

The Firewall's IDPS in Pattern F operates at L4/signature level: it inspects TCP
flow metadata, known-bad IP reputation, and network-level attack signatures. This is
valuable defense-in-depth but narrower in coverage than HTTP-oriented WAF rule sets.

#### Do you need the Load Balancer in Pattern F?

**Yes — keep an internal LB. Remove the public IP from the LB.**

The internal Load Balancer serves three functions that remain valid in Pattern F:

1. **Stable private VIP** for the Firewall DNAT rule. VMSS instance IPs change as
   the scale set grows and shrinks; the LB frontend IP is stable across scale events.
2. **High availability** across VMSS instances via health-probe-based backend selection.
3. **VMSS scaling integration** — new instances automatically register in the LB
   backend pool via the VMSS scale-set association.

In Pattern F the LB frontend is a **private IP in the workload spoke**. The Azure
Firewall in the hub carries the sole public IP. No public IP exists on the LB or on
any VMSS instance. The collector has zero direct internet path.

#### Topology

```
[Internet — authorized senders at <sender-egress-cidr>]
  Sender → mTLS client cert (strongly recommended; see §2.5)
        │ TCP :6514 (TLS, public internet)
        ▼
  ┌── ALZ Connectivity Hub VNet ──────────────────────────────┐
  │  Azure Firewall Premium (public IP: <hub-firewall-pip>)   │
  │    Threat Intelligence: Deny (block known-bad IPs)        │
  │    IDPS: L4/signature (NOT syslog TLS content inspection) │
  │    DNAT rule:                                             │
  │      <hub-firewall-pip>:6514 → <spoke-lb-frontend-ip>:6514│
  │  Azure DDoS Network Protection (on Firewall PIP)          │
  │  Azure Bastion (hub) — break-glass, no port 22 on VMs    │
  └──────────────────────┬────────────────────────────────────┘
                         │ VNet Peering (hub ↔ spoke)
                         │ UDR: 0.0.0.0/0 → Firewall private IP
                         ▼
  ┌── Workload Spoke VNet (<spoke-vnet-cidr>) ────────────────┐
  │  NSG (defense-in-depth):                                  │
  │    Allow :6514 TCP src <hub-azfw-private-ip-cidr> only   │
  │    Deny all other inbound :6514                           │
  │                                                           │
  │  Internal LB (frontend: <spoke-lb-frontend-ip>)           │
  │        │ TCP :6514                                        │
  │        ▼                                                  │
  │  VMSS instances (private IPs only — no public IP)         │
  │    rsyslog AuthMode="x509/name" (mTLS) + AMA              │
  │                                                           │
  │  Key Vault  ← private endpoint in spoke                  │
  │  AMPLS      ← Azure Monitor Private Link Scope           │
  └──────────────────────┬────────────────────────────────────┘
                         │ HTTPS/443 (private via AMPLS)
                         ▼
                 Azure Monitor / Sentinel
```

All collector egress (Azure Monitor, Key Vault, OS updates) routes via the Firewall
or private endpoints — the spoke has no direct internet breakout.

#### Network controls

| Control | Detail |
|---|---|
| **Azure Firewall DNAT rule** | Translates `<hub-firewall-pip>:6514` → `<spoke-lb-frontend-ip>:6514`. The sole public ingress path to the collector. |
| **Azure Firewall Threat Intelligence** | Mode: Deny. Blocks connections from IPs/domains on Microsoft's threat feed before the DNAT rule is evaluated. |
| **Azure Firewall IDPS (Premium)** | L4/signature intrusion detection on TCP flow metadata. Not deep TLS inspection of syslog content — that is end-to-end encrypted to rsyslog (see above). |
| **Azure DDoS Network Protection** | Applied to `<hub-firewall-pip>`. Adaptive ML-based volumetric and protocol attack mitigation. Standard plan required (Basic is automatic but minimal). |
| **NSG source allowlist (spoke)** | `Allow :6514 TCP` from the Firewall's private IP subnet only. Blocks any traffic that does not arrive via the Firewall DNAT path — backstop against UDR misconfiguration. |
| **Key Vault private endpoint** | KV DNS resolves to a private IP in the spoke. KV API traffic does not traverse the public Firewall IP or the internet. |
| **AMPLS (Azure Monitor Private Link Scope)** | AMA telemetry and DCR traffic routes to Azure Monitor over private endpoints in the spoke. No direct-internet path for the log-upload leg. |
| **Microsoft Defender for Servers** | Per-VMSS-instance: vulnerability assessment, endpoint detection, file integrity monitoring, just-in-time VM access. |
| **Azure Bastion (hub)** | Break-glass RDP/SSH over HTTPS (443) from the portal. The collector NSG has no inbound rule for port 22 from any source. |
| **No public IP on LB or VMSS** | Internal LB, private frontend only. No direct internet path to any collector resource. |

#### TLS mode

`StreamDriver.AuthMode="x509/name"` (mTLS) is **strongly recommended** for Pattern F.
The Azure Firewall provides network-layer filtering, but it does not prevent a sender
with a routable DNAT path from injecting arbitrary log data if `AuthMode="anon"` is
in use. The Firewall's IDPS cannot inspect the encrypted syslog payload.

**Pattern F should be combined with Pattern E (mTLS).** The Firewall provides
network-layer depth; mTLS provides cryptographic sender authentication. Neither
substitutes for the other.

`AuthMode="anon"` + Pattern F (server-only TLS) is better than Pattern C alone, but
leaves sender authentication absent. Only accept this combination for senders that
cannot present client certificates, with compensating controls: tight NSG allowlisting,
IDPS alerting, Defender for Servers, and continuous Sentinel monitoring.

#### Sender authentication

- **Primary:** mTLS client certificate (`x509/name`). See §2.5 and §4.
- **Defense-in-depth L1:** Azure Firewall Threat Intelligence — known-bad IP blocking.
- **Defense-in-depth L2:** Azure Firewall IDPS — L4/signature network detection.
- **Defense-in-depth L3:** NSG source allowlist — blocks non-Firewall ingress paths.
- **N/A:** WAF content inspection — see "Why a WAF does not apply" above.

#### Threat model & residual risk

| Threat | Mitigated? | Notes |
|---|---|---|
| External eavesdropping | ✅ | mTLS end-to-end encryption. Firewall sees TCP flow metadata only. |
| Log injection from unknown internet hosts | ✅ | Firewall Threat Intel + IDPS + DNAT scope. mTLS requires a valid client cert. |
| Log injection from within `<sender-egress-cidr>` | ✅ (with mTLS) | Requires theft of a per-sender private key + signed cert. Without mTLS: NSG-perimeter only. |
| Sender impersonation | ✅ (with mTLS) | Client cert CN/SAN must match PermittedPeers. |
| Volumetric DoS / connection flood | ⚠️ | DDoS Network Protection + Firewall IDPS provide volumetric mitigation. VMSS autoscale handles legitimate volume spikes. |
| TLS handshake CPU exhaustion | ⚠️ | NSG limits source surface. mTLS means attacker must complete a full handshake with a valid cert — reduces casual floods. |
| Firewall bypass via UDR misconfiguration | ⚠️ | NSG allowlist (Firewall private IP only) is the backstop. Enforce UDR via Azure Policy. |
| Collector host compromise | ⚠️ | No PIP, Bastion-only access, Defender for Servers reduce the surface. RCE in rsyslog or a compromised UAMI token remains a serious residual risk. |
| KV / cert material exfiltration | Low | Private endpoint — no internet path to Key Vault. UAMI scoped to Secrets User only. |

**Honest residual risk callouts:**

1. **Firewall IDPS is L4/signature, not semantic.** A valid sender with a legitimate
   client cert can still inject malformed syslog content. mTLS authenticates the sender;
   it does not validate the payload content. Content integrity is a separate concern
   (e.g., CEF/syslog parsing rules in Sentinel).

2. **The Firewall does not decrypt syslog TLS.** The encrypted stream passes through;
   the Firewall logs flow metadata. This is the intended behavior — end-to-end
   encryption to rsyslog is preserved, as it should be.

3. **Hub/spoke coupling.** Adding a DNAT rule and UDR may require a platform-team
   change request through Connectivity subscription governance. The workload template
   cannot unilaterally modify the hub Firewall.

#### When to use

- Public internet ingestion is **mandatory**: senders cannot use VPN/ExpressRoute and
  lack stable exclusive egress IPs for a Pattern C allowlist.
- The organization has an existing ALZ hub-spoke topology with Azure Firewall Premium
  in the Connectivity subscription.
- Compliance or risk requirements mandate network-layer controls beyond a raw public IP.
- **Combine with Pattern E (mTLS)** for cryptographic sender authentication.

**Do not use as the default.** Pattern A (private VNet) is the recommended default.
Deploy Pattern F only when public internet ingestion cannot be avoided.

#### Concrete config / param deltas

The template does **not** create the hub VNet or Azure Firewall. These are managed in
the Connectivity subscription. The collector-side changes are:

```bicep
// main.bicepparam — Pattern F (internal LB; hub Firewall handles the public IP)
param loadBalancerPublic         = false              // internal LB, no PIP
param enableTls                  = true
param tlsPort                    = 6514
param enablePlaintext            = false
param allowedSyslogSourceCidrs   = ['<hub-azfw-private-ip-cidr>']  // NSG: Firewall only
param enableMutualTls            = true               // strongly recommended; see §2.5
param permittedPeers             = ['*.senders.example.com']

// Future hub-integration params (not yet implemented in this template):
// param hubVnetId                 = '<hub-vnet-resource-id>'
// param hubFirewallName           = '<hub-firewall-name>'
// param hubFirewallResourceGroup  = '<hub-connectivity-rg>'
// param hubFirewallPrivateIp      = '<hub-firewall-private-ip>'
```

```bash
# Firewall DNAT rule — added by platform team in Connectivity subscription
# (not generated by this template)
az network firewall nat-rule create \
  --resource-group <hub-connectivity-rg> \
  --firewall-name <hub-firewall-name> \
  --collection-name syslog-collector-dnat \
  --priority 200 --action Dnat \
  --name syslog-tls-6514 \
  --protocols TCP \
  --source-addresses '<sender-egress-cidr>' \
  --destination-addresses '<hub-firewall-pip>' \
  --destination-ports 6514 \
  --translated-address '<spoke-lb-frontend-ip>' \
  --translated-port 6514
```

```bash
# Default-route UDR — applied to collector subnet in the workload spoke
# Forces all egress through the Firewall; prevents asymmetric routing on DNAT returns
az network route-table route create \
  --resource-group <spoke-rg> \
  --route-table-name <spoke-udr-name> \
  --name default-to-firewall \
  --address-prefix 0.0.0.0/0 \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address '<hub-firewall-private-ip>'
```

Key Vault: add a private endpoint in the workload spoke (see §3.2).  
Azure Monitor: configure AMPLS and link the Log Analytics workspace + DCR Data
Collection Endpoint to private DNS zones in the spoke.  
mTLS: additionally required Key Vault secrets — see §2.5.4.

---

## 3. Cross-Cutting Security Controls

### 3.1 Defense-in-depth matrix

| Control | A (Private) | B (Hybrid) | C (Public/IP-locked) | D (ANTI-PATTERN) | E (Public + mTLS) | F (ALZ+Firewall) |
|---|---|---|---|---|---|---|
| **NSG source scoping** | ✅ VNet CIDR | ✅ On-prem CIDRs | ✅ Egress CIDRs | ❌ | ✅ Defense-in-depth | ✅ Firewall IP only |
| **No public IP** | ✅ | ✅ | ❌ (PIP required) | ❌ | ❌ (PIP required) | ✅ (PIP on Firewall only) |
| **TLS in-transit encryption** | ✅ | ✅ | ✅ | ✅ (enc, not auth) | ✅ | ✅ |
| **mTLS sender authentication** | ❌ (not needed) | ❌ (not needed) | ❌ | ❌ | ✅ | ✅ (strongly recommended) |
| **Key Vault (cert storage, RBAC)** | ✅ | ✅ | ✅ | N/A | ✅ (+ client CA) | ✅ (+ private endpoint) |
| **IMDS cert delivery (no disk secrets)** | ✅ | ✅ | ✅ | N/A | ✅ | ✅ |
| **UAMI — Secrets User scope only** | ✅ | ✅ | ✅ | N/A | ✅ | ✅ |
| **No SSH from internet** | ✅ | ✅ | ✅ | ❌ (implicit risk) | ✅ | ✅ (Bastion in hub) |
| **Azure Firewall (Threat Intel + IDPS)** | N/A | N/A | N/A | N/A | N/A | ✅ (hub, Premium) |
| **Azure DDoS protection** | N/A (internal) | N/A (internal) | ⚠️ Basic (auto) | N/A | ⚠️ Basic; Standard recommended | ✅ Standard (on Firewall PIP) |
| **Key Vault private endpoint** | Optional | Optional | Optional | N/A | Optional | ✅ Required |
| **AMPLS (Azure Monitor private link)** | Optional | Optional | Optional | N/A | Optional | ✅ Recommended |
| **Microsoft Defender for Servers** | Optional | Optional | Optional | N/A | Optional | ✅ Recommended |
| **VMSS autoscale** | ✅ | ✅ | ✅ | N/A | ✅ | ✅ |
| **AMA → Sentinel HTTPS** | ✅ | ✅ | ✅ | N/A | ✅ | ✅ (private via AMPLS) |

### 3.2 Key Vault security

**Access model:** The VMSS User-Assigned Managed Identity is granted only
`Key Vault Secrets User` (read secrets, not write or manage). This is the minimum
required permission for cert fetch.

**No stored credentials:** VMSS VMs never have credentials written to disk. The UAMI
token is acquired from IMDS at boot time, used transiently to call the Key Vault REST
API, and discarded. No secrets appear in environment variables, cloud-init output logs,
or instance user data.

**Private endpoint (optional):** For Patterns A and B, a Key Vault private endpoint on
the collector VNet ensures KV API traffic does not traverse the public internet. For
Pattern E (public LB), KV API calls from the VMSS still route over the Azure backbone
(not through the public LB frontend) — private endpoint is still valid and recommended.

**Secret names (generic, use as-is):**

| Secret | Pattern |
|---|---|
| `syslog-ca-cert` | A, B, C, E |
| `syslog-server-cert` | A, B, C, E |
| `syslog-server-key` | A, B, C, E |
| `syslog-client-ca-cert` | E only (mTLS) |

### 3.3 Host hardening

- **No SSH from internet.** The NSG has no inbound rule for port 22 from `*`. Use
  Azure Bastion (requires no public IP on instances) or Azure Serial Console for
  emergency access.
- **Unattended upgrades.** Ubuntu's `unattended-upgrades` package should be enabled
  via cloud-init for automatic kernel and package security patches.
- **No inbound management ports.** No RDP, no SSH, no WinRM exposed to the internet.
- **Minimal UAMI permissions.** The VMSS UAMI has no roles beyond those required for
  cert fetch and AMA telemetry upload to Azure Monitor.
- **VMSS Uniform mode.** Instances are ephemeral; compromise of a single instance
  does not persist across a reimage.

### 3.4 DoS and rate considerations for `imtcp`

`imtcp` maintains TCP connection state per sender. Under a high-load scenario or attack:

**Connection limits:** rsyslog does not have a built-in per-IP connection rate limiter
for `imtcp`. For production public deployments (Patterns C and E), consider Azure
Firewall with IDPS and connection-rate throttling upstream of the LB.

**LB idle timeout:** The Azure Standard LB TCP idle timeout defaults to 4 minutes.
For long-lived syslog connections, increase `idleTimeoutInMinutes` to 30 on the LB
rule to prevent the LB from closing active sender sessions mid-stream.

**VMSS autoscale:** CPU-based autoscale (scale-out at 75%, scale-in at 25%, 5-minute
cooldown) handles legitimate volume spikes. For DoS resilience, consider adding a
custom connection-count metric for scale-out decisions.

**mTLS TLS handshake cost:** mTLS roughly doubles the TLS handshake CPU cost (both
parties present and verify a certificate chain). Under a connection-flood DoS, an
attacker can exhaust collector CPU with TLS handshakes even without valid client certs.
NSG scoping (defense-in-depth in Pattern E) reduces this surface significantly.

### 3.5 Monitoring the collector

A silently failing collector means log coverage gaps. Operators must monitor the
collector's own health as a first-class concern.

| What to monitor | How | Alert condition |
|---|---|---|
| **rsyslog process** | Azure Monitor VM Insights or custom metric | rsyslog not running on any VMSS instance |
| **Failed TLS handshakes** | rsyslog action statistics (STATSCOUNTER) forwarded to Log Analytics | Sustained spike in failed connections → misconfigured sender or cert issue |
| **Client cert validation failures** (Pattern E) | rsyslog journal log output | `x509 verify failed` or `permission denied` in rsyslog journal |
| **KV cert fetch failures** | cloud-init output log; custom monitoring script | Non-zero exit from `fetch-kv-certs.sh` → rsyslog starts without valid certs |
| **Server cert expiry** | Azure Monitor KV diagnostic log or custom script | Server cert expires within 30 days |
| **Client CA cert expiry** (Pattern E) | Same | Client CA expires within 60 days |
| **Log Analytics ingestion** | LAW built-in monitoring | Syslog table row count drops to zero for > 15 minutes during expected activity |
| **VMSS LB health probe** | LB metrics | All backend instances reporting unhealthy → zero collection capacity |

---

## 4. Certificate Lifecycle for mTLS

This section extends `docs/tls-setup.md` for mTLS-specific certificate operations.
Cross-reference that document for server cert generation, Key Vault upload procedures,
and server cert rotation.

### 4.1 Client CA architecture

```
client-ca-key.pem    ← Keep OFFLINE or in HSM. Never on a network-connected system.
client-ca.pem        ← Public cert. Store in Key Vault as syslog-client-ca-cert.
                        Delivered to VMSS via cloud-init fetch-kv-certs.sh.
                        Written to /etc/rsyslog.d/certs/client-ca.pem (mode 0644).
```

**Client CA generation:**

```bash
# Run on an offline workstation or in a secure CA environment

openssl genrsa -out client-ca-key.pem 4096

openssl req -new -x509 -key client-ca-key.pem \
  -days 3650 \
  -subj "/CN=Syslog Client CA/O=Example Corp/C=US" \
  -extensions v3_ca \
  -out client-ca.pem

# Upload the CA cert to Key Vault
az keyvault secret set \
  --vault-name "<keyvault-name>" \
  --name "syslog-client-ca-cert" \
  --file client-ca.pem

# Destroy the local CA key copy; retain the offline backup securely
shred -u client-ca-key.pem
```

### 4.2 Per-sender client certificate issuance

Issue **one client certificate per authorized sender device**. The certificate's CN
(and SAN) must match the `PermittedPeers` pattern on the collector.

**Required certificate fields:**

| Field | Value |
|---|---|
| Subject CN | `<sender-hostname>.senders.example.com` (must match PermittedPeers) |
| Subject Alternative Name (DNS) | Same as CN |
| KeyUsage | `digitalSignature` |
| ExtendedKeyUsage | `clientAuth` ← **required by rsyslog/gtls** |
| Validity | 90–365 days (shorter = lower revocation window) |
| Key size | 4096-bit RSA or P-384 EC |

**Distribution:** Deliver the client cert and key to the sender over a **secure
out-of-band channel** (not email, not unencrypted HTTP). Options:

- Azure Key Vault (if the sender is an Azure VM with a UAMI and access to a KV)
- Ansible Vault or Terraform encrypted remote state
- Manual secure copy (SCP/SFTP) over an existing authenticated management channel
- HashiCorp Vault PKI secrets engine (for automated issuance at scale)

### 4.3 Certificate rotation

#### Server certificate rotation

See `docs/tls-setup.md §3` for the complete procedure. The short version:

1. Generate new server cert signed by the same server CA.
2. Upload as new `syslog-server-cert` / `syslog-server-key` KV secret versions.
3. VMSS rolling reimage picks up new certs on next instance boot.

#### Client certificate rotation (individual sender)

1. Generate a new client cert for the sender (new key + new cert, same CN/SAN).
2. Distribute new cert + key to the sender over a secure channel.
3. Update the sender rsyslog config to reference the new cert (or overwrite in place).
4. Restart rsyslog on the sender.
5. The old cert continues to work until it expires — no collector-side action needed
   unless revoking early (see §4.4).

#### Client CA rotation (highest impact — plan carefully)

1. Generate a new client CA offline.
2. Upload new `syslog-client-ca-cert` to Key Vault.
3. Issue **all** sender client certs from the new CA before updating the collector.
4. Create a combined CA bundle containing both old and new client CAs.
5. Upload the bundle as `syslog-client-ca-cert` to allow both old and new certs during
   the transition window.
6. VMSS rolling reimage: new instances trust both CAs.
7. Once all senders have new client certs, remove the old CA from the bundle.
8. Upload single-CA bundle (new CA only) and reimage VMSS again.

### 4.4 Revocation

> ⚠️ **rsyslog/gtls limitation:** The GnuTLS stream driver does **not** support CRL
> (Certificate Revocation List) or OCSP (Online Certificate Status Protocol) checking.
> There is no `CRLFile` directive and no OCSP stapling support in rsyslog's `imtcp`
> gtls driver (rsyslog 8.x as of this writing). This is a known limitation of the
> gtls driver.

#### Pragmatic revocation approaches

| Approach | Mechanism | When to use | Trade-off |
|---|---|---|---|
| **Remove from PermittedPeers** | Remove the compromised sender's CN/SAN from rsyslog `PermittedPeers`; redeploy VMSS | Single sender compromised | Effective immediately after VMSS rolling reimage; requires Bicep param update |
| **NSG emergency deny** | Add NSG Deny rule scoped to the compromised sender's egress IP | Sender has unique static egress IP | Only works with static IPs; not available for shared NAT |
| **CA rotation** | Rotate client CA; re-issue all other senders; compromised cert's CA is untrusted | CA compromise (rare) | Nuclear option; very high operational cost |
| **Short cert lifetimes** | Issue client certs with 30–90 day validity | Always (default practice) | Limits window of a compromised cert; requires automated renewal to be sustainable |

**Recommended stance:** Issue client certs with **90-day validity**. Automate issuance
and renewal. Use `PermittedPeers` removal as the primary revocation mechanism for
individual cert compromise. Reserve CA rotation for CA compromise. Consider
HashiCorp Vault PKI or a similar automated PKI system to make short-lifetime certs
operationally feasible at scale.

---

### 4.5 Certificate Rotation & Renewal Automation {#cert-rotation-automation}

> **Decision tracked in a tracked enhancement.**

`docs/tls-setup.md §3` covers the manual rotation baseline (generate → upload KV
secret version → reimage or Run Command). This section documents three concrete
automation approaches. **None are yet implemented**; they are documented here for
deliberate future implementation. Cross-references: §4.3 (rotation procedure),
§4.4 (revocation), §3.5 (monitoring including cert expiry alerts).

#### Why automation is required

A 90-day server cert with no automated renewal and no expiry alert will silently expire
and take the TLS listener offline simultaneously for all senders. Short-lived client
certs (the recommended stance from §4.4) multiply the problem by the number of
authorized senders. Manual rotation is not sustainable at scale.

> **rsyslog/gtls behavior:** rsyslog loads TLS certificate files at **startup** (or
> on `SIGHUP` / `systemctl reload rsyslog`). Replacing the on-disk PEM files alone
> does **not** cause rsyslog to use the new certs — a **reload or restart is required**.
> A `systemctl restart rsyslog` causes the TLS listener to briefly drop connections
> (< 1 second on a clean restart); TCP senders reconnect automatically. Stagger
> restarts across VMSS instances to prevent a simultaneous coverage gap.

---

#### Approach 1 — Instance roll (immutable-infra) {#rotation-approach-1}

**Model:** Update the KV secret versions → trigger a VMSS rolling upgrade. New instances
boot fresh; `fetch-kv-certs.sh` pulls the latest secret version at cloud-init time.

```
1. Generate new server cert (or let CI / ACME re-issue it — see Approach 3b).
2. az keyvault secret set --vault-name <keyvault-name> \
       --name syslog-server-cert --file new-server.pem
   az keyvault secret set --vault-name <keyvault-name> \
       --name syslog-server-key  --file new-server-key.pem
3. az vmss rolling-upgrade start \
       --resource-group <rg-name> --name <vmss-name>
   # Monitor: az vmss rolling-upgrade get-latest --resource-group ... --name ...
4. New instances fetch the new cert at boot-time cloud-init.
   Old instances continue serving connections until replaced in the rolling window.
```

**Automatable via scheduled GitHub Actions** (`schedule: cron`): re-issue cert, upload
to KV, start rolling upgrade, wait for completion.

**Trade-offs:**
- ✅ Simple — cert delivery reuses the same boot-time mechanism as the initial deploy.
- ✅ No new on-box tooling; instances are replaced, not mutated.
- ⚠️ Each cert rotation triggers a full instance roll — heavier than needed for
  cert-only rotation.
- ⚠️ Brief per-instance unavailability during the rolling window (autoscale keeps
  capacity; the LB health probe routes around draining instances).
- **Best used as break-glass fallback**, or when the instance roll is already happening
  for other reasons (OS patch cycle, config change).

---

#### Approach 2 — On-box systemd timer re-fetch {#rotation-approach-2}

> **TODO — not yet added to `bicep/scripts/cloud-init.yaml`.** The artifacts below
> are the concrete additions cloud-init would need. Mark this section as the
> implementation specification.

**Model:** A `systemd` timer fires every 8 hours on each VMSS instance. A wrapper
script (`renew-certs.sh`) re-fetches each KV secret to a temp file, checksums it
against the on-disk cert, and only on a difference: atomically swaps the file and
calls `systemctl reload-or-restart rsyslog`. The `RandomizedDelaySec` field on the
timer staggers the instances so they do not restart rsyslog simultaneously.

> **Prefer `systemd` timers over `cron` on modern Ubuntu (22.04+).** Systemd timers
> have proper dependency ordering, journal integration, and transient-unit sandboxing.
> A cron equivalent is: `*/30 * * * * root /usr/local/bin/renew-certs.sh >> /var/log/renew-certs.log 2>&1`
> in `/etc/cron.d/renew-certs` — functionally equivalent if systemd is unavailable.

**Additions to `write_files:` in `cloud-init.yaml`:**

```yaml
  # ── cert renewal wrapper ──────────────────────────────────────────────────
  - path: /usr/local/bin/renew-certs.sh
    owner: root:root
    permissions: '0700'
    content: |
      #!/usr/bin/env bash
      # renew-certs.sh — Re-fetch TLS cert material from Key Vault.
      # Called by renew-certs.timer every 8h (with RandomizedDelaySec stagger).
      # Only restarts rsyslog when at least one cert file has changed.
      #
      # TODO: KV_NAME and UAMI_CLIENT_ID must be templated in by Bicep at compile
      # time — same pattern as fetch-kv-certs.sh (loadTextContent + replace + base64
      # in bicep/modules/vmss.bicep). Replace __KV_NAME__ and __UAMI_CLIENT_ID__
      # placeholders before this file reaches the VM.
      set -euo pipefail

      KV_NAME="__KV_NAME__"
      UAMI_CLIENT_ID="__UAMI_CLIENT_ID__"
      CERT_DIR="/etc/rsyslog.d/certs"
      CHANGED=0

      TOKEN=$(curl -sf \
        -H "Metadata: true" \
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net&client_id=${UAMI_CLIENT_ID}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

      KV_URI="https://${KV_NAME}.vault.azure.net/secrets"

      fetch_and_compare() {
        local secret_name="$1" dest_path="$2" mode="$3"
        local tmp_path="${dest_path}.new"
        curl -sf \
          -H "Authorization: Bearer ${TOKEN}" \
          "${KV_URI}/${secret_name}?api-version=7.4" \
          | python3 -c "import sys,json; sys.stdout.write(json.load(sys.stdin)['value'])" \
          > "${tmp_path}"
        chmod "${mode}" "${tmp_path}"
        if ! cmp -s "${dest_path}" "${tmp_path}" 2>/dev/null; then
          mv "${tmp_path}" "${dest_path}"
          chown root:root "${dest_path}"
          chmod "${mode}" "${dest_path}"
          echo "UPDATED: ${dest_path}"
          CHANGED=1
        else
          rm -f "${tmp_path}"
        fi
      }

      fetch_and_compare "syslog-ca-cert"     "${CERT_DIR}/ca.pem"         644
      fetch_and_compare "syslog-server-cert" "${CERT_DIR}/server.pem"     644
      fetch_and_compare "syslog-server-key"  "${CERT_DIR}/server-key.pem" 600
      # mTLS (Pattern E/F): uncomment when enableMutualTls = true
      # fetch_and_compare "syslog-client-ca-cert" "${CERT_DIR}/client-ca.pem" 644

      if [ "${CHANGED}" -eq 1 ]; then
        echo "Cert material changed — reloading rsyslog"
        systemctl reload-or-restart rsyslog
      else
        echo "No cert changes detected."
      fi

  # ── systemd service unit ─────────────────────────────────────────────────
  - path: /etc/systemd/system/renew-certs.service
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=Re-fetch TLS cert material from Key Vault
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=oneshot
      ExecStart=/usr/local/bin/renew-certs.sh
      StandardOutput=journal
      StandardError=journal
      SyslogIdentifier=renew-certs

  # ── systemd timer unit ───────────────────────────────────────────────────
  - path: /etc/systemd/system/renew-certs.timer
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=Periodically re-fetch TLS certs from Key Vault
      Requires=renew-certs.service

      [Timer]
      # Every 8h; RandomizedDelaySec staggers the 3 VMSS instances up to ±30 min
      # so they do not call systemctl reload-or-restart rsyslog simultaneously.
      OnBootSec=15min
      OnUnitActiveSec=8h
      RandomizedDelaySec=1800
      Persistent=true

      [Install]
      WantedBy=timers.target
```

**Additions to `runcmd:` in `cloud-init.yaml`:**

```yaml
runcmd:
  # (after existing runcmd steps — enable cert renewal timer)
  - systemctl daemon-reload
  - systemctl enable renew-certs.timer
  - systemctl start renew-certs.timer
```

**Stagger rationale:** With 3 VMSS instances and `RandomizedDelaySec=1800` (30 min),
the base 8h interval plus each instance's independent random offset means rsyslog
reloads never overlap. Each reload takes < 1 second; TCP senders reconnect
automatically. With staggering, no single moment has all instances reloading
simultaneously.

**rsyslog reload vs. restart:** `reload-or-restart` attempts `SIGHUP` (reload) first.
In practice, the gtls driver's handling of `SIGHUP` for cert re-read is inconsistent
across rsyslog versions — a full `restart` is more reliable for cert rotation. If your
rsyslog version is confirmed to reload certs cleanly via `SIGHUP` (test in staging),
substitute `systemctl reload rsyslog` for a shorter listener gap.

---

#### Approach 3 — KV-side renewal bridged to PEM secrets {#rotation-approach-3}

**Context:** Cert material is stored as Key Vault **Secrets** (PEM text), not KV
**Certificate** objects (PKCS#12). This was a deliberate choice (deviation-log item 18):
rsyslog requires PEM files; KV Certificates deliver PKCS#12 which requires conversion.
The trade-off: KV Certificate objects have native auto-renewal policies; KV Secrets do
not. Approach 3 bridges that gap.

**Option 3a — KV Certificate auto-renew + Event Grid bridge (not implemented):**

```
1. Store the server cert as a KV Certificate object with a lifetime action:
      AutoRenew at N days before expiry (or X% of validity).
      KV re-issues via the configured issuer (self-signed or CA-integrated).

2. Event Grid subscription on the vault listens for:
      Microsoft.KeyVault.CertificateNearExpiry       → alerting / manual review
      Microsoft.KeyVault.CertificateNewVersionCreated → renewal trigger

3. The event triggers an Azure Function or Automation Runbook that:
      a. Downloads the KV Certificate as base64 PKCS#12.
      b. Extracts PEM cert and key:
           openssl pkcs12 -in cert.p12 -nokeys -out server.pem -passin pass:
           openssl pkcs12 -in cert.p12 -nocerts -nodes -out server-key.pem -passin pass:
      c. Uploads server.pem as new version of KV Secret 'syslog-server-cert'.
      d. Uploads server-key.pem as new version of KV Secret 'syslog-server-key'.

4. The systemd timer (Approach 2) detects the new KV Secret versions on its next
   scheduled run (within 8h) and reloads rsyslog.
   OR: trigger a VMSS rolling upgrade (Approach 1) for immediate delivery.
```

> Note: KV Certificate auto-renew supports self-signed renewal and CA-integrated
> renewal (DigiCert, GlobalSign connectors). For a private CA (the self-signed CA from
> `docs/tls-setup.md §2`), use the "Self" issuer for self-signed renewal.

**Option 3b — Scheduled CI re-issue via GitHub Actions (simpler; recommended):**

```yaml
# .github/workflows/rotate-server-cert.yml  (documented — NOT YET IMPLEMENTED)
name: Rotate syslog server cert
on:
  schedule:
    - cron: '0 3 * * 1'   # Every Monday 03:00 UTC — tune to fire ≥30 days before expiry
  workflow_dispatch:        # Allow manual emergency trigger

permissions:
  id-token: write

jobs:
  rotate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Generate new server cert
        run: |
          # The CA private key is stored as an encrypted GitHub Actions secret
          # (base64-encoded PEM). NEVER commit it to source control.
          # Alternative: call an ACME client (certbot, acme.sh) for a public DNS name.
          echo "${{ secrets.SYSLOG_CA_KEY_B64 }}" | base64 -d > ca-key.pem
          az keyvault secret download \
            --vault-name <keyvault-name> --name syslog-ca-cert --file ca.pem

          openssl genrsa -out server-key.pem 4096
          openssl req -new -key server-key.pem \
            -subj "/CN=collector.example.com/O=Example Corp/C=US" \
            -out server.csr
          openssl x509 -req -in server.csr \
            -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
            -days 365 \
            -extfile <(printf "subjectAltName=DNS:collector.example.com\nextendedKeyUsage=serverAuth\n") \
            -out server.pem

      - name: Upload new cert versions to Key Vault
        run: |
          az keyvault secret set --vault-name <keyvault-name> \
            --name syslog-server-cert --file server.pem
          az keyvault secret set --vault-name <keyvault-name> \
            --name syslog-server-key  --file server-key.pem
          shred -u ca-key.pem server-key.pem server.csr

      # Optional: trigger VMSS rolling upgrade for immediate delivery (skip if
      # the systemd timer (Approach 2) is in place — it delivers within 8h)
      # - name: Trigger VMSS rolling upgrade
      #   run: |
      #     az vmss rolling-upgrade start \
      #       --resource-group <rg-name> --name <vmss-name>
```

Option 3b reuses the existing OIDC deploy identity and Key Vault permissions — no new
Azure resources required. The systemd timer (Approach 2) delivers the new secret
versions to running instances within the next timer interval (≤8h).

> ⚠️ **CA key security in Option 3b:** The CA private key must be accessible to the
> runner. Store it as an encrypted GitHub Actions repository secret (base64-encoded
> PEM). A more durable alternative at scale: use a KV-managed CA (Approach 3a) or
> HashiCorp Vault PKI secrets engine. Never commit the CA key to source control.

---

#### Expiry monitoring (always required) {#cert-expiry-monitoring}

Automation is not infallible. An independent expiry alert ensures a silently failed
rotation is caught before the cert expires and takes the collector offline.

**Recommended alert thresholds:**

| Cert | Warning | Critical |
|---|---|---|
| `syslog-server-cert` | 30 days | 14 days |
| `syslog-client-ca-cert` (mTLS) | 60 days | 30 days |
| Per-sender client certs (mTLS) | 30 days | 14 days |

The client CA threshold is larger because CA rotation requires all senders to re-issue
before the old CA is removed (see §4.3) — significant lead time is needed.

```bash
# Azure Monitor metric alert on Key Vault — cert secret near expiry
# Requires KV diagnostic settings → Log Analytics workspace enabled
az monitor metrics alert create \
  --name "syslog-server-cert-expiry" \
  --resource-group <rg-name> \
  --scopes "/subscriptions/<subscription-id>/resourceGroups/<rg-name>/providers/Microsoft.KeyVault/vaults/<keyvault-name>" \
  --condition "avg DaysToExpiry < 30" \
  --description "Syslog server cert expires within 30 days — check rotation automation" \
  --severity 2 \
  --action-group "<action-group-id>"
```

> **Sentinel integration:** Route KV near-expiry alerts to Microsoft Sentinel as
> incidents. A collector with an expired TLS cert silently loses all log ingestion —
> this is a high-severity event in a security logging pipeline.

---

#### mTLS rotation note {#rotation-mtls-note}

Approaches 1–3 address the **server cert** and (where applicable) the **client CA
cert**. Per-sender client cert rotation is a sender-side operation (§4.3). Key points:

- **Server cert rotation** (Approaches 1–3): transparent to senders after rsyslog
  reload; senders reconnect and renegotiate with the new server cert.
- **Per-sender client cert rotation** (§4.3): sender-side action; new cert from same
  client CA; no collector-side action needed unless the sender's PermittedPeers
  CN/SAN changes.
- **Client CA rotation** (§4.3 — hardest): requires dual-trust overlap window;
  plan as a deliberate coordinated operation, not an automated scheduled task.

---

#### Recommendation {#rotation-recommendation}

| Approach | Role | Status |
|---|---|---|
| **Approach 2 — systemd timer re-fetch** | Primary cert delivery on running instances | ⚠️ TODO — add to cloud-init |
| **Approach 3b — scheduled CI re-issue** | Primary cert re-issuance | ⚠️ TODO — add `.github/workflows/rotate-server-cert.yml` |
| **Approach 1 — instance roll** | Break-glass / fallback | Available today (manual) |
| **Expiry monitoring** | Always-on safety net | ⚠️ TODO — configure KV metric alert |
| **Approach 3a — KV Cert + Event Grid bridge** | Advanced (KV-managed CA desired) | Not implemented; additional Azure resources required |

**Recommended baseline:** Deploy the **systemd timer** (Approach 2) via cloud-init so
every running instance checks for new cert versions every 8h. Add a **scheduled CI
workflow** (Approach 3b) that re-issues the server cert weekly or on a schedule that
ensures renewal before the 30-day warning threshold. Set an **Azure Monitor expiry
alert** as an independent safety net. Use **Approach 1** as break-glass if both fail.

---

## 5. Comparison Table

| | **A — Private** | **B — Hybrid** | **C — Public/IP-locked** | **D — Public/open** ⛔ | **E — Public + mTLS** | **F — ALZ+Firewall** |
|---|---|---|---|---|---|---|
| **LB type** | Internal | Internal | Public + PIP | Public + PIP | Public + PIP | Internal (Firewall has PIP) |
| **Public internet exposure** | None | None | Yes (IP-locked NSG) | Yes (open NSG) | Yes (cert-locked) | Via Firewall DNAT only |
| **TLS mode** | `anon` (enc only) | `anon` (enc only) | `anon` (enc only) | `anon` (enc only) | `x509/name` (mTLS) | `x509/name` (mTLS recommended) |
| **Sender authentication** | None (network) | None (network) | None (IP-based) | ❌ None | ✅ Cryptographic | ✅ Cryptographic + Firewall TI |
| **Log injection risk** | Low (VNet boundary) | Low (VPN/ER boundary) | Medium (allowlist) | **Critical** | Low (valid cert required) | Low (Firewall + mTLS) |
| **Eavesdropping risk** | Low (VNet + TLS) | Low (VPN + TLS) | Low (TLS) | Low (TLS — only protection) | Low (mTLS) | Low (mTLS, end-to-end) |
| **Residual spoofing risk** | Any host in VNet CIDR | Any host in on-prem CIDR | Any host in egress allowlist | **Any host on the internet** | Requires cert + key theft | Requires cert + key theft |
| **WAF applicable?** | N/A | N/A | N/A | N/A | N/A | ❌ No — L4 TCP, not HTTP |
| **Sender device requirement** | TLS capable | TLS capable | TLS capable | TLS capable | TLS capable + client cert | TLS capable + client cert |
| **Azure Firewall required** | No | No | No | No | No | ✅ Yes (hub, Premium SKU) |
| **Relative cost / complexity** | Low | Low | Medium | N/A | High | Very High |
| **KV secrets required** | 3 | 3 | 3 | N/A | 4 (+ client CA) | 4 (+ private endpoint) |
| **Implemented today** | ✅ Default | ✅ Param change | ✅ Param change | ❌ Blocked | ⚠️ Designed, not built | ⚠️ Documented, not built |
| **Recommended for** | Azure-native senders | Hybrid / on-prem | Known-IP public senders | — | Unknown-IP public; compliance auth | Mandatory public internet + existing ALZ hub |

---

## 6. Recommendation

**Default to the most private pattern that satisfies your requirements.** Avoid public
IP exposure unless you have a concrete requirement for it, and avoid opening NSG rules
beyond what individual senders need.

### Decision guide

| Your situation | Recommended pattern |
|---|---|
| All senders are in the same Azure VNet or a peered VNet | **Pattern A** (default) |
| Some senders are on-premises, reached via VPN or ExpressRoute | **Pattern B** |
| Senders are on the internet with stable, known, exclusive egress IPs | **Pattern C** |
| Senders are on the internet with unknown/shared egress IPs, OR compliance requires cryptographic sender auth | **Pattern E** |
| Public internet ingestion is mandatory AND an ALZ hub with Azure Firewall Premium exists | **Pattern F** (combined with Pattern E mTLS) |
| You are considering `allowedSyslogSourceCidrs = ['0.0.0.0/0']` | **Do not. Use Pattern E or F instead.** |

### Current implementation status

| Pattern | Available today | How to enable |
|---|---|---|
| **A** | ✅ Default | No changes; `loadBalancerPublic = false`, `enableTls = true` |
| **B** | ✅ Param change | Set `allowedSyslogSourceCidrs` to on-prem CIDRs |
| **C** | ✅ Param change | Set `loadBalancerPublic = true`; scope `allowedSyslogSourceCidrs` |
| **D** | ❌ Do not use | — |
| **E** | ⚠️ Designed, not built | See §2.5.6 for the complete TODO list |
| **F** | ⚠️ Documented, not built | Requires existing ALZ hub + Firewall; see §2.6 and platform team coordination |

### What implementing Pattern E requires

To implement Pattern E, the following work is needed (none of it is blocking today,
and all groundwork is already laid in comments and stubs):

1. **Bicep params:** Add `enableMutualTls` (`bool`, default `false`) and
   `permittedPeers` (`array`) to `main.bicep` / `main.bicepparam`.
2. **Conditional rsyslog config:** Generate `AuthMode="x509/name"` + `PermittedPeers`
   lines in `rsyslog-tls.conf` when `enableMutualTls = true` (Bicep string interpolation
   in the cloud-init template).
3. **Cert fetch extension:** Add `syslog-client-ca-cert` fetch to `fetch-kv-certs.sh`
   → `/etc/rsyslog.d/certs/client-ca.pem` (mode 0644).
4. **`DefaultNetstreamDriverCAFile` path:** Point to `client-ca.pem` (not `ca.pem`)
   when mTLS is enabled, or generate a combined bundle.
5. **Client CA:** Generate the client CA (offline), store cert in Key Vault as
   `syslog-client-ca-cert`.
6. **Per-sender client certs:** Issue one client cert per authorized sender, distribute
   securely, configure sender rsyslog with the cert + key.
7. **`permittedPeers` values:** Populate with the CN/SANs of all authorized senders.

The implementation is non-trivial primarily because of step 6 — the operational process
of issuing and distributing per-sender client certificates. The Bicep and rsyslog
changes themselves are straightforward. This documentation provides the complete
specification; implementation proceeds when the team is ready to own the cert lifecycle.

---

*Cross-references: [docs/tls-setup.md](tls-setup.md) — server cert generation, Key Vault upload, manual server cert rotation; §3 cross-links to §4.5 rotation automation. [docs/architecture.md](architecture.md) — overall system topology and end-to-end log flow. Issue #2 — cert rotation automation. Issue #3 — Pattern F (ALZ/Firewall) topology.*

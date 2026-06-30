# Architecture: Syslog-VMSS-AMA Collector

> **Date:** 2026-06-29  
> **Author:** Ripley (Lead / Cloud Architect)  
> **Status:** Draft — pending open-question resolution

---

## 1. What the Upstream Template Deploys

The upstream repository ([Azure/Azure-Sentinel — DataConnectors/Syslog-VMSS-AMA](https://github.com/Azure/Azure-Sentinel/tree/master/DataConnectors/Syslog-VMSS-AMA)) is a **single ARM template** (`azureDeploy.json`) plus a **README**. No parameter files, no Bicep, no helper scripts inside the folder itself.

### Resources provisioned by `azureDeploy.json`

| # | Resource Type | Name Pattern | Purpose |
|---|---|---|---|
| 1 | `Microsoft.Network/networkSecurityGroups` | `{Base_Name}-nsg` | Allow inbound Syslog (514/UDP+TCP) and SSH (22) |
| 2 | NSG child rules (×2) | `Allow-Syslog`, `Allow-SSH` | Explicit child-resource duplicates of the inline rules |
| 3 | `Microsoft.Network/virtualNetworks` | `{Base_Name}-vnet` | 10.0.0.0/16 VNet with a single /24 `default` subnet |
| 4 | Subnet child resource | `{Base_Name}-vnet/default` | Explicit child subnet (has a typo: `Microsoft.Networks` — see deviations) |
| 5 | `Microsoft.Network/publicIPAddresses` | `{Base_Name}-pip` | Standard SKU, static IPv4, with DNS label |
| 6 | `Microsoft.Network/loadBalancers` | `{Base_Name}-lb` | Standard SKU LB: TCP 514, UDP 514 rules; health probe on TCP 514; NAT pool for SSH (50000+) |
| 7 | `Microsoft.Compute/virtualMachineScaleSets` | `{Base_Name}-vmss` | Ubuntu 18.04-LTS, Standard_F4s_v2, cloud-init for rsyslog, AMA extension (v1.22) |
| 8 | `Microsoft.Insights/autoscalesettings` | `{Base_Name}-autoscale` | CPU-based autoscale (scale-out >75%, scale-in <25%) |
| 9 | `Microsoft.Insights/dataCollectionRules` | `default` | DCR kind=Linux, streams `Microsoft-Syslog`, configurable facilities/levels |
| 10 | `Microsoft.Insights/dataCollectionRuleAssociations` | `DCRa` | Binds the DCR to the VMSS |
| 11 | `Microsoft.ManagedIdentity/userAssignedIdentities` | `managedIdentity` | UAMI for AMA to authenticate to Azure Monitor |

### External dependency (cloud-init)

The template's `cloudinit` parameter defaults to downloading and running:

```
https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/Syslog/Forwarder_AMA_installer.py
```

This Python script (`Forwarder_AMA_installer.py`):
- Detects whether `rsyslog` or `syslog-ng` is running on the VM.
- Uncomments or appends `imudp` / `imtcp` module config so rsyslog listens on **port 514 (TCP + UDP)**.
- Restarts the syslog daemon.
- Does **NOT** configure TLS, RELP, or any encrypted transport.

---

## 2. End-to-End Log Flow

```
┌──────────────┐       514/UDP or TCP       ┌───────────────────────┐
│ Syslog Source │ ─────────────────────────► │  Azure Load Balancer  │
│ (appliance,  │       (plain syslog)       │  Standard SKU, PIP    │
│  server, etc)│                            └──────────┬────────────┘
└──────────────┘                                       │
                                                       ▼
                                            ┌──────────────────────┐
                                            │  VMSS Instance(s)    │
                                            │  Ubuntu 18.04-LTS    │
                                            │                      │
                                            │  rsyslog listens on  │
                                            │  514/TCP + 514/UDP   │
                                            │         │            │
                                            │         ▼            │
                                            │  AMA Extension       │
                                            │  (AzureMonitorLinux-  │
                                            │   Agent v1.22+)      │
                                            │  reads from syslog   │
                                            │  socket / journal    │
                                            └──────────┬───────────┘
                                                       │ HTTPS (443)
                                                       │ to Azure Monitor
                                                       │ ingestion endpoint
                                                       ▼
                                            ┌──────────────────────┐
                                            │ Data Collection Rule │
                                            │ (Microsoft-Syslog    │
                                            │  stream)             │
                                            └──────────┬───────────┘
                                                       │
                                                       ▼
                                            ┌──────────────────────┐
                                            │ Log Analytics        │
                                            │ Workspace            │
                                            │ → Syslog table       │
                                            │ → Microsoft Sentinel │
                                            └──────────────────────┘
```

**Key points:**
- AMA reads syslog events from the local rsyslog Unix socket (not over the network).
- AMA sends data to Azure Monitor ingestion endpoints over **HTTPS (TLS 1.2+)** — this leg is always encrypted.
- The **gap** is the first leg: syslog source → load balancer → VMSS rsyslog. This is **plain text** (port 514, no TLS).

---

## 3. TLS Assessment & Recommendation

> **Deployment patterns and security guide:** For the complete treatment of deployment
> topologies (private, hybrid, public IP-allowlisted, and mutual TLS), threat models,
> defense-in-depth controls, and the mTLS certificate lifecycle, see
> **[docs/deployment-patterns.md](deployment-patterns.md)**. The sections below
> describe the original gap analysis and architectural decision.

### What the upstream does
**Nothing.** The upstream template and the `Forwarder_AMA_installer.py` script configure plain-text syslog only (514/TCP and 514/UDP). There is zero TLS configuration.

### What we need to add

**Recommended approach: rsyslog `imtcp` with TLS (via GnuTLS driver)**

rsyslog natively supports TLS for TCP syslog using the `gtls` (GnuTLS) or `ossl` (OpenSSL) stream drivers. This is the most battle-tested approach for syslog-over-TLS.

#### Implementation plan

| Layer | Change | Details |
|---|---|---|
| **NSG** | Add port 6514 inbound rule | RFC 5425 standard port for syslog-TLS |
| **Load Balancer** | Add TCP 6514 LB rule + health probe | Forward TLS syslog to backend pool |
| **cloud-init / rsyslog config** | Replace `Forwarder_AMA_installer.py` with our own config | Configure `imtcp` with `StreamDriver.Name="gtls"`, `StreamDriver.Mode="1"`, `StreamDriver.AuthMode="x509/name"` or `"anon"` |
| **Certificates** | Provision TLS cert/key to each VMSS instance | Options: (a) Azure Key Vault + VMSS Key Vault extension, (b) self-signed CA deployed via cloud-init, (c) Let's Encrypt via ACME |
| **DCR** | No change | The DCR sees the same `Microsoft-Syslog` stream regardless of transport — AMA reads from the local socket |
| **Syslog sources** | Must be configured to send to port 6514 with TLS | Source device config is out of scope of this deployment |

#### Alternative: RELP with TLS (rsyslog `imrelp` + `omrelp`)
- More reliable (application-level ACKs) but requires RELP support on the sender side.
- Port 2514 (conventional) or any chosen port.
- We can support this as a second phase if needed.

#### Certificate approach recommendation
1. **Azure Key Vault** (preferred): Store the CA cert and server cert/key in Key Vault. Use the VMSS Key Vault VM extension to auto-pull certs. Rotate via Key Vault policy.
2. Fallback: Self-signed CA generated at deploy time, injected via cloud-init `write_files`.

#### What stays the same
- Keep plain-text 514/TCP+UDP as a **fallback** for sources that don't support TLS, behind an NSG rule scoped to specific source IPs.
- AMA → Azure Monitor is always HTTPS; no changes needed.

---

## 4. Proposed Bicep Module Breakdown

We will convert the monolithic ARM template into composable Bicep modules. Proposed structure:

```
bicep/
├── main.bicep                    # Orchestrator — calls all modules
├── main.bicepparam               # Parameter file for your Azure subscription
├── modules/
│   ├── network.bicep             # VNet, Subnet, NSG (with TLS port rules)
│   ├── loadbalancer.bicep        # Public IP, Load Balancer (514 + 6514 rules)
│   ├── identity.bicep            # User-Assigned Managed Identity
│   ├── vmss.bicep                # VMSS definition, AMA extension, cloud-init
│   ├── dcr.bicep                 # Data Collection Rule + DCR Association
│   └── autoscale.bicep           # Autoscale settings
├── scripts/
│   ├── cloud-init.yaml           # Custom cloud-init (rsyslog + TLS config)
│   └── rsyslog-tls.conf          # rsyslog TLS snippet (deployed via cloud-init)
└── docs/                         # (symlink or separate — this folder)
```

**Dallas** should build the modules in this order (dependency chain):
1. `identity.bicep` (no dependencies)
2. `network.bicep` (no dependencies)
3. `loadbalancer.bicep` (depends on: network → PIP)
4. `dcr.bicep` (needs workspace reference — parameter)
5. `vmss.bicep` (depends on: network, LB, identity, DCR; includes AMA extension + cloud-init)
6. `autoscale.bicep` (depends on: VMSS)
7. `main.bicep` (wires everything together)

---

## 5. Open Questions

See the consolidated list in the main README or raise in the squad thread.

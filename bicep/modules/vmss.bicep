// ============================================================
// vmss.bicep — Virtual Machine Scale Set (Uniform)
//
// Deviations from upstream:
//   #1  — Ubuntu 24.04 LTS Noble Gen2 (Canonical ubuntu-24_04-lts
//          / server) replaces EOL Ubuntu 18.04.
//   #2  — API version 2024-07-01 (upstream used 2019-03-01).
//   #9  — VM SKU parameterised; default Standard_D2s_v5.
//   #10 — AMA extension: autoUpgradeMinorVersion=true; version pinned
//          at 1.33 baseline but auto-upgrades minor.
//   #11 — UAMI attached; AMA settings reference UAMI by resource ID.
//   #5  — cloud-init loaded from bicep/scripts/cloud-init.yaml
//          (no runtime download from GitHub).
//
// Cert delivery: cloud-init IMDS fetch (single mechanism).
//   The KeyVaultForLinux VM extension is NOT used — it writes opaque
//   filenames that conflict with the canonical paths rsyslog expects.
//   cloud-init's fetch-kv-certs.sh acquires an AAD token from IMDS and
//   calls Key Vault REST API directly, writing:
//     syslog-ca-cert     → /etc/rsyslog.d/certs/ca.pem   (0644)
//     syslog-server-cert → /etc/rsyslog.d/certs/server.pem (0644)
//     syslog-server-key  → /etc/rsyslog.d/certs/server-key.pem (0600)
//   The Key Vault name and UAMI client ID are templated into cloud-init
//   at Bicep compile time via loadTextContent + replace + base64.
// ============================================================

@description('Base name prefix for all resources.')
param baseName string

@description('Azure region.')
param location string

@description('VM SKU for VMSS instances.')
param vmSku string = 'Standard_D2s_v5'

@description('Initial (minimum) instance count.')
param instanceCountMin int = 1

@description('Resource ID of the subnet to attach VMSS NICs to.')
param subnetId string

@description('Resource ID of the LB backend address pool.')
param lbBackendPoolId string

@description('Resource ID of the User-Assigned Managed Identity (for AMA).')
param uamiId string

@description('Client ID of the User-Assigned Managed Identity — injected into cloud-init for IMDS cert fetch.')
param uamiClientId string

@description('Key Vault name (e.g. kv-sc-syslog-abc12345) — injected into cloud-init for IMDS cert fetch.')
param keyVaultName string

@description('Admin username for the Linux OS profile.')
param adminUsername string = 'azureuser'

@description('SSH public key for the admin user. Not a secret — public key material.')
param adminSshPublicKey string

@description('Resource tags.')
param tags object = {}

// ── VMSS ─────────────────────────────────────────────────────

// computerNamePrefix: must be ≤9 chars, alphanumeric + hyphens.
// 'sc-syslog' is exactly 9 chars, fits as-is.
var computerNamePrefix = take(baseName, 9)

// Template cloud-init: replace __KV_NAME__ and __UAMI_CLIENT_ID__ placeholders
// so fetch-kv-certs.sh knows which vault and identity to use.
var cloudInitTemplated = replace(
  replace(
    loadTextContent('../scripts/cloud-init.yaml'),
    '__KV_NAME__',
    keyVaultName
  ),
  '__UAMI_CLIENT_ID__',
  uamiClientId
)

resource vmss 'Microsoft.Compute/virtualMachineScaleSets@2024-07-01' = {
  name: '${baseName}-vmss'
  location: location
  tags: tags
  sku: {
    name: vmSku
    tier: 'Standard'
    capacity: instanceCountMin
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${uamiId}': {}
    }
  }
  properties: {
    orchestrationMode: 'Uniform'
    upgradePolicy: {
      mode: 'Automatic'
    }
    virtualMachineProfile: {
      // ── Storage / Image ───────────────────────────────────
      storageProfile: {
        imageReference: {
          publisher: 'Canonical'
          offer: 'ubuntu-24_04-lts'   // Ubuntu 24.04 LTS Noble Gen2 (deviation #1)
          sku: 'server'
          version: 'latest'
        }
        osDisk: {
          createOption: 'FromImage'
          caching: 'ReadWrite'
          managedDisk: {
            storageAccountType: 'Premium_LRS'
          }
        }
      }

      // ── OS Profile ────────────────────────────────────────
      osProfile: {
        computerNamePrefix: computerNamePrefix
        adminUsername: adminUsername
        customData: base64(cloudInitTemplated)  // deviation #5; KV_NAME + UAMI_CLIENT_ID templated in
        linuxConfiguration: {
          disablePasswordAuthentication: true
          ssh: {
            publicKeys: [
              {
                path: '/home/${adminUsername}/.ssh/authorized_keys'
                keyData: adminSshPublicKey
              }
            ]
          }
        }
      }

      // ── Network Profile ───────────────────────────────────
      networkProfile: {
        networkInterfaceConfigurations: [
          {
            name: '${baseName}-nic'
            properties: {
              primary: true
              ipConfigurations: [
                {
                  name: 'ipconfig1'
                  properties: {
                    subnet: {
                      id: subnetId
                    }
                    loadBalancerBackendAddressPools: [
                      {
                        id: lbBackendPoolId
                      }
                    ]
                  }
                }
              ]
            }
          }
        ]
      }

      // ── Extension Profile ─────────────────────────────────
      extensionProfile: {
        extensions: [
          // Azure Monitor Agent (deviation #10 — autoUpgrade, UAMI auth)
          {
            name: 'AzureMonitorLinuxAgent'
            properties: {
              publisher: 'Microsoft.Azure.Monitor'
              type: 'AzureMonitorLinuxAgent'
              typeHandlerVersion: '1.33'
              autoUpgradeMinorVersion: true
              enableAutomaticUpgrade: true
              settings: {
                authentication: {
                  managedIdentity: {
                    'identifier-name': 'mi_res_id'
                    'identifier-value': uamiId
                  }
                }
              }
            }
          }
          // KeyVaultForLinux extension intentionally absent.
          // Cert delivery is handled by cloud-init fetch-kv-certs.sh (IMDS MSI fetch).
          // See deviation-log item 21 and bicep/scripts/cloud-init.yaml.
        ]
      }
    }
  }
}

// ── Outputs ──────────────────────────────────────────────────

@description('Resource ID of the VMSS.')
output vmssId string = vmss.id

@description('Name of the VMSS (used by DCR association scope).')
output vmssName string = vmss.name

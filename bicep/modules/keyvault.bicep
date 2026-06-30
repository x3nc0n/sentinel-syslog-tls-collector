// ─────────────────────────────────────────────────────────────────────────────
// keyvault.bicep — Azure Key Vault for syslog TLS certificate material
// Owner: Ash (Security & Identity)
// ─────────────────────────────────────────────────────────────────────────────
//
// PURPOSE
//   Provisions an RBAC-mode Key Vault to store the syslog TLS server cert,
//   server key, and CA cert as Key Vault Secrets (PEM text).
//   Grants the AMA/VMSS User-Assigned Managed Identity 'Key Vault Secrets User'
//   (read secrets only — minimum required permission).
//
// EXPECTED INPUTS (pass from main.bicep)
//   baseName            string  Naming prefix, e.g. 'sc-syslog'
//   location            string  Azure region (must match resource group)
//   amaUamiPrincipalId  string  principalId of the AMA UAMI (from identity.bicep output)
//   tenantId            string  AAD tenant ID (default: subscription().tenantId)
//
// OUTPUTS (consumed by main.bicep → vmss.bicep / cloud-init)
//   keyVaultId          string  Resource ID of the Key Vault
//   keyVaultName        string  Name of the Key Vault (use in KV extension config)
//   keyVaultUri         string  Vault URI, e.g. https://<name>.vault.azure.net/
//
// KEY VAULT SECRET NAMES (populate manually after deploy — see docs/tls-setup.md)
//   syslog-ca-cert      PEM-encoded CA certificate
//   syslog-server-cert  PEM-encoded server certificate
//   syslog-server-key   PEM-encoded server private key
//
// WIRING EXAMPLE IN main.bicep
//   module kv 'modules/keyvault.bicep' = {
//     name: 'keyvault'
//     params: {
//       baseName: baseName
//       location: location
//       amaUamiPrincipalId: identity.outputs.principalId
//     }
//   }
//   // Pass kv.outputs.keyVaultName to vmss.bicep for the KV extension config.
// ─────────────────────────────────────────────────────────────────────────────

@description('Naming prefix for resources, e.g. sc-syslog.')
param baseName string

@description('Azure region where the Key Vault will be created.')
param location string

@description('Object ID (principalId) of the AMA / VMSS User-Assigned Managed Identity.')
param amaUamiPrincipalId string

@description('AAD tenant ID. Defaults to the current subscription tenant.')
param tenantId string = subscription().tenantId

@secure()
@description('PEM-encoded CA certificate. When non-empty, created as KV secret syslog-ca-cert at deploy time (single-shot deploy path). Empty = manual-upload path (backward compatible).')
param syslogCaCertPem string = ''

@secure()
@description('PEM-encoded server certificate. When non-empty, created as KV secret syslog-server-cert at deploy time. Empty = manual-upload path.')
param syslogServerCertPem string = ''

@secure()
@description('PEM-encoded server private key. When non-empty, created as KV secret syslog-server-key at deploy time. Empty = manual-upload path.')
param syslogServerKeyPem string = ''

// Key Vault names must be globally unique, 3–24 chars, alphanumeric + hyphens.
// Use the first 8 chars of uniqueString to stay well under the 24-char limit.
var kvName = take('kv-${baseName}-${uniqueString(baseName, location)}', 24)

// Built-in role: Key Vault Secrets User (4633458b-17de-408a-b874-0445c86b69e6)
// Grants: secrets/get, secrets/list — read only, no key/cert plane access.
var kvSecretsUserRoleDefId = '4633458b-17de-408a-b874-0445c86b69e6'

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: tenantId

    // RBAC authorization mode — no legacy access policies.
    enableRbacAuthorization: true

    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true

    // Public access enabled for initial bootstrap; restrict to VNet in
    // production by setting defaultAction to 'Deny' and adding a
    // virtualNetworkRules entry for the collector subnet.
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
      ipRules: []
      virtualNetworkRules: []
    }
  }
}

// Grant the AMA UAMI read access to secrets (Key Vault Secrets User).
// Scoped to this vault only — least privilege.
resource kvSecretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, amaUamiPrincipalId, kvSecretsUserRoleDefId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      kvSecretsUserRoleDefId
    )
    principalId: amaUamiPrincipalId
    principalType: 'ServicePrincipal'
    description: 'AMA UAMI — read syslog TLS secrets'
  }
}

// ── Optional cert secrets (single-shot deploy path) ──────────
// Created only when the corresponding secureString param is non-empty.
// Empty defaults preserve the manual-upload path (see docs/tls-setup.md).
// Secret names MUST match cloud-init fetch-kv-certs.sh canonical names.

resource caCertSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(syslogCaCertPem)) {
  parent: keyVault
  name: 'syslog-ca-cert'
  properties: {
    value: syslogCaCertPem
    contentType: 'application/x-pem-file'
  }
}

resource serverCertSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(syslogServerCertPem)) {
  parent: keyVault
  name: 'syslog-server-cert'
  properties: {
    value: syslogServerCertPem
    contentType: 'application/x-pem-file'
  }
}

resource serverKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!empty(syslogServerKeyPem)) {
  parent: keyVault
  name: 'syslog-server-key'
  properties: {
    value: syslogServerKeyPem
    contentType: 'application/x-pem-file'
  }
}

output keyVaultId string = keyVault.id
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri

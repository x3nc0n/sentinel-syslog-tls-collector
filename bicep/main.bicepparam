// ============================================================
// main.bicepparam — Default parameters for the Syslog/CEF
// over TLS collector. Override values to suit your environment.
//
// Usage:
//   az deployment group create \
//     --resource-group rg-syslog-collector \
//     --parameters bicep/main.bicepparam \
//     --parameters adminSshPublicKey="<your-public-key>"
// ============================================================

using './main.bicep'

param location = 'eastus2'
param baseName = 'sc-syslog'
param vmSku = 'Standard_D2s_v5'
param instanceCountMin = 1
param instanceCountMax = 3
param enableTls = true
param tlsPort = 6514
param enablePlaintext = false
param plaintextPort = 514
param allowedSyslogSourceCidrs = ['10.0.0.0/16']
param loadBalancerPublic = false
param createWorkspace = true
param workspaceName = 'log-sc-syslog-collector'
param existingWorkspaceId = ''
param enableSentinel = true
param vnetAddressPrefix = '10.0.0.0/16'
param subnetAddressPrefix = '10.0.0.0/24'
param adminUsername = 'azureuser'
// adminSshPublicKey must be supplied at deploy time — not stored in source.
// Example: --parameters adminSshPublicKey="ssh-rsa AAAA..."
// The Key Vault is always auto-deployed via keyvault.bicep; KV name is derived
// from uniqueString(baseName, location). Pass secrets after deployment using
// the keyVaultName output from main.bicep.
param tags = {
  workload: 'syslog-collector'
  env: 'prod'
  managedBy: 'bicep'
  deployedBy: 'squad'
}

// ============================================================
// main.bicep — Orchestrator (resource-group scope)
//
// Target:
//   Subscription : <online-subscription-id> (target landing-zone subscription)
//   Resource Group: <resource-group-name>  (e.g. rg-syslog-collector-<region>)
//
// Module dependency order (per architecture.md §4):
//   1. identity   (no deps)
//   2. network    (no deps)
//   3. workspace  (no deps)
//   4. lb         (depends on network → subnetId)
//   5. vmss       (depends on network, lb, identity, workspace)
//   6. dcr        (depends on workspace, vmss)
//   7. autoscale  (depends on vmss)
// ============================================================

targetScope = 'resourceGroup'

// ── Parameters ───────────────────────────────────────────────

@description('Azure region for all resources.')
param location string = 'eastus2'

@description('Base name prefix shared across all resource names.')
param baseName string = 'sc-syslog'

@description('VMSS VM SKU.')
param vmSku string = 'Standard_D2s_v5'

@description('Minimum VMSS instance count (also used as initial capacity).')
param instanceCountMin int = 1

@description('Maximum VMSS instance count.')
param instanceCountMax int = 3

@description('Enable TLS syslog listener (RFC 5425 port 6514).')
param enableTls bool = true

@description('TLS syslog port.')
param tlsPort int = 6514

@description('Enable plain-text syslog listener (port 514 TCP + UDP).')
param enablePlaintext bool = false

@description('Plain-text syslog port.')
param plaintextPort int = 514

@description('Allowed source CIDRs for all syslog NSG rules.')
param allowedSyslogSourceCidrs array = ['10.0.0.0/16']

@description('True = public Standard LB with a PIP. False = internal LB, no PIP.')
param loadBalancerPublic bool = false

@description('Create a new Log Analytics workspace.')
param createWorkspace bool = true

@description('Name of the Log Analytics workspace (new or existing).')
param workspaceName string = 'log-sc-syslog-collector'

@description('Full resource ID of an existing workspace. Required only when createWorkspace = false.')
param existingWorkspaceId string = ''

@description('Onboard Microsoft Sentinel on the workspace.')
param enableSentinel bool = true

@description('VNet address space.')
param vnetAddressPrefix string = '10.0.0.0/16'

@description('Subnet address prefix (must fall within vnetAddressPrefix).')
param subnetAddressPrefix string = '10.0.0.0/24'

@description('Resource tags applied to every resource.')
param tags object = {
  workload: 'syslog-collector'
  env: 'prod'
  managedBy: 'bicep'
  deployedBy: 'squad'
}

@description('Admin username for VMSS instances.')
param adminUsername string = 'azureuser'

@description('SSH public key for the admin user (not a secret — public material).')
param adminSshPublicKey string

@secure()
@description('PEM-encoded CA certificate. When non-empty, injected into Key Vault at deploy time (single-shot TLS deploy). Empty = manual upload.')
param syslogCaCertPem string = ''

@secure()
@description('PEM-encoded server certificate. When non-empty, injected into Key Vault at deploy time. Empty = manual upload.')
param syslogServerCertPem string = ''

@secure()
@description('PEM-encoded server private key. When non-empty, injected into Key Vault at deploy time. Empty = manual upload.')
param syslogServerKeyPem string = ''

// ── Module: Identity ──────────────────────────────────────────

module identity 'modules/identity.bicep' = {
  name: 'identity'
  params: {
    baseName: baseName
    location: location
    tags: tags
  }
}

// ── Module: Network ───────────────────────────────────────────

module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    baseName: baseName
    location: location
    vnetAddressPrefix: vnetAddressPrefix
    subnetAddressPrefix: subnetAddressPrefix
    allowedSyslogSourceCidrs: allowedSyslogSourceCidrs
    enableTls: enableTls
    tlsPort: tlsPort
    enablePlaintext: enablePlaintext
    plaintextPort: plaintextPort
    tags: tags
  }
}

// ── Module: Log Analytics Workspace + Sentinel ────────────────

module workspace 'modules/workspace.bicep' = {
  name: 'workspace'
  params: {
    location: location
    createWorkspace: createWorkspace
    workspaceName: workspaceName
    existingWorkspaceId: existingWorkspaceId
    enableSentinel: enableSentinel
    tags: tags
  }
}

// ── Module: Load Balancer ─────────────────────────────────────

module lb 'modules/loadbalancer.bicep' = {
  name: 'loadbalancer'
  params: {
    baseName: baseName
    location: location
    loadBalancerPublic: loadBalancerPublic
    subnetId: network.outputs.subnetId
    enableTls: enableTls
    tlsPort: tlsPort
    enablePlaintext: enablePlaintext
    plaintextPort: plaintextPort
    tags: tags
  }
}

// ── Module: Key Vault (TLS cert material — owned by Ash) ──────

module keyvault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    baseName: baseName
    location: location
    amaUamiPrincipalId: identity.outputs.uamiPrincipalId
    syslogCaCertPem: syslogCaCertPem
    syslogServerCertPem: syslogServerCertPem
    syslogServerKeyPem: syslogServerKeyPem
  }
}

// ── Module: VMSS ──────────────────────────────────────────────

module vmss 'modules/vmss.bicep' = {
  name: 'vmss'
  params: {
    baseName: baseName
    location: location
    vmSku: vmSku
    instanceCountMin: instanceCountMin
    subnetId: network.outputs.subnetId
    lbBackendPoolId: lb.outputs.backendPoolId
    uamiId: identity.outputs.uamiId
    uamiClientId: identity.outputs.uamiClientId
    keyVaultName: keyvault.outputs.keyVaultName
    adminUsername: adminUsername
    adminSshPublicKey: adminSshPublicKey
    tags: tags
  }
}

// ── Module: Data Collection Rule + Association ────────────────

module dcr 'modules/dcr.bicep' = {
  name: 'dcr'
  params: {
    baseName: baseName
    location: location
    workspaceId: workspace.outputs.workspaceId
    vmssName: vmss.outputs.vmssName
    tags: tags
  }
}

// ── Module: Autoscale ─────────────────────────────────────────

module autoscale 'modules/autoscale.bicep' = {
  name: 'autoscale'
  params: {
    baseName: baseName
    location: location
    vmssId: vmss.outputs.vmssId
    instanceCountMin: instanceCountMin
    instanceCountMax: instanceCountMax
    tags: tags
  }
}

// ── Outputs ───────────────────────────────────────────────────

@description('Resource ID of the VMSS.')
output vmssId string = vmss.outputs.vmssId

@description('Resource ID of the DCR.')
output dcrId string = dcr.outputs.dcrId

@description('Resource ID of the Log Analytics workspace.')
output workspaceId string = workspace.outputs.workspaceId

@description('Resource ID of the UAMI.')
output uamiId string = identity.outputs.uamiId

@description('Public IP address (empty when loadBalancerPublic = false).')
output lbPublicIp string = lb.outputs.publicIpAddress

@description('NAT Gateway egress public IP — the source IP VMSS instances use for outbound traffic.')
output egressPublicIp string = network.outputs.egressPublicIp

@description('Key Vault URI (use when configuring additional VMSS extensions or cert rotation).')
output keyVaultUri string = keyvault.outputs.keyVaultUri

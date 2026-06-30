// ============================================================
// network.bicep — VNet, Subnet, NSG
//
// Deviations from upstream:
//   #6  — No public SSH (22) rule from *.
//   #7  — Syslog rules scoped to allowedSyslogSourceCidrs; 6514 TLS added.
//   #8  — Fixed 'Microsoft.Networks' typo; subnet is defined inline on the
//         VNet (no separate child resource), so the typo cannot reappear.
// ============================================================

@description('Base name prefix for all resources.')
param baseName string

@description('Azure region.')
param location string

@description('VNet address space CIDR.')
param vnetAddressPrefix string

@description('Subnet address prefix CIDR.')
param subnetAddressPrefix string

@description('Source CIDRs allowed to send syslog. Applied to every syslog NSG rule.')
param allowedSyslogSourceCidrs array

@description('Enable TLS syslog listener rule (port tlsPort).')
param enableTls bool

@description('TLS syslog port (default 6514 per RFC 5425).')
param tlsPort int

@description('Enable plaintext syslog listener rules (port plaintextPort).')
param enablePlaintext bool

@description('Plaintext syslog port (default 514).')
param plaintextPort int

@description('Resource tags.')
param tags object = {}

// ── Security rules (conditionally built) ─────────────────────

var tlsRule = enableTls ? [
  {
    name: 'Allow-Syslog-TLS'
    properties: {
      description: 'Allow TLS syslog ingestion (RFC 5425) from authorised sources.'
      priority: 100
      direction: 'Inbound'
      access: 'Allow'
      protocol: 'Tcp'
      sourceAddressPrefixes: allowedSyslogSourceCidrs
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: string(tlsPort)
    }
  }
] : []

var plaintextRule = enablePlaintext ? [
  {
    name: 'Allow-Syslog-Plain-TCP'
    properties: {
      description: 'Allow plain-text TCP syslog from authorised sources (legacy fallback).'
      priority: 200
      direction: 'Inbound'
      access: 'Allow'
      protocol: 'Tcp'
      sourceAddressPrefixes: allowedSyslogSourceCidrs
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: string(plaintextPort)
    }
  }
  {
    name: 'Allow-Syslog-Plain-UDP'
    properties: {
      description: 'Allow plain-text UDP syslog from authorised sources (legacy fallback).'
      priority: 210
      direction: 'Inbound'
      access: 'Allow'
      protocol: 'Udp'
      sourceAddressPrefixes: allowedSyslogSourceCidrs
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: string(plaintextPort)
    }
  }
] : []

var denyAllInbound = [
  {
    name: 'Deny-All-Other-Inbound'
    properties: {
      description: 'Explicit deny for all other inbound traffic.'
      priority: 4000
      direction: 'Inbound'
      access: 'Deny'
      protocol: '*'
      sourceAddressPrefix: '*'
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '*'
    }
  }
]

var securityRules = concat(tlsRule, plaintextRule, denyAllInbound)

// ── Resources ────────────────────────────────────────────────

// NAT Gateway public IP — separate from the LB frontend PIP.
// Standard SKU, static allocation; provides the source IP for all VMSS outbound flows.
resource natgwPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${baseName}-natgw-pip'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

// NAT Gateway — provides reliable outbound SNAT for VMSS instances.
// Standard LB with no instance PIPs gives no default outbound; NAT GW fills that gap
// for both internal and public LB configurations. Zone-agnostic for simplicity.
resource natgw 'Microsoft.Network/natGateways@2024-05-01' = {
  name: '${baseName}-natgw'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    idleTimeoutInMinutes: 4
    publicIpAddresses: [
      {
        id: natgwPip.id
      }
    ]
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${baseName}-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: securityRules
  }
}

// Subnet defined inline on the VNet — avoids the upstream
// child-resource typo ('Microsoft.Networks') entirely. (deviation #8)
resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${baseName}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressPrefix]
    }
    subnets: [
      {
        name: 'default'
        properties: {
          addressPrefix: subnetAddressPrefix
          networkSecurityGroup: {
            id: nsg.id  // Microsoft.Network (correct), never Microsoft.Networks
          }
          natGateway: {
            id: natgw.id  // outbound SNAT for VMSS instances (no instance PIPs)
          }
        }
      }
    ]
  }
}

// ── Outputs ──────────────────────────────────────────────────

@description('Resource ID of the default subnet.')
output subnetId string = vnet.properties.subnets[0].id

@description('Resource ID of the NSG.')
output nsgId string = nsg.id

@description('Resource ID of the VNet.')
output vnetId string = vnet.id

@description('NAT Gateway outbound public IP — the source IP all VMSS instances appear as for egress.')
output egressPublicIp string = natgwPip.properties.ipAddress

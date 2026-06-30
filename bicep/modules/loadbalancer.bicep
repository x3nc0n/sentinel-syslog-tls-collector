// ============================================================
// loadbalancer.bicep — Public IP (optional) + Standard LB
//
// Deviations from upstream:
//   #15 — inboundNatPools removed; SSH NAT omitted entirely.
//          Use Azure Bastion or Serial Console for access.
//   #4  — TCP 6514 TLS rule + health probe; optional 514 TCP/UDP.
//   Param loadBalancerPublic (default false) → internal LB,
//   no public IP created.
// ============================================================

@description('Base name prefix for all resources.')
param baseName string

@description('Azure region.')
param location string

@description('When true, a Standard public IP is created and attached to the LB frontend. When false, an internal frontend is used (private IP from the subnet).')
param loadBalancerPublic bool = false

@description('Subnet resource ID — required for internal LB frontend.')
param subnetId string

@description('Enable TLS syslog LB rule (TCP tlsPort).')
param enableTls bool

@description('TLS syslog port.')
param tlsPort int

@description('Enable plaintext syslog LB rules (TCP + UDP plaintextPort).')
param enablePlaintext bool

@description('Plaintext syslog port.')
param plaintextPort int

@description('Resource tags.')
param tags object = {}

// ── Naming ───────────────────────────────────────────────────

var lbName           = '${baseName}-lb'
var backendPoolName  = 'backend'
var frontendName     = 'frontend'
var probeName        = 'probe-primary'
var probePort        = enableTls ? tlsPort : plaintextPort

// ── Public IP (only when loadBalancerPublic = true) ──────────

resource pip 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (loadBalancerPublic) {
  name: '${baseName}-pip'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: replace(baseName, '-', '')
    }
  }
}

// ── Load Balancer ────────────────────────────────────────────

// Build LB rules and probes conditionally
var tlsLbRule = enableTls ? [
  {
    name: 'rule-syslog-tls'
    properties: {
      protocol: 'Tcp'
      frontendPort: tlsPort
      backendPort: tlsPort
      enableFloatingIP: false
      idleTimeoutInMinutes: 4
      frontendIPConfiguration: {
        id: resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', lbName, frontendName)
      }
      backendAddressPool: {
        id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lbName, backendPoolName)
      }
      probe: {
        id: resourceId('Microsoft.Network/loadBalancers/probes', lbName, probeName)
      }
    }
  }
] : []

var plaintextTcpLbRule = enablePlaintext ? [
  {
    name: 'rule-syslog-plain-tcp'
    properties: {
      protocol: 'Tcp'
      frontendPort: plaintextPort
      backendPort: plaintextPort
      enableFloatingIP: false
      idleTimeoutInMinutes: 4
      frontendIPConfiguration: {
        id: resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', lbName, frontendName)
      }
      backendAddressPool: {
        id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lbName, backendPoolName)
      }
      probe: {
        id: resourceId('Microsoft.Network/loadBalancers/probes', lbName, probeName)
      }
    }
  }
] : []

var plaintextUdpLbRule = enablePlaintext ? [
  {
    name: 'rule-syslog-plain-udp'
    properties: {
      protocol: 'Udp'
      frontendPort: plaintextPort
      backendPort: plaintextPort
      enableFloatingIP: false
      idleTimeoutInMinutes: 4
      frontendIPConfiguration: {
        id: resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', lbName, frontendName)
      }
      backendAddressPool: {
        id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lbName, backendPoolName)
      }
      probe: {
        id: resourceId('Microsoft.Network/loadBalancers/probes', lbName, probeName)
      }
    }
  }
] : []

var lbRules = concat(tlsLbRule, plaintextTcpLbRule, plaintextUdpLbRule)

var probes = (enableTls || enablePlaintext) ? [
  {
    name: probeName
    properties: {
      protocol: 'Tcp'
      port: probePort
      intervalInSeconds: 15
      numberOfProbes: 2
    }
  }
] : []

resource lb 'Microsoft.Network/loadBalancers@2024-05-01' = {
  name: lbName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    frontendIPConfigurations: [
      {
        name: frontendName
        properties: loadBalancerPublic ? {
          publicIPAddress: {
            id: pip.id
          }
        } : {
          subnet: {
            id: subnetId
          }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
    backendAddressPools: [
      {
        name: backendPoolName
      }
    ]
    probes: probes
    loadBalancingRules: lbRules
    // inboundNatPools intentionally omitted — deprecated for Uniform VMSS.
    // SSH access via Azure Bastion or Serial Console. (deviation #15)
  }
}

// ── Outputs ──────────────────────────────────────────────────

@description('Resource ID of the load balancer.')
output lbId string = lb.id

@description('Resource ID of the backend address pool.')
output backendPoolId string = lb.properties.backendAddressPools[0].id

@description('Name of the load balancer (used by VMSS IP config reference).')
output lbName string = lb.name

@description('Public IP address (empty string when loadBalancerPublic = false).')
#disable-next-line BCP318 // pip is non-null here because loadBalancerPublic guards the ternary
output publicIpAddress string = loadBalancerPublic ? pip.properties.ipAddress : ''

// ============================================================
// dcr.bicep — Data Collection Rule (Linux / Syslog) + DCR Association
//
// Deviations from upstream:
//   #12 — GA API version 2023-03-11 (upstream used 2021-09-01-preview).
//   #13 — Named '${baseName}-dcr' (upstream hardcoded 'default').
// ============================================================

@description('Base name prefix for all resources.')
param baseName string

@description('Azure region.')
param location string

@description('Resource ID of the Log Analytics workspace destination.')
param workspaceId string

@description('Name of the VMSS to associate this DCR with.')
param vmssName string

@description('Resource tags.')
param tags object = {}

// ── Data Collection Rule ──────────────────────────────────────

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${baseName}-dcr'
  location: location
  tags: tags
  kind: 'Linux'
  properties: {
    description: 'Collect syslog events and forward to Log Analytics / Sentinel.'
    dataSources: {
      syslog: [
        {
          name: 'syslogDataSource'
          streams: ['Microsoft-Syslog']
          // Sensible defaults: core facilities, Info+ severity
          facilityNames: [
            'auth'
            'authpriv'
            'cron'
            'daemon'
            'kern'
            'local0'
            'local1'
            'local2'
            'local3'
            'local4'
            'local5'
            'local6'
            'local7'
            'syslog'
            'user'
            'uucp'
          ]
          logLevels: [
            'Info'
            'Notice'
            'Warning'
            'Error'
            'Critical'
            'Alert'
            'Emergency'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceId
          name: 'workspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-Syslog']
        destinations: ['workspace']
      }
    ]
  }
}

// ── DCR Association → VMSS ────────────────────────────────────
// Scoped to the VMSS resource so AMA discovers and applies the rule.

resource vmss 'Microsoft.Compute/virtualMachineScaleSets@2024-07-01' existing = {
  name: vmssName
}

resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: 'DCRa-${baseName}'
  scope: vmss
  properties: {
    description: 'Binds the syslog DCR to the collector VMSS.'
    dataCollectionRuleId: dcr.id
  }
}

// ── Outputs ──────────────────────────────────────────────────

@description('Resource ID of the Data Collection Rule.')
output dcrId string = dcr.id

@description('Name of the Data Collection Rule.')
output dcrName string = dcr.name

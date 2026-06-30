// ============================================================
// workspace.bicep — Log Analytics Workspace + Sentinel
//
// Deviation #17: optionally creates the workspace and onboards
// Microsoft Sentinel. When createWorkspace = false, references
// an existing workspace by full resource ID.
// ============================================================

@description('Azure region.')
param location string

@description('When true, a new Log Analytics workspace is created. When false, an existing workspace is referenced via existingWorkspaceId.')
param createWorkspace bool = true

@description('Name of the new workspace. Also used to derive the Sentinel solution name.')
param workspaceName string = 'log-sc-syslog-collector'

@description('Full resource ID of an existing Log Analytics workspace. Required when createWorkspace = false.')
param existingWorkspaceId string = ''

@description('When true, Microsoft Sentinel (SecurityInsights) is onboarded on the workspace.')
param enableSentinel bool = true

@description('Resource tags.')
param tags object = {}

// ── Workspace (conditional create) ───────────────────────────

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (createWorkspace) {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Resolve workspace resource ID regardless of create / reference path
var resolvedWorkspaceId   = createWorkspace ? workspace.id   : existingWorkspaceId
// Parse workspace name from the resource ID tail when referencing existing
var resolvedWorkspaceName = createWorkspace ? workspaceName  : last(split(existingWorkspaceId, '/'))

// ── Microsoft Sentinel onboarding ────────────────────────────
// Uses the SecurityInsights OMSGallery solution — the stable mechanism
// for enabling Sentinel on a workspace. (deviation #17)
// API 2015-11-01-preview is the only available version for this RP.

resource sentinelSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = if (enableSentinel) {
  name: 'SecurityInsights(${resolvedWorkspaceName})'
  location: location
  plan: {
    name: 'SecurityInsights(${resolvedWorkspaceName})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
  properties: {
    workspaceResourceId: resolvedWorkspaceId
  }
}

// ── Outputs ──────────────────────────────────────────────────

@description('Resource ID of the Log Analytics workspace (new or existing).')
output workspaceId string = resolvedWorkspaceId

@description('Name of the Log Analytics workspace.')
output workspaceName string = resolvedWorkspaceName

// ============================================================
// identity.bicep — User-Assigned Managed Identity for AMA
//
// Deviation-log: #11 — named '${baseName}-uami' instead of
// the upstream generic 'managedIdentity'.
// ============================================================

@description('Base name prefix for all resources.')
param baseName string

@description('Azure region.')
param location string

@description('Resource tags.')
param tags object = {}

// ── Resources ────────────────────────────────────────────────

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${baseName}-uami'
  location: location
  tags: tags
}

// ── Outputs ──────────────────────────────────────────────────

@description('Full resource ID of the UAMI.')
output uamiId string = uami.id

@description('Principal (object) ID of the UAMI — used for RBAC assignments.')
output uamiPrincipalId string = uami.properties.principalId

@description('Client ID of the UAMI — used in AMA extension settings.')
output uamiClientId string = uami.properties.clientId

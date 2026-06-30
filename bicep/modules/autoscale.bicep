// ============================================================
// autoscale.bicep — CPU-based autoscale for the VMSS
//
// Deviations from upstream:
//   #2  — API version 2022-10-01 (upstream used ancient 2014-04-01).
//   #14 — 5-minute cooldown (upstream used 1 minute → scale thrashing).
// ============================================================

@description('Base name prefix for all resources.')
param baseName string

@description('Azure region.')
param location string

@description('Resource ID of the VMSS to autoscale.')
param vmssId string

@description('Minimum instance count.')
param instanceCountMin int = 1

@description('Maximum instance count.')
param instanceCountMax int = 3

@description('Resource tags.')
param tags object = {}

// ── Autoscale ─────────────────────────────────────────────────

resource autoscale 'Microsoft.Insights/autoscalesettings@2022-10-01' = {
  name: '${baseName}-autoscale'
  location: location
  tags: tags
  properties: {
    enabled: true
    name: '${baseName}-autoscale'
    targetResourceUri: vmssId
    profiles: [
      {
        name: 'default'
        capacity: {
          minimum: string(instanceCountMin)
          maximum: string(instanceCountMax)
          default: string(instanceCountMin)
        }
        rules: [
          // ── Scale-out: CPU > 75% ─────────────────────────
          {
            metricTrigger: {
              metricName: 'Percentage CPU'
              metricResourceUri: vmssId
              timeGrain: 'PT1M'
              statistic: 'Average'
              timeWindow: 'PT5M'
              timeAggregation: 'Average'
              operator: 'GreaterThan'
              threshold: 75
            }
            scaleAction: {
              direction: 'Increase'
              type: 'ChangeCount'
              value: '1'
              cooldown: 'PT5M'  // deviation #14: was PT1M upstream
            }
          }
          // ── Scale-in: CPU < 25% ──────────────────────────
          {
            metricTrigger: {
              metricName: 'Percentage CPU'
              metricResourceUri: vmssId
              timeGrain: 'PT1M'
              statistic: 'Average'
              timeWindow: 'PT5M'
              timeAggregation: 'Average'
              operator: 'LessThan'
              threshold: 25
            }
            scaleAction: {
              direction: 'Decrease'
              type: 'ChangeCount'
              value: '1'
              cooldown: 'PT5M'  // deviation #14: was PT1M upstream
            }
          }
        ]
      }
    ]
  }
}

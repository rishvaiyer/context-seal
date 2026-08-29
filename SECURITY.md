# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to [rishtiyer@gmail.com](mailto:rishtiyer@gmail.com). Include the affected commit, reproduction steps, expected and observed behavior, and likely impact. Do not include real credentials, personal data, or other sensitive material in the report.

## Security model

CanaryNorth places a server-side policy boundary between an AI-assisted request and a tool action. The current implementation checks capability scope, expiry, identity context, tenant and workspace binding, nonce replay, and approval state before recording a signed decision receipt.

Deterministic input signals can hold suspicious content for review, but authorization comes from the structural policy checks rather than those text patterns.

## Deployment requirements

Production mode fails closed unless authentication, signing material, and durable receipt storage are configured. Use `.env.example` and the deployment-boundary tests as the current configuration reference.

The public Railway deployment is a synthetic demonstration and does not forward requests to external tools.

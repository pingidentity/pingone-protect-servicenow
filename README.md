# PingOne Protect Audit Webhook to ServiceNow Incident Integration

This repository contains the configuration steps and ServiceNow Scripted REST Resource script for creating ServiceNow incidents from PingOne Protect audit webhook events.

The integration flow is:

```text
PingOne Protect audit event
  -> PingOne webhook
  -> ServiceNow Scripted REST API
  -> ServiceNow incident
```

The included script processes PingOne Protect `RISK_EVALUATION.CREATED` events, filters for `HIGH` risk evaluations, and creates ServiceNow incidents with risk, user, device, network, location, and velocity details.

## Repository Contents

```text
.
|-- README.md
`-- servicenow/
    `-- pingone_audit_ingest.js
```

## Prerequisites

### PingOne

- PingOne tenant
- PingOne Protect enabled
- Access to PingOne webhooks
- Permission to subscribe to audit events

### ServiceNow

- Admin access
- Scripted REST API access
- Permission to create users, groups, and incidents

## ServiceNow Configuration

### 1. Create the API user

Create a dedicated integration user in ServiceNow.

Navigate to one of:

- All > Users
- Organization > Users

Recommended user values:

| Field | Value |
| --- | --- |
| User ID | `pingone.webhook` |
| Active | `true` |
| Web service access only | `true` |
| Password needs reset | `false` |

Assign these roles:

- `itil`
- `rest_service`

Use a strong password and store it securely. Do not commit ServiceNow credentials to this repository.

### 2. Create the assignment group

Create a ServiceNow assignment group named:

```text
Fraud Analysts
```

Navigate to one of:

- All > Groups
- User Administration > Groups

The included script looks up this group by name and assigns created incidents to it when found.

### 3. Create the Scripted REST API

Navigate to one of:

- All > Scripted REST APIs
- System Web Services > Scripted REST APIs

Create a new Scripted REST API:

| Field | Value |
| --- | --- |
| Name | `PingOne Audit API` |
| API ID | `pingone_audit` |
| Requires authentication | `true` |
| Default ACLs | `Scripted REST External Default` |

Submit the record.

### 4. Create the REST resource

Inside the `PingOne Audit API`, create a REST resource:

| Field | Value |
| --- | --- |
| Name | `ingest` |
| HTTP Method | `POST` |
| Relative Path | `/events` |
| Requires authentication | `true` |
| Requires ACL authorization | `false` |

Submit the resource.

### 5. Add the resource script

Open the Scripted REST Resource script editor and paste the contents of:

```text
servicenow/pingone_audit_ingest.js
```

Save the Scripted REST Resource.

### 6. Confirm the endpoint URL

The endpoint format is:

```text
https://YOUR_INSTANCE.service-now.com/api/YOUR_NAMESPACE/pingone_audit/events
```

Replace:

- `YOUR_INSTANCE` with the ServiceNow instance name
- `YOUR_NAMESPACE` with the generated namespace shown by ServiceNow for the Scripted REST API

## PingOne Configuration

### 1. Create the webhook

In PingOne Admin, navigate to:

```text
Integrations > Webhooks
```

Create a webhook with these values:

| Setting | Value |
| --- | --- |
| Destination URL | ServiceNow endpoint URL |
| Method | `POST` |
| Content-Type | `application/json` |
| Accept | `application/json` |
| Authentication | `Basic Authentication` |

### 2. Configure authentication

Use the ServiceNow integration user credentials:

| Field | Value |
| --- | --- |
| Username | `pingone.webhook` |
| Password | ServiceNow integration user password |

### 3. Select events

Subscribe to:

```text
RISK_EVALUATION.CREATED
```

The ServiceNow script ignores events that are not `RISK_EVALUATION.CREATED` and ignores risk evaluations that are not `HIGH`.

## Test the Integration

Send a sample payload to the Scripted REST API:

```shell
curl -X POST \
  'https://YOUR_INSTANCE.service-now.com/api/YOUR_NAMESPACE/pingone_audit/events' \
  -u 'pingone.webhook:SERVICE_NOW_PASSWORD' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d @payload.json
```

Expected successful response:

```json
{
  "status": "success",
  "received_count": 1,
  "created_count": 1,
  "incidents": ["INCIDENT_SYS_ID"]
}
```

If the payload contains no qualifying high-risk evaluation events, `created_count` will be `0`.

## Validate Incident Creation

In ServiceNow, navigate to:

- All > Incidents

Or open:

```text
https://YOUR_INSTANCE.service-now.com/incident_list.do
```

Created incidents include:

- HIGH risk evaluations only
- Caller mapping by matching PingOne username to `sys_user.email`
- Assignment to `Fraud Analysts` when the group exists
- Risk score and event ID
- Device and browser details
- Location details
- IP reputation details
- Risk signals
- Velocity signals

## Troubleshooting

### 401 Unauthorized

Check the Basic Authentication username and password used by the PingOne webhook.

### 404 Not Found

Confirm the endpoint URL, namespace, API ID, and resource relative path.

### 406 Not Acceptable

Confirm the webhook sends:

```text
Accept: application/json
```

### No Incident Created

Verify that:

- The event action is `RISK_EVALUATION.CREATED`
- The risk evaluation level is `HIGH`
- The webhook payload reached ServiceNow
- The ServiceNow API user has permission to create incidents

### ServiceNow Script Errors

In ServiceNow, navigate to:

```text
System Logs > Errors
```

Review errors from the Scripted REST API execution.

## Recommended Enhancements

- Add deduplication based on PingOne event ID.
- Map risk levels to different priorities if you decide to ingest non-HIGH events.
- Add a shared secret header to validate webhook origin.
- Enrich IP details with a reputation provider.
- Route incidents based on risk signal type, geography, or anonymous network indicators.

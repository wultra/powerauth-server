# Telemetry API

<!-- TEMPLATE api -->

Telemetry API allows querying various statistics about the PowerAuth system usage. Information obtained from the reports can be used for example for billing purposes, estimating performance requirements or measure user base growth.

## Possible Error Codes

The API may return one of the following error codes:

| HTTP  | Error Code              | Description                                                                       |
|-------|-------------------------|-----------------------------------------------------------------------------------|
| `400` | `ERROR_TELEMETRY`       | Error related to telemetry reports.                                               |
| `400` | `ERROR_HTTP_REQUEST`    | Request did not pass validation (mandatory property missing, null/invalid value). |
| `401` | `ERROR_UNAUTHORIZED`    | Returned in the case authentication fails (invalid application credentials).      |
| `404` | `ERROR_NOT_FOUND`       | Returned in the case URL is not present (calling wrong API).                      |

## Services

To obtain report information, you need to call the telemetry service with appropriate parameters. To simplify processing of the reports and allow extensions in the future, all reports are returned via a single service and have unified request/response structure.

There are several specific reports supported in the system.

### Unique Current Monthly Active Users

Report for unique users in past 30 days (monthly active users = MAU).

- Report name: `CURRENT_MAU`
- Parameters:
  - `application` - specifies for what application should the report be generated
- Report data:
  - `application` - specifies for what application the report was generated
  - `days` - constant value `30`
  - `users` - number of unique active users in past 30 days

### Unique Active Users In Past Days

Report for the unique users in specified number of days since today.

- Report name: `USERS_IN_PAST_DAYS`
- Parameters:
  - `application` - specifies for what application should the report be generated
  - `days` - how many days back in the past the report should look, at most 365 
- Report data:
  - `application` - specifies for what application the report was generated
  - `days` - for how many days the report was generated
  - `users` - number of unique active users in given number of days

<!-- begin api POST /rest/v3/telemetry/report -->
### Generate Telemetry Report

Request a telemetry report with provided attributes.

#### Request

```json
{
  "requestObject": {
    "name": "$REPORT_NAME",
    "parameters": {
      "$PARAM1": "$VALUE1",
      "$PARAM2": "$VALUE2",
      "$PARAM3": "$VALUE3"
    }
  }
}
```

##### Request Params

| Attribute                                              | Type     | Description         |
|--------------------------------------------------------|----------|---------------------|
| `name`<span class="required" title="Required">*</span> | `String` | Report name.        |
| `parameters`                                           | `String` | Report parameters.  |

#### Response 200

If the report is successfully prepared, API returns the following reponse:

```json
{
  "status": "OK",
  "responseObject": {
    "name": "$REPORT_NAME",
    "reportData": {
      "$PARAM1": "$VALUE1",
      "$PARAM2": "$VALUE2",
      "$PARAM3": "$VALUE3"
    }
  }
}
```

| Attribute                                              | Type     | Description  |
|--------------------------------------------------------|----------|--------------|
| `name`<span class="required" title="Required">*</span> | `String` | Report name. |
| `reportData`                                           | `String` | Report data. |

<!-- end -->
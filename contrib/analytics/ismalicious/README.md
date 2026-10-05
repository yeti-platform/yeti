# IsMalicious indicator enrichment

The built-in `IsMaliciousReport` one-shot task enriches IPv4/IPv6, hostnames,
URLs and MD5/SHA-1/SHA-256 observables. It attaches the complete API response
and a report link to the observable's `IsMalicious` context. It does not tag
an observable as benign or automatically block it.

Each lookup sends the indicator's value to IsMalicious at
`api.ismalicious.com`, a third-party service. Avoid running it on indicators
you are not willing to disclose, including internal hostnames or investigation
URLs. Repeated lookups replace the previous `IsMalicious` context with the
latest report and leave other sources' context intact.

Create an [IsMalicious account](https://ismalicious.com/app/account), generate
an API key/secret pair and set the `X-API-KEY` credential, which is **Base64 of
`apiKey:apiSecret`**, in the task worker's environment:

```text
YETI_ISMALICIOUS_API_CREDENTIAL=<Base64-encoded API key:API secret pair>
```

Alternatively, configure `api_credential` under `[ismalicious]` in `yeti.conf`.
Keep the credential private and restart the task workers after configuration.
Run **IsMalicious Report** from a supported observable's one-shot actions.
Each observable consumes one lookup under your account's quota. This plugin
does not ingest or redistribute the paid TAXII feeds.

The request uses `GET https://api.ismalicious.com/check` with `query` and
`enrichment=standard`, verified TLS, a 30-second timeout, and no redirects.
The existing Yeti HTTP/HTTPS proxy configuration applies. Authentication,
rate-limit, transport and malformed-response failures leave existing context
unchanged and fail the task explicitly. No automatic retries are made.

Use `report.evidence.verdict`, reasons and contradictions when interpreting
the result. `malicious: false` alone does not prove safety; an unknown hash
stays unknown even when its numeric risk score is zero. Risk score and
confidence are separate fields. Contextual source rows are not detection
counts. Optional fields depend on the indicator and available evidence.

API reference: <https://ismalicious.com/api-docs>.

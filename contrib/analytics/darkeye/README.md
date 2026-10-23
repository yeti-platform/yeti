# DarkEye domain lookup

The built-in `DarkEyeLookup` one-shot task looks up a hostname observable in
DarkEye's ransomware, breach, lead and stealer data and stores the matching
records in the observable's `DarkEye` context. DarkEye (<https://darkeye.io>)
serves this data through two APIs, and the task queries each one that has a
key configured:

- Have I Been Ransomed? (`haveibeenransom.com`): ransomware leak-site posts
  and data breaches for the domain.
- Breach House (`breach.house`): ransomware victims, data breaches, access
  leads and stealer logs that match the domain.

The context lists the products queried, the record count, a `truncated` flag
and one entry per record with its product, category (`ransomware`,
`breaches`, `leads` or `stealers`), id, title, website, group, country and
discovery date. The task keeps only listing metadata and never stores leaked
records, proof files or leak-site and download URLs. It does not tag the
observable. Repeated lookups replace the previous `DarkEye` context and leave
other sources' context intact.

Each lookup sends the domain to DarkEye, a third-party service. Avoid running
it on domains you are not willing to disclose.

Both APIs need a key (see <https://haveibeenransom.com/howapi> and
<https://breach.house/docs>). Set at least one in the task worker's
environment:

```text
YETI_DARKEYE_HAVEIBEENRANSOM_API_KEY=<Have I Been Ransomed? API key>
YETI_DARKEYE_BREACHHOUSE_API_KEY=<Breach House API token>
```

Alternatively, configure `haveibeenransom_api_key` and `breachhouse_api_key`
under `[darkeye]` in `yeti.conf`. Keep the keys private and restart the task
workers after configuration. Run **DarkEye Lookup** from a hostname's one-shot
actions.

Have I Been Ransomed? returns pages of 20 leaks, and each page counts as one
request against the key's daily quota. `max_pages` (default 5) caps the pages
per lookup. Breach House answers in one request per lookup, which counts
against the token's daily budget; `limit` (default 25, maximum 200) caps the
results per source. When either cap cuts the results short, the context has
`truncated: true`. Wildcard characters are rejected, so only plain domain
names are queried.

Requests use verified TLS, a 30-second timeout and no redirects, and the
existing Yeti HTTP/HTTPS proxy configuration applies. If any configured API
fails (authentication, rate limit, transport or malformed response), the task
fails explicitly and leaves existing context unchanged. It does not retry
automatically.

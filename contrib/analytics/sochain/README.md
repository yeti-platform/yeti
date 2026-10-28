# SoChain wallet enrichment

The built-in `SoChainWallet` one-shot task looks up a `wallet` observable on
[SoChain](https://sochain.com/docs) (Bitcoin, Litecoin, Dogecoin, Zcash). It
attaches a `SoChain` context to the observable with:

- the network, balance, total received and sent, transaction counts, and the
  first and last activity (block height and UTC time);
- address poisoning: whether look-alike addresses sent the wallet dust,
  imitating an address it paid or was paid by, with each finding;
- recent counterparties: who it paid and was paid by, with amounts and txids;
- a link to the address on sochain.com.

Each look-alike address is saved as a `wallet` observable and linked to the
looked-up wallet with an `address-poisoning` relationship; a finding whose
sender is not an alphanumeric ASCII address is skipped and logged. The task
does not tag observables.

The network comes from the wallet's `coin` (`btc`, `ltc`, `doge`, `zec` or the
coin names) or from a `<coin>:<address>` / `<coin>/<address>` value. A wallet
without a coin, such as one imported from a MISP `btc` attribute, is matched to
the first of Bitcoin, Litecoin, Dogecoin and Zcash on which SoChain says the
address is valid. Repeated lookups replace the previous `SoChain` context and
leave other sources' context intact.

Each lookup sends the address to SoChain, a third-party service. Avoid running
it on addresses you are not willing to disclose.

A lookup makes three requests, plus up to four to detect the network when the
wallet has no coin: up to seven in all. No API key is needed: SoChain answers
up to 2,500 requests a day per IP. Setting the wallet's coin saves the
detection requests. For more, create a key at <https://sochain.com/dashboard>
and set it in the task worker's environment:

```text
YETI_SOCHAIN_API_KEY=<key>
```

or as `api_key` under `[sochain]` in `yeti.conf`. It is sent as the `API-KEY`
header. Restart the task workers after configuration.

Requests use a 15-second timeout, no redirects and the Yeti proxy
configuration. Authentication, rate-limit, transport and malformed-response
failures leave existing context unchanged and fail the task. No automatic
retries are made.

API reference: <https://sochain.com/api/v3/openapi.json>.

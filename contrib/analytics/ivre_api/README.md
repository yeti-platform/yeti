# IVRE plugin for YETI #

This analytics uses IVRE's data. [IVRE](https://ivre.rocks/) is an
open-source network recon framework.

IVRE's code is available on [GitHub](https://github.com/cea-sec/ivre/)
and its documentation on [Read the docs](https://doc.ivre.rocks/).

## Description ##

Currently, this analytics provides:

- Estimated geographic location and Autonomous System (AS) of IP
  addresses (based on
  [MaxMind data](https://dev.maxmind.com/geoip/geoip2/geolite2/)).

- DNS responses seen: links are created from IP addresses to hostnames
  and vice versa, aka your own private Passive DNS service.

- X509 certificates seen in TLS traffic: links are created:

    - from IP addresses to certificates.

    - from certificates to hostnames and IP addresses (via `Subject` and
      `Subject Alternative Names` fields).

    - from certificates to subjects and issuers (as a dedicated
      observable type: `CertificateSubject`, via `Subject` and
      `Issuer` fields).

    - certificate subjects to (other) certificates (with same issuer
      or subject).

- HTTP headers: links are created from IP addresses to hostnames (and
  vice versa) based on `Host:` headers, and from IP addresses to
  `User-Agent` and `Server` header values.

This adds "IVRE - MaxMind" that uses IVRE's API to fetch information
from MaxMind databases, and "IVRE - Passive" that uses IVRE's passive
data to create links with hostnames and certificates.

## Example ##

Here is a graph of a fictitious investigation about an IP address used
by the `archlinux.org` domain, based on data from IVRE:

![Investigation graph for archlinux.org](investigation-archlinux.png)

## Installation ##

Using the `virtualenv` you use for YETI (if you do use `virtualenv`),
run (from YETI's source directory):

```Bash
ln -s ../../../contrib/analytics/ivre_api/ivre_api.py plugins/analytics/private/
pip install -r contrib/analytics/ivre_api/requirements.txt
ivre ipdata --download
```

You should be all set!

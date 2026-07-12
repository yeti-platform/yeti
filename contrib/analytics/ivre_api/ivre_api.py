"""Analytics relying on IVRE's data.

IVRE is an open-source network recon framework. See
<https://ivre.rocks/> to learn more about it.

Currently, this analytics provides:

  - Estimated geographic location and Autonomous System (AS) of IP
  addresses (based on MaxMind data, see
  <https://dev.maxmind.com/geoip/geoip2/geolite2/>).

  - DNS responses seen: links are created from IP addresses to
    hostnames and vice versa, aka your own private Passive DNS
    service.

  - X509 certificates seen in TLS traffic: links are created:

      - from IP addresses to certificates.

      - from certificates to hostnames and IP addresses (via Subject
        and Subject Alternative Names).

      - from certificates to subjects and issuers (as a dedicated
        observable type: CertificateSubject, via Subject and Issuer).

      - certificate subjects to (other) certificates (same issuer or
        subject).

  - HTTP headers: links are created from IP addresses to hostnames
    (and vice versa) based on Host: headers, and from IP addresses to
    User-Agent and Server header values.

"""

import itertools
import logging
from pprint import pformat

from ivre.db import db
from ivre.utils import encode_b64

from core.analytics import InlineAnalytics, OneShotAnalytics
from core.errors import ObservableValidationError
from core.observables import (
    AutonomousSystem,
    Certificate,
    CertificateSubject,
    Email,
    Hostname,
    Ip,
    Text,
    Url,
)

LOG = logging.getLogger("Yeti-Ivre")


def _try_link(
    links,
    base_obs,
    obs_type,
    value,
    description,
    source,
    first_seen=None,
    last_seen=None,
):
    """Try to add a link from `base_obs` to a new or existing obervable of
    type `obs_type`. ObservableValidationError exceptions on observable
    creation are silently ignored.

    This is useful, for example, to prevent crashes when trying to add
    Hostname observables based on fields that can contain either a
    hostname or an IP address (e.g., the commonName field of X509
    certificate subjects).

    """
    try:
        obs = obs_type.get_or_create(value=value)
    except ObservableValidationError:
        pass
    else:
        links.update(
            base_obs.link_to(
                obs, description, source, first_seen=first_seen, last_seen=last_seen
            )
        )


class IvreMaxMind(InlineAnalytics, OneShotAnalytics):
    """Perform lookups in MaxMind databases using IVRE.

    It creates links from an `Ip` observable to an `AutonomousSystem`
    observable, and fills the `geoip` attribute of `Ip` observables with
    `country`, `region` and `city` fields.

    You can fetch or update the local MaxMind databases by running `ivre
    ipdata --download`.

    """

    default_values = {
        "name": "IVRE - MaxMind",
        "description": __doc__,
    }

    ACTS_ON = ["Ip"]

    @classmethod
    def analyze(cls, observable, results):
        LOG.debug(
            "%s: begin analyze %r (type %s)",
            cls.__name__,
            observable,
            observable.__class__.__name__,
        )
        if isinstance(observable, Ip):
            return cls.analyze_ip(observable, results)
        LOG.warning(
            "%s: cannot analyze, unknown observable %r (type %s)",
            cls.__name__,
            observable,
            observable.__class__.__name__,
        )
        return []

    @classmethod
    def each(cls, observable):
        return cls.analyze(observable, None)

    @staticmethod
    def analyze_ip(ip, results):
        """Specific analyzer for Ip observables."""

        links = set()
        result = db.data.infos_byip(ip.value)
        if result is None:
            return []
        if results is not None:
            results.update(raw=pformat(result))

        if "as_name" in result:
            asn = AutonomousSystem.get_or_create(
                value=result["as_name"],
                as_num=result["as_num"],
            )
            links.update(ip.active_link_to(asn, "asn#", "IVRE - MaxMind"))

        if "country_code" in result:
            ip.geoip = {"country": result["country_code"]}
            if "region_code" in result:
                ip.geoip["region"] = " / ".join(result["region_code"])
            if "city" in result:
                ip.geoip["city"] = result["city"]
            ip.save()

        if all(context["source"] != "ivre_maxmind" for context in ip.context):
            result["source"] = "ivre_maxmind"
            ip.add_context(result)

        return list(links)


def _handle_cert(dbase, rec, links):
    """Internal function to handle a record corresponding to an X509
    certificate.

    """

    raw_data = dbase.from_binary(rec["value"])
    cert = Certificate.from_data(raw_data, hash_sha256=rec["infos"]["sha256"])
    rec["value"] = encode_b64(raw_data).decode()
    links.update(
        cert.link_to(
            CertificateSubject.get_or_create(value=rec["infos"]["subject_text"]),
            "cert-subject",
            "IVRE - X509 subject",
        )
    )
    links.update(
        cert.link_to(
            CertificateSubject.get_or_create(value=rec["infos"]["issuer_text"]),
            "cert-issuer",
            "IVRE - X509 issuer",
        )
    )
    commonname = rec["infos"]["subject"]["commonName"]
    if commonname:
        while commonname.startswith("*."):
            commonname = commonname[2:]
        if commonname:
            _try_link(
                links,
                cert,
                Hostname,
                commonname,
                "cert-commonname",
                "IVRE - X509 Subject commonName",
            )
    for san in rec["infos"].get("san", []):
        if san.startswith("DNS:"):
            san = san[4:]
            while san.startswith("*."):
                san = san[2:]
            if san:
                _try_link(
                    links, cert, Hostname, san, "cert-san", "IVRE - X509 subjectAltName"
                )
        elif san.startswith("IP Address:"):
            san = san[11:]
            if san:
                _try_link(
                    links, cert, Ip, san, "cert-san", "IVRE - X509 subjectAltName"
                )
        elif san.startswith("email:"):
            san = san[6:]
            if san:
                _try_link(
                    links, cert, Email, san, "cert-san", "IVRE - X509 subjectAltName"
                )
        elif san.startswith("URI:"):
            san = san[4:]
            if san:
                _try_link(
                    links, cert, Url, san, "cert-san", "IVRE - X509 subjectAltName"
                )
        else:
            LOG.debug("_handle_rec: cannot handle subjectAltName: %r", san)
    return cert


class IvrePassive(OneShotAnalytics):
    """Perform lookups in IVRE's passive database for records created with
    Zeek (formerly known as Bro, see <https://www.zeek.org/>) and the
    passiverecon script.

    It creates links from an `Ip` observable to:

      - `Certificate` and `CertificateSubject` observables, based on X509
        certificates seen in TLS traffic.

        - from those, to `Hostname`, `Ip` `Email` and `Url` observables,
          based on the subject commonName and the subjectAltName values

      - `Hostname` observables, based on DNS answers and HTTP Host: headers

    From `Hostname` observables to:

      - `Ip` and other `Hostname` observables, based on DNS answers

      - `Ip`, based on HTTP Host: headers

    From `CertificateSubject` observables to:

      - (other) `Certificate` observables, based on X509 certificates seen
        in TLS traffic.

    Please refer to IVRE's documentation on how to collect passive data.

    """

    default_values = {
        "name": "IVRE - Passive",
        "description": __doc__,
    }

    ACTS_ON = ["Ip", "Hostname", "CertificateSubject"]

    @classmethod
    def analyze(cls, observable, results):
        LOG.debug(
            "Begin analyze %s for %r (type %s)",
            cls.__name__,
            observable,
            observable.__class__.__name__,
        )
        if isinstance(observable, Ip):
            return cls.analyze_ip(observable, results)
        if isinstance(observable, Hostname):
            return cls.analyze_hostname(observable, results)
        if isinstance(observable, CertificateSubject):
            return cls.analyze_certsubj(observable, results)
        LOG.warning(
            "%s: cannot analyze, unknown observable %r (type %s)",
            cls.__name__,
            observable,
            observable.__class__.__name__,
        )
        return []

    @classmethod
    def analyze_ip(cls, ip, results):
        """Specific analyzer for Ip observables."""

        links = set()
        result = {}
        for rec in db.passive.get(db.passive.searchhost(ip.value)):
            LOG.debug("%s.analyze_ip: record %r", cls.__name__, rec)
            if rec["recontype"] == "DNS_ANSWER":
                value = rec["value"]
                hostname = Hostname.get_or_create(value=value)
                rec_type = "dns-%s" % rec["source"].split("-", 1)[0]
                result.setdefault(rec_type, set()).add(value)
                links.update(
                    ip.link_to(
                        hostname,
                        rec_type,
                        "IVRE - DNS-%s" % rec["source"],
                        first_seen=rec["firstseen"],
                        last_seen=rec["lastseen"],
                    )
                )

            elif rec["recontype"] == "HTTP_CLIENT_HEADER_SERVER":
                if rec["source"] == "HOST":
                    value = rec["value"]
                    result.setdefault("http-host", set()).add(value)
                    _try_link(
                        links,
                        ip,
                        Hostname,
                        value,
                        "http-host",
                        "IVRE - HTTP Host: header",
                        first_seen=rec["firstseen"],
                        last_seen=rec["lastseen"],
                    )
                else:
                    continue
            elif rec["recontype"] == "HTTP_SERVER_HEADER":
                if rec["source"] == "SERVER":
                    value = rec["value"]
                    result.setdefault("http-server", set()).add(value)
                    links.update(
                        ip.link_to(
                            Text.get_or_create(value=value),
                            "http-server",
                            "IVRE - HTTP Server: header",
                            first_seen=rec["firstseen"],
                            last_seen=rec["lastseen"],
                        )
                    )
                else:
                    continue
            elif rec["recontype"] == "HTTP_CLIENT_HEADER":
                if rec["source"] == "USER-AGENT":
                    value = rec["value"]
                    result.setdefault("http-user-agent", set()).add(value)
                    links.update(
                        ip.link_to(
                            Text.get_or_create(value=value),
                            "http-server",
                            "IVRE - HTTP User-Agent: header",
                            first_seen=rec["firstseen"],
                            last_seen=rec["lastseen"],
                        )
                    )
                else:
                    continue
            elif rec["recontype"] == "SSL_SERVER":
                if rec["source"] == "cert":
                    cert = _handle_cert(db.passive, rec, links)
                    result.setdefault("ssl-cert", set()).add(cert.value)
                    links.update(
                        ip.link_to(
                            cert,
                            "ssl-cert",
                            "IVRE - SSL X509 certificate",
                            first_seen=rec["firstseen"],
                            last_seen=rec["lastseen"],
                        )
                    )
                else:
                    continue
            else:
                continue

        if result:
            results.update(
                raw=pformat({key: list(value) for key, value in result.items()})
            )
            if all(context["source"] != "ivre_passive" for context in ip.context):
                ip.add_context({"source": "ivre_passive", "results": result})

        return list(links)

    @classmethod
    def analyze_hostname(cls, hostname, results):
        """Specific analyzer for Hostname observables."""

        links = set()
        result = []
        for rec in itertools.chain(
            db.passive.get(db.passive.searchdns(hostname.value, subdomains=True)),
            db.passive.get(
                db.passive.searchdns(hostname.value, reverse=True, subdomains=True)
            ),
        ):
            LOG.debug("%s.analyze_hostname: record %r", cls.__name__, rec)
            host = Hostname.get_or_create(value=rec["value"])
            if "addr" in rec:
                links.update(
                    Ip.get_or_create(value=rec["addr"]).link_to(
                        host,
                        "dns-%s" % rec["source"].split("-", 1)[0],
                        "IVRE - DNS-%s" % rec["source"],
                        first_seen=rec["firstseen"],
                        last_seen=rec["lastseen"],
                    )
                )
            else:
                links.update(
                    host.link_to(
                        Hostname.get_or_create(value=rec["targetval"]),
                        "dns-%s" % rec["source"].split("-", 1)[0],
                        "IVRE - DNS-%s" % rec["source"],
                        first_seen=rec["firstseen"],
                        last_seen=rec["lastseen"],
                    )
                )
                result.append(rec)

        results.update(raw=pformat(result))
        return list(links)

    @classmethod
    def analyze_certsubj(cls, subject, results):
        """Specific analyzer for CertificateSubject observables."""

        links = set()
        result = []
        for rec in itertools.chain(
            db.passive.get(db.passive.searchcertsubject(subject.value)),
            db.passive.get(db.passive.searchcertissuer(subject.value)),
        ):
            LOG.debug("%s.analyze_certsubj: record %r", cls.__name__, rec)
            cert = _handle_cert(db.passive, rec, links)
            links.update(
                Ip.get_or_create(value=rec["addr"]).link_to(
                    cert,
                    "ssl-cert",
                    "IVRE - SSL X509 certificate",
                    first_seen=rec["firstseen"],
                    last_seen=rec["lastseen"],
                )
            )
            result.append(rec)

        results.update(raw=pformat(result))
        return list(links)

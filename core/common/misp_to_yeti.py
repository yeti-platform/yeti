import json
import logging

import dateparser
import pycountry
from pymisp import MISPAttribute, MISPEvent, MISPObject

from core.schemas import entity, indicator, observable

MISP_Attribute_TO_IMPORT = {
    "btc": observable.ObservableType.wallet,
    "domain": observable.ObservableType.hostname,
    "hostname": observable.ObservableType.hostname,
    "ip-dst": observable.ObservableType.ipv4,
    "ip-src": observable.ObservableType.ipv4,
    "url": observable.ObservableType.url,
    "md5": observable.ObservableType.md5,
    "sha1": observable.ObservableType.sha1,
    "sha256": observable.ObservableType.sha256,
    "filename|sha256": observable.ObservableType.sha256,
    "filename|md5": observable.ObservableType.md5,
    "filename|sha1": observable.ObservableType.sha1,
    "ssdeep": observable.ObservableType.ssdeep,
    "mutex": observable.ObservableType.mutex,
    "named pipe": observable.ObservableType.named_pipe,
    "email": observable.ObservableType.email,
    "filename": observable.ObservableType.file,
    "regkey": observable.ObservableType.registry_key,
    "AS": observable.ObservableType.asn,
    "cookie": observable.ObservableType.cookie,
    "other": observable.ObservableType.generic,
    "path": observable.ObservableType.path,
}


class MispToYeti:
    def __init__(self, misp_event):
        self.misp_event = MISPEvent()
        self.misp_event.from_json(json.dumps(misp_event))
        self.func_by_type = {
            "asn": self.__import_asn_object,
            "av-signature": self.__import_av_signature,
            "btc-wallet": self.__import_btc_wallet,
            "c2-list": self.__import_c2_list,
            "crowdsec-ip-context": self.__import_crowdsec_ip_context,
            "command-line": self.__import_commande_line,
            "cookie": self.__import_cookie,
            "cs-beacon-config": self.__import_cs_beaconing,
            "domain-ip": self.__import_domain_ip,
            "dns-record": self.__import_dns_record,
            "directory": self.__import_directory,
            "email": self.__import_email,
        }

    def attr_misp_to_yeti(
        self,
        invest: entity.Investigation,
        attribute: MISPAttribute,
        description: str = "",
    ) -> observable.Observable:  # type: ignore
        obs_yeti = None
        if attribute.get("type") in MISP_Attribute_TO_IMPORT:
            obs_yeti = observable.TYPE_MAPPING[
                MISP_Attribute_TO_IMPORT[attribute.get("type")]  # type: ignore
            ](value=attribute.get("value")).save()
        else:
            try:
                obs_yeti = observable.generic_observable.GenericObservable(
                    value=attribute.get("value")
                ).save()  # type: ignore
            except ValueError:
                logging.error(f"Invalid value: {attribute.get('value')}")

        if obs_yeti:
            tags = attribute.get("Tag")
            if tags:
                obs_yeti.tag([t["name"] for t in tags])
            invest.link_to(obs_yeti, "imported_by_misp", description)
            logging.info(f"Attribute {attribute.get('value')} imported")

        return obs_yeti  # type: ignore

    def add_context_by_misp(
        self, attribute_misp: MISPAttribute, obs_yeti: observable.Observable
    ):
        context = {}
        context["Org"] = self.misp_event.org.name

        if attribute_misp.get("comment"):
            context["comment"] = attribute_misp.get("comment")
        obs_yeti.add_context("misp", context)

    def add_obs(self, invest: entity.Investigation, obs_misp: MISPObject):
        for attr in obs_misp["Attribute"]:
            obs_yeti = self.attr_misp_to_yeti(invest, attr)

            if obs_yeti:
                self.add_context_by_misp(attr, obs_yeti)
                yield obs_yeti
            else:
                logging.info(f"Attribute {attr} not imported")

    def obs_misp_to_yeti(self, invest: entity.Investigation, object_misp: MISPObject):
        if object_misp["name"] in self.func_by_type:
            self.func_by_type[object_misp["name"]](invest, object_misp)
        else:
            for obs_yeti in self.add_obs(invest, object_misp):
                invest.link_to(
                    obs_yeti,
                    "imported_by_misp",
                    description=f"misp {self.misp_event['Orgc']['name']}",
                )

    def misp_to_yeti(self):
        invest = entity.Investigation(name=self.misp_event["info"]).save()
        tags = self.misp_event.tags
        if tags:
            invest.tag([t["name"] for t in tags])
        invest.description = (
            f"Org {self.misp_event['Orgc']['name']} Event id: {self.misp_event['id']}"
        )
        for object_misp in self.misp_event.objects:
            self.obs_misp_to_yeti(invest, object_misp)

        for attribute_misp in self.misp_event.attributes:
            obs_yeti = self.attr_misp_to_yeti(invest, attribute_misp)
            if obs_yeti:
                self.add_context_by_misp(attribute_misp, obs_yeti)
            else:
                logging.info(f"Attribute {attribute_misp} not imported")
        invest.save()

    def __import_av_signature(
        self, invest: entity.Investigation, object_av_signature: MISPObject
    ):
        signature = object_av_signature.get_attributes_by_relation("signature")[0]
        description = object_av_signature.get_attributes_by_relation("Text")
        software = object_av_signature.get_attributes_by_relation("software")

        av_sig = indicator.av_signature(
            name=signature["value"],
            pattern=signature["value"],
            diamond=indicator.DiamondModel.capability,
            location="misp",
        ).save()

        if description:
            av_sig.description = description[0]["value"]
        if software:
            av_sig.software = software[0]["value"]
        av_sig.save()
        invest.link_to(
            av_sig, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}"
        )

    def __import_asn_object(self, invest: entity.Investigation, object_asn: dict):
        asn = self.attr_misp_to_yeti(
            invest,
            object_asn["value"],
            description=f"misp {self.misp_event['Orgc']['name']}",
        )
        context = {}

        if subnet := object_asn.get("subnet"):
            try:
                subnet = observable.cidr.CIDR(value=subnet).save()
                asn.link_to(subnet, "part_of", "subnet")
            except ValueError:
                logging.error(f"Invalid subnet: {subnet}")

        if object_asn["last-seen"]:
            context["last-seen"] = object_asn["last-seen"]
        if object_asn["first-seen"]:
            context["first-seen"] = object_asn["first-seen"]
        if object_asn["description"]:
            context["description"] = object_asn["description"]
        if object_asn["country"]:
            context["country"] = object_asn["country"]

        asn.add_context(f"misp {self.misp_event['Orgc']['name']} ", context)

        invest.link_to(
            asn, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}"
        )

    def __import_btc_wallet(self, invest: entity.Investigation, object_btc: MISPObject):
        address = object_btc.get_attributes_by_relation("wallet-address")[0]

        btc = observable.wallet.Wallet(
            value=address["value"], coin="btc", address=address["value"]
        ).save()

        btc_received = object_btc.get_attributes_by_relation("BTC_received")
        btc_sent = object_btc.get_attributes_by_relation("BTC_sent")
        btc_balance = object_btc.get_attributes_by_relation("balence_btc")

        context = {}

        if btc_received:
            context["BTC_received"] = btc_received[0]["value"]
        if btc_sent:
            context["BTC_sent"] = btc_sent[0]["value"]
        if btc_balance:
            context["balence_btc"] = btc_balance[0]["value"]

        btc.add_context(f"misp {self.misp_event['Orgc']['name']}", context)

    def __import_c2_list(self, invest: entity.Investigation, object_c2: MISPObject):
        threat_actor = object_c2.get_attributes_by_relation("threat")
        tags = [t["value"] for t in threat_actor]

        for c2 in object_c2.get_attributes_by_relation("c2-ip"):
            obs_yeti = self.attr_misp_to_yeti(
                invest, c2, description=f"misp {self.misp_event['Orgc']['name']}"
            )
            if tags:
                obs_yeti.tag(tags)

        for c2 in object_c2.get_attributes_by_relation("c2-ipport"):
            ip, port = c2["value"].split("|")
            obs_yeti = observable.TYPE_MAPPING[MISP_Attribute_TO_IMPORT["ip-src"]](
                value=ip
            ).save()
            if tags:
                obs_yeti.tag(tags)
            obs_yeti.add_context("misp", {"port": port})

    def __import_crowdsec_ip_context(
        self, invest: entity.Investigation, object_crowdsec_ip: MISPObject
    ):
        ip_attr = object_crowdsec_ip.get_attributes_by_relation("ip")[0]
        ip = self.attr_misp_to_yeti(
            invest, ip_attr, description=f"misp {self.misp_event['Orgc']['name']}"
        )

        as_num = object_crowdsec_ip.get_attributes_by_relation("as-num")
        as_name = object_crowdsec_ip.get_attributes_by_relation("as-name")
        as_obj = None
        if as_num:
            as_obj = observable.asn.ASN(value=as_num[0].value).save()
            ip.link_to(as_obj, "part_of", "asn")
        if as_obj and as_name:
            as_obj.name = as_name[0].value

        context = {}
        attack_details = object_crowdsec_ip.get_attributes_by_relation("attack-details")

        if attack_details:
            context["attack-details"] = attack_details[0].value

        background_noise = object_crowdsec_ip.get("background-noise")
        if background_noise:
            context["background-noise"] = background_noise[0].value

        behaviors = object_crowdsec_ip.get("behaviors")
        if behaviors:
            context["behaviors"] = behaviors[0].value

        city = object_crowdsec_ip.get_attributes_by_relation("city")
        country = object_crowdsec_ip.get_attributes_by_relation("country")
        country_code = object_crowdsec_ip.get_attributes_by_relation("country_code")

        if city or country or country_code:
            location = None
            if city:
                location = entity.Location(
                    name=city[0].value, city=city[0].value
                ).save()

            if country:
                location = entity.Location(
                    name=country[0].value, country=country[0].value
                ).save()
                location.set_country_code_by_name(country[0].value)
            if country_code:
                country_name = pycountry.countries.get(
                    alpha_2=country_code[0].value
                ).name
                location = entity.Location(
                    name=country_name, country=country_name
                ).save()
            if location:
                ip.link_to(location, "located_at", "location")
                invest.link_to(
                    location,
                    "imported_by_misp",
                    f"misp {self.misp_event['Orgc']['name']} CrowdSec",
                )
        dst_port = object_crowdsec_ip.get_attributes_by_relation("dst-port")
        if dst_port:
            context["dst_port"] = dst_port[0].value

        ip_range_scope = object_crowdsec_ip.get_attributes_by_relation("ip-range-scope")
        if ip_range_scope:
            context["ip-range-scope"] = ip_range_scope[0].value

        trust = object_crowdsec_ip.get_attributes_by_relation("trust")
        if trust:
            context["trust"] = trust[0].value

        ip_range = object_crowdsec_ip.get_attributes_by_relation("ip-range")
        if ip_range:
            cidr_obs = observable.cidr.CIDR(value=ip_range[0].value).save()  # type: ignore
            ip.link_to(cidr_obs, "part_of", "subnet")
            invest.link_to(
                cidr_obs,
                "imported_by_misp",
                f"misp {self.misp_event['Orgc']['name']} CrowdSec",
            )
        if context:
            ip.add_context(f"misp {self.misp_event['Orgc']['name']} CrowdSec", context)

        reverse_dns = object_crowdsec_ip.get_attributes_by_relation("reverse_dns")
        if reverse_dns:
            hostname = self.attr_misp_to_yeti(
                invest,
                reverse_dns[0],
                description=f"misp {self.misp_event['Orgc']['name']} CrowdSec",
            )
            ip.link_to(hostname, "resolved_to", "hostname")

    def __import_commande_line(
        self, invest: entity.Investigation, object_command_line: MISPObject
    ):
        cmd_line = object_command_line.get_attributes_by_relation("value")[0]
        description_misp = object_command_line.get_attributes_by_relation(
            "description"
        )[0]
        description = description_misp["value"] if description_misp else ""
        cmd_line_obs = observable.command_line.CommandLine(
            value=cmd_line["value"]
        ).save()
        context = {}

        if description:
            context["description"] = description

        if context:
            cmd_line_obs.add_context(f"misp {self.misp_event['Orgc']['name']}", context)

        invest.link_to(
            cmd_line_obs, "imported by misp", f"misp {self.misp_event['Orgc']['name']}"
        )

    def __import_cookie(self, invest: entity.Investigation, object_cookie: MISPObject):
        name = object_cookie.get_attributes_by_relation("cookie-name")[0]["value"]

        cookie_attr = object_cookie.get_attributes_by_relation("cookie")[0]
        cookie = self.attr_misp_to_yeti(
            invest, cookie_attr, description=f"misp {self.misp_event['Orgc']['name']}"
        )
        cookie.name = name
        https_only = object_cookie.get("http-only")
        if https_only:
            cookie.http_only = https_only
        secure = object_cookie.get("secure")
        if secure:
            cookie.secure = secure
        cookie_type = object_cookie.get("type")
        if cookie_type:
            cookie.type_cookie = cookie_type
        expires = object_cookie.get("expires")
        if expires:
            cookie.expires = dateparser.parse(expires)
        cookie.save()

    def __import_cs_beaconing(
        self, invest: entity.Investigation, object_cs_beaconing: MISPObject
    ):
        cs_malware = entity.Malware(name="Cobalt Strike").save()

        sha256_attr = object_cs_beaconing.get_attributes_by_relation("sh256")
        sha256_obs = None
        if sha256_attr:
            sha256_obs = self.attr_misp_to_yeti(
                invest,
                sha256_attr[0],  # type: ignore
                description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )
            cs_malware.link_to(sha256_obs, "file", "sha256")

        sha1_attr = object_cs_beaconing.get_attributes_by_relation("sha1")
        sha1_obs = None
        if sha1_obs:
            sha1_obs = self.attr_misp_to_yeti(
                invest,
                sha1_attr[0],  # type: ignore
                description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )
            cs_malware.link_to(sha1_obs, "file", "sha1")

        md5_attr = object_cs_beaconing.get_attributes_by_relation("md5")
        md5_obs = None
        if md5_attr:
            md5_obs = self.attr_misp_to_yeti(
                invest,
                md5_attr[0],  # type: ignore
                description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )
            cs_malware.link_to(md5_obs, "file", "md5")

        config_cs = None
        if sha256_obs:
            config_cs = observable.file.File(value=f"FILE:{sha256_obs.value}").save()
        elif sha1_obs and not config_cs:
            config_cs = observable.file.File(value=f"FILE:{sha1_obs.value}").save()
        elif md5_obs and not config_cs:
            config_cs = observable.file.File(value=f"FILE:{md5_obs.value}").save()
        if config_cs:
            if md5_obs:
                config_cs.md5 = md5_obs.value

            if sha1_obs:
                config_cs.sha1 = sha1_obs.value

            cs_malware.link_to(config_cs, "file", "file")

            invest.link_to(
                cs_malware,
                "imported_by_misp",
                f"misp {self.misp_event['Orgc']['name']}",
            )
        asn_attr = object_cs_beaconing.get_attributes_by_relation("asn")
        if asn_attr:
            asn = self.attr_misp_to_yeti(
                invest,
                asn_attr[0],  # type: ignore
                description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )
            cs_malware.link_to(asn, "part_of", "asn")

        geo = object_cs_beaconing.get("geo")
        country = None
        if geo:
            country = entity.Location(name=geo, country=geo)
            country.set_country_code_by_name(country.name)
            country.save()
            invest.link_to(
                country,
                "imported_by_misp",
                f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )

        c2_url = filter(lambda x: x["type"] == "c2", object_cs_beaconing["Attribute"])
        for url in c2_url:
            obs_yeti = self.attr_misp_to_yeti(
                invest, url, description=f"misp {self.misp_event['Orgc']['name']}"
            )
            obs_yeti.link_to(asn, "part_of", "asn")
            cs_malware.link_to(obs_yeti, "downloaded", "c2")

        ips = filter(lambda x: x["type"] == "ip", object_cs_beaconing["Attribute"])
        for ip_value in ips:
            ip = self.attr_misp_to_yeti(
                invest,
                ip_value,
                description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )
            ip.link_to(asn, "part_of", "asn")
            if country:
                ip.link_to(country, "located_at", "location")
            cs_malware.link_to(ip, "communicate_with", "ip")

        city = object_cs_beaconing.get("city")
        if city:
            location = entity.Location(name=city, city=city).save()
            ip.link_to(location, "located_at", "location")
            invest.link_to(
                location,
                "imported_by_misp",
                f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )

        jar_md5 = object_cs_beaconing.get_attributes_by_relation("jar-md5")
        if jar_md5:
            app_c2 = self.attr_misp_to_yeti(
                invest,
                jar_md5[0],
                description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )
        cs_malware.link_to(app_c2, "jar-md5", "MD5 of adversary cobaltstrike.jar file")

        watermark = object_cs_beaconing.get_attributes_by_relation("watermark")
        watermark_yeti = None
        if watermark:
            watermark_yeti = self.attr_misp_to_yeti(
                invest,
                watermark[0],
                description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )
            watermark_yeti.link_to(app_c2, "watermarked", "watermark")
            cs_malware.link_to(watermark_yeti, "watermarked", "watermark")

    def __import_domain_ip(
        self, invest: entity.Investigation, object_domain_ip: MISPObject
    ):
        domain_attr = object_domain_ip.get_attributes_by_relation("domain")
        ip_attr = object_domain_ip.get_attributes_by_relation("ip")
        hostname_attr = object_domain_ip.get_attributes_by_relation("hostname")
        ip_obj = None
        domain_obj = None
        hostname_obj = None

        if domain_attr:
            domain_obj = self.attr_misp_to_yeti(
                invest,
                domain_attr[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
        if ip_attr:
            ip_obj = self.attr_misp_to_yeti(
                invest,
                ip_attr[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
        if hostname_attr:
            hostname_obj = self.attr_misp_to_yeti(
                invest,
                hostname_attr[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
        if hostname_obj and domain_obj and ip_obj:
            domain_obj.link_to(hostname_obj, "resolved_to", "hostname")
            domain_obj.link_to(ip_obj, "resolved_to", "ip")
            hostname_obj.link_to(ip_obj, "resolved_to", "ip")

        elif domain_obj and ip_obj and not hostname_obj:
            domain_obj.link_to(ip_obj, "resolved_to", "ip")
        elif not domain_obj and ip_obj and hostname_obj:
            hostname_obj.link_to(ip_obj, "resolved_to", "ip")

        context = {}
        last_seen = object_domain_ip.get("last-seen")
        if last_seen:
            context["last-seen"] = last_seen

        first_seen = object_domain_ip.get("first-seen")
        if first_seen:
            context["first-seen"] = first_seen

        description = object_domain_ip.get("text")
        if description:
            context["description"] = description

        if hostname_obj:
            hostname_obj.add_context(f"misp {self.misp_event['Orgc']['name']}", context)
        if domain_obj:
            domain_obj.add_context(f"misp {self.misp_event['Orgc']['name']}", context)
        if ip_obj:
            ip_obj.add_context(f"misp {self.misp_event['Orgc']['name']}", context)

    def __import_dns_record(
        self, invest: entity.Investigation, object_dns_record: MISPObject
    ):
        queried_domain = object_dns_record.get_attributes_by_relation("queried-domain")[
            0
        ]
        queried_obj = self.attr_misp_to_yeti(
            invest,
            queried_domain,
            description=f"misp {self.misp_event['Orgc']['name']}",
        )

        a_record = object_dns_record.get_attributes_by_relation("a-record")
        aaaa_record = object_dns_record.get_attributes_by_relation("aaaa-record")
        cname_record = object_dns_record.get_attributes_by_relation("cname-record")
        mx_record = object_dns_record.get_attributes_by_relation("mx-record")
        ns_record = object_dns_record.get_attributes_by_relation("ns-record")
        soa_record = object_dns_record.get_attributes_by_relation("soa-record")
        txt_record = object_dns_record.get_attributes_by_relation("txt-record")
        spf_record = object_dns_record.get_attributes_by_relation("spf-record")
        ptr_record = object_dns_record.get_attributes_by_relation("ptr-record")
        srv_record = object_dns_record.get_attributes_by_relation("srv-record")
        description = object_dns_record.get_attributes_by_relation("Text")

        context = {}
        if description:
            context["description"] = description[0]["value"]

        if a_record:
            a_red_obj = self.attr_misp_to_yeti(
                invest,
                a_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            if context:
                a_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )
            queried_obj.link_to(a_red_obj, "resolved_to", "ip")
        if aaaa_record:
            aaaa_red_obj = self.attr_misp_to_yeti(
                invest,
                aaaa_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            if context:
                aaaa_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )

            queried_obj.link_to(aaaa_red_obj, "resolved_to", "ip")
        if cname_record:
            cname_red_obj = self.attr_misp_to_yeti(
                invest,
                cname_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            if context:
                cname_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )
            queried_obj.link_to(cname_red_obj, "cname", "hostname")
        if mx_record:
            mx_red_obj = self.attr_misp_to_yeti(
                invest,
                mx_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            if context:
                mx_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )
            queried_obj.link_to(mx_red_obj, "mx", "hostname")
        if ns_record:
            ns_red_obj = self.attr_misp_to_yeti(
                invest,
                ns_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            if context:
                ns_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )

            queried_obj.link_to(ns_red_obj, "ns", "hostname")
        if soa_record:
            soa_red_obj = self.attr_misp_to_yeti(
                invest,
                soa_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            queried_obj.link_to(soa_red_obj, "soa", "hostname")
            if context:
                soa_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )

        if txt_record:
            txt_red_obj = self.attr_misp_to_yeti(
                invest,
                txt_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )

            if txt_red_obj:
                queried_obj.link_to(txt_red_obj, "txt", "hostname")
                if context:
                    txt_red_obj.add_context(
                        f"misp {self.misp_event['Orgc']['name']}", context
                    )
        if spf_record:
            spf_red_obj = self.attr_misp_to_yeti(
                invest,
                spf_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            queried_obj.link_to(spf_red_obj, "spf", "hostname")
            if context:
                spf_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )
        if ptr_record:
            ptr_red_obj = self.attr_misp_to_yeti(
                invest,
                ptr_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            queried_obj.link_to(ptr_red_obj, "ptr", "hostname")
            if context:
                ptr_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )
        if srv_record:
            srv_red_obj = self.attr_misp_to_yeti(
                invest,
                srv_record[0],
                description=f"misp {self.misp_event['Orgc']['name']}",
            )
            queried_obj.link_to(srv_red_obj, "srv", "hostname")
            if context:
                srv_red_obj.add_context(
                    f"misp {self.misp_event['Orgc']['name']}", context
                )

    def __import_directory(self, invest: entity.Investigation, obj_path: MISPObject):
        path_attr = obj_path.get_attributes_by_relation("path")[0]
        path = observable.path.Path(value=path_attr["value"])

        creation_time = obj_path.get_attributes_by_relation("creation-time")
        if creation_time:
            path.creation_time = creation_time[0]["value"]

        modification_time = obj_path.get_attributes_by_relation("modification-time")
        if modification_time:
            path.modification_time = modification_time[0]["value"]
        access_time = obj_path.get_attributes_by_relation("access-time")
        if access_time:
            path.access_time = access_time[0]["value"]

        path_encoding = obj_path.get_attributes_by_relation("path-encoding")
        if path_encoding:
            path.path_encoding = path_encoding[0]["value"]
        path = path.save()
        invest.link_to(
            path, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}"
        )

    def __import_email(self, invest: entity.Investigation, object_email: MISPObject):
        from_email_list = []
        list_to_emails = []
        list_cc_emails = []
        list_bbc_emails = []
        from_domains_list = []
        list_ips_src = []
        list_to_display_names = []
        attachment_list = []
        from_attr = object_email.get_attributes_by_relation("from")

        if from_attr:
            from_email_list = [
                self.attr_misp_to_yeti(
                    invest,
                    email_from,
                    description=f"misp {self.misp_event['Orgc']['name']}",
                )
                for email_from in from_attr
            ]

        bbc_email = object_email.get_attributes_by_relation("bcc-email")

        if bbc_email:
            list_bbc_emails = [
                self.attr_misp_to_yeti(
                    invest,
                    email_bcc,
                    description=f"misp {self.misp_event['Orgc']['name']}",
                )
                for email_bcc in bbc_email
            ]

        cc_attr = object_email.get_attributes_by_relation("cc-email")
        if cc_attr:
            list_cc_emails = [
                self.attr_misp_to_yeti(
                    invest,
                    email_cc,
                    description=f"misp {self.misp_event['Orgc']['name']}",
                )
                for email_cc in cc_attr
            ]

        to_attr = object_email.get_attributes_by_relation("to")
        if to_attr:
            list_to_emails = [
                self.attr_misp_to_yeti(
                    invest,
                    email_to,
                    description=f"misp {self.misp_event['Orgc']['name']}",
                )
                for email_to in to_attr
            ]
        to_display_name_attr = object_email.get_attributes_by_relation(
            "to-display-name"
        )
        if to_display_name_attr:
            list_to_display_names = [
                observable.generic_observable.GenericObservable(
                    value=display_name["value"]
                ).save()
                for display_name in to_display_name_attr
            ]
        for email in list_to_emails:
            for display_name in list_to_display_names:
                email.link_to(display_name, "display_name", "display_name")

        from_domain_attrs = object_email.get_attributes_by_relation("from-domain")
        if from_domain_attrs:
            from_domains_list = [
                self.attr_misp_to_yeti(
                    invest,
                    domain,
                    description=f"misp {self.misp_event['Orgc']['name']}",
                )
                for domain in from_domain_attrs
            ]

        ips_src_attr = object_email.get_attributes_by_relation("ip-src")
        if ips_src_attr:
            list_ips_src = [
                self.attr_misp_to_yeti(
                    invest,
                    ip_src,
                    description=f"misp {self.misp_event['Orgc']['name']}",
                )
                for ip_src in ips_src_attr
            ]
        for domain in from_domains_list:
            for ip in list_ips_src:
                domain.link_to(ip, "misp", "ip")

        subject_attr = object_email.get_attributes_by_relation("subject")
        ## Add subjects for all emails
        if subject_attr:
            for index, subject in enumerate(subject_attr):
                for email in from_email_list:
                    email.add_context("misp", {f"subject {index}": subject["value"]})
                for email in list_to_emails:
                    email.add_context("misp", {f"subject {index}": subject["value"]})
                for email in list_cc_emails:
                    email.add_context("misp", {"fsubject {index}": subject["value"]})
                for email in list_bbc_emails:
                    email.add_context("misp", {f"subject {index}": subject["value"]})

        ## Add send date to all emails
        send_date = object_email.get_attributes_by_relation("send-date")
        if send_date:
            for email in from_email_list:
                email.add_context("misp", {"send-date": send_date[0]["value"]})
            for email in list_to_emails:
                email.add_context("misp", {"send-date": send_date[0]["value"]})
            for email in list_cc_emails:
                email.add_context("misp", {"send-date": send_date[0]["value"]})
            for email in list_bbc_emails:
                email.add_context("misp", {"send-date": send_date[0]["value"]})

        received_date = object_email.get_attributes_by_relation("received-date")

        ## add receive date to all emails
        if received_date:
            for email in from_email_list:
                email.add_context("misp", {"received-date": received_date[0]["value"]})
            for email in list_to_emails:
                email.add_context("misp", {"received-date": received_date[0]["value"]})
            for email in list_cc_emails:
                email.add_context("misp", {"received-date": received_date[0]["value"]})
            for email in list_bbc_emails:
                email.add_context("misp", {"received-date": received_date[0]["value"]})

        user_agent_attr = object_email.get_attributes_by_relation("user-agent")
        if user_agent_attr:
            user_agent_obs = observable.user_agent.UserAgent(
                value=user_agent_attr[0]["value"]
            ).save()
            invest.link_to(
                user_agent_obs,
                "imported_by_misp",
                f"misp {self.misp_event['Orgc']['name']}",
            )

        attachment_attr = object_email.get_attributes_by_relation("attachment")
        if attachment_attr:
            attachment_list = [
                self.attr_misp_to_yeti(
                    invest,
                    attachment,
                    description=f"misp {self.misp_event['Orgc']['name']}",
                )
                for attachment in attachment_attr
            ]

        for email in from_email_list:
            email.link_to(user_agent_obs, "sent_by", "user_agent")

        ## add attachement at all emails
        for attachment in attachment_list:
            for email in list_to_emails:
                email.link_to(attachment, "sent_to", "attachment")
            for email in list_cc_emails:
                email.link_to(attachment, "sent_to", "attachment")
            for email in list_bbc_emails:
                email.link_to(attachment, "sent_to", "attachment")
            for email in from_email_list:
                email.link_to(attachment, "sent_by", "attachment")

        ## add IP src to ips_src
        for email in from_email_list:
            for ip in list_ips_src:
                email.link_to(ip, "sent_by", "ip")

        # Create Link between emails
        for email_from in from_email_list:
            for email_to in list_to_emails:
                email_from.link_to(email_to, "sent_to", "email")
        for email_cc in list_cc_emails:
            for email_to in list_to_emails:
                email_cc.link_to(email_to, "sent_to", "email")

        for email_bcc in list_bbc_emails:
            for email_to in list_to_emails:
                email_bcc.link_to(email_to, "sent_to", "email")

        for email_bcc in list_bbc_emails:
            for email_to in list_to_emails:
                email_bcc.link_to(email_to, "sent_to", "email")

    ## to detail the use case
    def __import_exploit_poc(
        self, invest: entity.Investigation, object_exploit_poc: MISPObject
    ):
        poc_attr = object_exploit_poc.get_attributes_by_relation("poc")
        print(poc_attr)

    def __import_exploit(
        self, invest: entity.Investigation, object_exploit: MISPObject
    ):
        exploit_attr = object_exploit.get_attributes_by_relation("exploit")
        filename_attr = object_exploit.get_attributes_by_relation("filename")
        exploit_as_attachment = object_exploit.get_attributes_by_relation(
            "exploit-as-attachment"
        )

        exploit_obj = None
        if exploit_attr:
            exploit_obj = entity.Exploit(name=exploit_attr[0]["value"]).save()
            for file_attr in filename_attr:
                file_obj = observable.file.File(value=filename_attr[0]["value"]).save()
                exploit_obj.link_to(file_obj, "exploit", "file")
            if exploit_as_attachment:
                exploit_as_att_obj = observable.generic_observable.GenericObservable(
                    value=exploit_as_attachment[0]["value"]
                ).save()
                exploit_obj.link_to(exploit_as_att_obj, "exploit", "file")

        elif not exploit_obj and filename_attr:
            exploit_obj = entity.Exploit(name=filename_attr[0]["value"]).save()
            for file_attr in filename_attr[1:]:
                file_obj = observable.file.File(value=file_attr["value"]).save()
                exploit_obj.link_to(file_obj, "exploit", "file")
            if exploit_as_attachment:
                exploit_as_att_obj = observable.generic_observable.GenericObservable(
                    value=exploit_as_attachment[0]["value"]
                ).save()
                exploit_obj.link_to(exploit_as_att_obj, "exploit", "file")

        elif not exploit_obj and exploit_as_attachment:
            exploit_obj = entity.Exploit(name=exploit_as_attachment[0]["value"])
            for file_attr in filename_attr:
                file_obj = observable.file.File(value=file_attr["value"]).save()
                exploit_obj.link_to(file_obj, "exploit", "file")

        description = object_exploit.get_attributes_by_relation("description")

        if description:
            exploit_obj.description = description[0]["value"]

        accessibility = object_exploit.get_attributes_by_relation("accessibility")
        if accessibility:
            exploit_obj.accessibility = accessibility[0]["value"]

        software_attr = object_exploit.get_attributes_by_relation("software")
        if software_attr:
            exploit_obj.software = software_attr[0]["value"]

        level_attr = object_exploit.get_attributes_by_relation("level")
        if level_attr:
            exploit_obj.level = level_attr[0]["value"]

        reference_attr = object_exploit.get_attributes_by_relation("reference")
        if reference_attr:
            exploit_obj.reference = reference_attr[0]["value"]

        cve_id = object_exploit.get_attributes_by_relation("cve-id")

        if cve_id:
            vulnerability = entity.Vulnerability(name=cve_id[0]["value"]).save()
            exploit_obj.link_to(vulnerability, "exploit", "vulnerability")  # type: ignore

        context = {}

        zero_day_today = object_exploit.get_attributes_by_relation("0day-today-id")
        if zero_day_today:
            context["0day-today-id"] = zero_day_today[0]["value"]

        credit = object_exploit.get_attributes_by_relation("credit")
        if credit:
            context["credit"] = credit[0]["value"]

        comment = object_exploit.get_attributes_by_relation("comment")
        if comment:
            context["comment"] = comment[0]["value"]

        exploitdb_id = object_exploit.get_attributes_by_relation("exploitdb-id")

        for index, exploit in enumerate(exploitdb_id):
            context[f"exploitdb-id {index}"] = exploit["value"]
        title = object_exploit.get_attributes_by_relation("title")
        if title:
            context["title"] = title[0]["value"]

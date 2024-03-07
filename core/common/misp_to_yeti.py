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
        }

    def attr_misp_to_yeti(
        self,
        invest: entity.Investigation,
        attribute: MISPAttribute,
        description: str = "",
    ) -> observable.Observable:  # type: ignore
        if attribute.get("type") in MISP_Attribute_TO_IMPORT:
            obs_yeti = observable.TYPE_MAPPING[
                MISP_Attribute_TO_IMPORT[attribute.get("type")]  # type: ignore
            ](value=attribute.get("value")).save()
            tags = attribute.get("Tag")
            if tags:
                obs_yeti.tag([t["name"] for t in tags])
            invest.link_to(obs_yeti, "imported_by_misp", description)
            print(f"Attribute {attribute.get('value')} imported")

        else:
            obs_yeti = observable.generic_observable.GenericObservable(
                value=attribute.get("value")
            ).save()  # type: ignore
        return obs_yeti

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
                print(f"Attribute {attr} not imported")

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
                print(f"Attribute {attribute_misp} not imported")
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

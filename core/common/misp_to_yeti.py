import logging
from datetime import timedelta

import dateparser
import pycountry

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
    "asn": observable.ObservableType.asn,
    "cookie": observable.ObservableType.cookie,
    "other": observable.ObservableType.generic,
}


class MispToYeti:
    def __init__(self, misp_event):
        self.misp_event = misp_event
        self.func_by_type = {
            "asn": self.__import_asn_object,
            "av-signature": self.__import_av_signature,
            "btc-wallet": self.__import_btc_wallet,
            "c2-list": self.__import_c2_list,
            "crowdsec-ip-context": self.__import_crowdsec_ip_context,
            "command-line": self.__import_commande_line,
            "cookie": self.__import_cookie,
        }

    def attr_misp_to_yeti(
        self, invest: entity.Investigation, attribute: dict, description: str = ""
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
            return obs_yeti

    def add_context_by_misp(
        self, attribute_misp: dict, obs_yeti: observable.Observable
    ):
        context = {}
        context["Org"] = self.misp_event["Org"]["name"]

        if attribute_misp.get("comment"):
            context["comment"] = attribute_misp.get("comment")
        obs_yeti.add_context("misp", context)

    def add_obs(self, invest: entity.Investigation, obs_misp: dict):
        for attr in obs_misp["Attribute"]:
            obs_yeti = self.attr_misp_to_yeti(invest, attr)

            if obs_yeti:
                self.add_context_by_misp(attr, obs_yeti)
                yield obs_yeti
            else:
                print(f"Attribute {attr} not imported")

    def obs_misp_to_yeti(self, invest: entity.Investigation, object_misp: dict):
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
        tags = self.misp_event.get("Tag")
        if tags:
            invest.tag([t["name"] for t in tags])
        invest.description = (
            f"Org {self.misp_event['Orgc']['name']} Event id: {self.misp_event['id']}"
        )
        for object_misp in self.misp_event["Object"]:
            self.obs_misp_to_yeti(invest, object_misp)

        for attribute_misp in self.misp_event["Attribute"]:
            obs_yeti = self.attr_misp_to_yeti(invest, attribute_misp)
            if obs_yeti:
                self.add_context_by_misp(attribute_misp, obs_yeti)
            else:
                print(f"Attribute {attribute_misp} not imported")
        invest.save()

    def __import_av_signature(
        self, invest: entity.Investigation, object_av_signature: dict
    ):
        av_sig = indicator.av_signature(
            name=object_av_signature["signature"],
            software=object_av_signature["software"],
            diamond=indicator.DiamondModel.capability,
            pattern=object_av_signature["signature"],
            location="misp",
        )
        av_sig.description = object_av_signature["description"]
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

    def __import_btc_wallet(self, invest: entity.Investigation, object_btc: dict):
        btc_address = list(
            filter(lambda x: x["type"] == "wallet-address", object_btc["Attribute"])
        )[0]
        btc = self.attr_misp_to_yeti(
            invest, btc_address, description=f"misp {self.misp_event['Orgc']['name']}"
        )
        context = {}
        if object_btc["BTC_received"]:
            context["BTC_received"] = object_btc["BTC_received"]
        if object_btc["BTC_sent"]:
            context["BTC_sent"] = object_btc["BTC_sent"]
        if object_btc["BTC_balance"]:
            context["BTC_balance"] = object_btc["BTC_balance"]
        if object_btc["time"]:
            context["time"] = object_btc["time"]
        if context:
            btc.add_context(f"misp {self.misp_event['Orgc']['name']} ", context)
        invest.link_to(
            btc, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}"
        )
        btc.save()

    def __import_c2_list(self, invest: entity.Investigation, object_c2_list: dict):
        list_c2_ip = filter(lambda x: x["type"] == "c2-ip", object_c2_list["Attribute"])
        list_c2_domain = filter(
            lambda x: x["type"] == "c2-ipport", object_c2_list["Attribute"]
        )
        for c2 in list_c2_ip:
            obs_yeti = self.attr_misp_to_yeti(
                invest, c2, description=f"misp {self.misp_event['Orgc']['name']}"
            )
            obs_yeti.link_to_tag(object_c2_list["threat"], timedelta(days=30))
        for c2 in list_c2_domain:
            ip, port = c2["value"].split("|")
            obs_yeti = observable.TYPE_MAPPING[MISP_Attribute_TO_IMPORT["ip-src"]](
                value=ip
            )
            obs_yeti.link_to_tag(object_c2_list["threat"], timedelta(days=30))
            obs_yeti.add_context("misp", {"port": port})

    def __import_crowdsec_ip_context(
        self, invest: entity.Investigation, object_crowdsec_ip: dict
    ):
        ip = self.attr_misp_to_yeti(
            invest,
            object_crowdsec_ip["ip"],
            description=f"misp {self.misp_event['Orgc']['name']} CrowdSec",
        )

        as_num = object_crowdsec_ip.get("as_num")
        if as_num:
            asn = self.attr_misp_to_yeti(invest, as_num)
            ip.link_to(asn, "part_of", "asn")

        context = {}
        attack_details = object_crowdsec_ip.get("attack-details")

        if attack_details:
            context["attack-details"] = attack_details

        background_noise = object_crowdsec_ip.get("background-noise")
        if background_noise:
            context["background-noise"] = background_noise

        behaviors = object_crowdsec_ip.get("behaviors")
        if behaviors:
            context["behaviors"] = behaviors

        city = object_crowdsec_ip.get("city")
        country = object_crowdsec_ip.get("country")
        country_code = object_crowdsec_ip.get("country_code")

        if city or country or country_code:
            if city:
                location = entity.Location(name=city, city=city).save()

            if country:
                location = entity.Location(name=country, country=country).save()
                location.set_country_code_by_name(country)
            if country_code:
                country_name = pycountry.countries.get(alpha_2=country_code).name
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
        dst_port = object_crowdsec_ip.get("dst-port")
        if dst_port:
            context["dst_port"] = dst_port

        ip_range_scope = object_crowdsec_ip.get("ip-range-scope")
        if ip_range_scope:
            context["ip-range-scope"] = ip_range_scope

        trust = object_crowdsec_ip.get("trust")
        if trust:
            context["trust"] = trust

        ip_range = object_crowdsec_ip.get("ip-range")
        if ip_range:
            cidr_obs = observable.cidr.CIDR(value=ip_range).save()  # type: ignore
            ip.link_to(cidr_obs, "part_of", "subnet")
            invest.link_to(
                cidr_obs,
                "imported_by_misp",
                f"misp {self.misp_event['Orgc']['name']} CrowdSec",
            )

        ip.add_context(f"misp {self.misp_event['Orgc']['name']} CrowdSec", context)

        reverse_dns = object_crowdsec_ip.get("reverse_dns")
        if reverse_dns:
            hostname = self.attr_misp_to_yeti(
                invest,
                reverse_dns,
                description=f"misp {self.misp_event['Orgc']['name']} CrowdSec",
            )
            ip.link_to(hostname, "resolved_to", "hostname")

    def __import_commande_line(
        self, invest: entity.Investigation, object_command_line: dict
    ):
        cmd_line = object_command_line["value"]
        cmd_line = observable.command_line.CommandLine(value=cmd_line).save()

        description = object_command_line.get("description")
        context = {}
        if description:
            context["description"] = description
        if context:
            cmd_line.add_context(f"misp {self.misp_event['Orgc']['name']}", context)
        invest.link_to(
            cmd_line, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}"
        )

    def __import_cookie(self, invest: entity.Investigation, object_cookie: dict):
        name = object_cookie["name"]

        cookie_attr = object_cookie["cookie"]
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
        self, invest: entity.Investigation, object_cs_beaconing: dict
    ):
        cs_malware = entity.Malware(name="Cobalt Strike").save()
        sha256_obs = self.attr_misp_to_yeti(
            invest,
            object_cs_beaconing["sha256"],
            description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
        )
        sha1_obs = self.attr_misp_to_yeti(
            invest,
            object_cs_beaconing["sha1"],
            description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
        )
        md5_obs = self.attr_misp_to_yeti(
            invest,
            object_cs_beaconing["md5"],
            description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
        )
        file_cs = observable.file.File(value=f"FILE:{sha256_obs}").save()
        file_cs.md5 = md5_obs.value
        file_cs.sha1 = sha1_obs.value
        cs_malware.link_to(sha256_obs, "file", "sha256")
        cs_malware.link_to(sha1_obs, "file", "sha1")
        cs_malware.link_to(md5_obs, "file", "md5")
        cs_malware.link_to(file_cs, "file", "file")
        file_cs.link_to(sha256_obs, "file", "sha256")
        file_cs.link_to(sha1_obs, "file", "sha1")
        file_cs.link_to(md5_obs, "file", "md5")

        invest.link_to(
            cs_malware, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}"
        )
        asn = self.attr_misp_to_yeti(invest, object_cs_beaconing["asn"])
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

        jar_md5 = object_cs_beaconing["jar-md5"]
        app_c2 = self.attr_misp_to_yeti(
            invest,
            jar_md5,
            description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
        )
        cs_malware.link_to(app_c2, "jar-md5", "MD5 of adversary cobaltstrike.jar file")

        watermark = object_cs_beaconing.get("watermark")
        watermark_yeti = None
        if watermark:
            watermark_yeti = self.attr_misp_to_yeti(
                invest,
                watermark,
                description=f"misp {self.misp_event['Orgc']['name']} Cobalstrike Beaconing",
            )
            watermark_yeti.link_to(app_c2, "watermarked", "watermark")
            cs_malware.link_to(watermark_yeti, "watermarked", "watermark")

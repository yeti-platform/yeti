import logging
from datetime import timedelta
from core.schemas import entity, observable, indicator

MISP_Attribute_TO_IMPORT = {
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
    "btc": observable.ObservableType.wallet,
    "email": observable.ObservableType.email,
    "filename": observable.ObservableType.file,
    "regkey": observable.ObservableType.registry_key,
    "asn": observable.ObservableType.asn,
}

class MispToYeti:

    def __init__(self, misp_event):
        self.misp_event = misp_event
        self.func_by_type = {
        "asn": self.__import_asn_object,
        "av-signature": self.__import_av_signature,
        "btc-wallet": self.__import_btc_wallet,
        "c2-list": self.__import_c2_list,
    }

    def attr_misp_to_yeti(
        self, invest: entity.Investigation, attribute: dict
    ) -> observable.Observable: # type: ignore
        if attribute.get("type") in MISP_Attribute_TO_IMPORT:
            obs_yeti = observable.TYPE_MAPPING[
                MISP_Attribute_TO_IMPORT[attribute.get("type")] # type: ignore
            ](value=attribute.get("value")).save()
            invest.link_to(obs_yeti, "imported_by_misp",f"misp {self.misp_event['Orgc']['name']}")
            print(f"Attribute {attribute.get('value')} imported")
            return obs_yeti

    def add_context_by_misp(
        self, attribute_misp: dict, event: dict, obs_yeti: observable.Observable
    ):
        context = {}
        event_id = attribute_misp.get("event_id")
        context["Org"] = event["Org"]["name"]
        context["event_id"] = event_id
        if attribute_misp.get("comment"):
            context["comment"] = attribute_misp.get("comment")

        obs_yeti.add_context("misp", context)
    
    def add_obs(self,invest: entity.Investigation,obs_misp: dict):
        for attr in obs_misp["Attribute"]:
            obs_yeti = self.attr_misp_to_yeti(invest,attr)
        
            if obs_yeti:
                self.add_context_by_misp(attr, obs_misp, obs_yeti)
                yield obs_yeti
            else:
                print(f"Attribute {attr} not imported")
    
    def obs_misp_to_yeti(self,invest: entity.Investigation, object_misp: dict):
        if object_misp["name"] in self.func_by_type:
            self.func_by_type[object_misp["name"]](invest,object_misp)
        else:
            for obs_yeti in self.add_obs(invest,object_misp):
                invest.link_to(obs_yeti, "imported_by_misp",f"misp {self.misp_event['Orgc']['name']}")
            

    def misp_to_yeti(self):
        invest = entity.Investigation(name=self.misp_event["info"]).save()

        if self.misp_event["Tag"]:
            invest.tag(self.misp_event["Tag"])
            

        for object_misp in self.misp_event["Object"]:
            self.obs_misp_to_yeti(invest,object_misp)

        for attribute_misp in self.misp_event["Attribute"]:
            obs_yeti = self.attr_misp_to_yeti(invest,attribute_misp)
            if obs_yeti:
                self.add_context_by_misp(attribute_misp, self.misp_event, obs_yeti)
            else:
                print(f"Attribute {attribute_misp} not imported")
        invest.save()

    def __import_av_signature(self, invest: entity.Investigation,object_av_signature: dict):
        av_sig = indicator.av_signature(name=object_av_signature["signature"],software=object_av_signature["software"]).save()
        av_sig.description = object_av_signature["description"]
        av_sig.save()
        invest.link_to(av_sig, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}")

    def __import_asn_object(self, invest: entity.Investigation,object_asn: dict):
        asn = observable.asn.ASN(value=object_asn["asn"]).save()
        context = {}

        if subnet := object_asn.get("subnet"):
            try:
                subnet = observable.cidr.CIDR(value=subnet).save()
                asn.link_to(subnet, "part_of", "subnet")
            except ValueError:
                logging.error(f"Invalid subnet: {subnet}")

        if object_asn['last-seen']:
            context["last-seen"] = object_asn['last-seen']
        if object_asn['first-seen']:
            context["first-seen"] = object_asn['first-seen']
        if object_asn['description']:
            context["description"] = object_asn['description']
        if object_asn['country']:
            context["country"] = object_asn['country']
        
        asn.add_context(f"misp {self.misp_event['Orgc']['name']} ", context)
        
        invest.link_to(asn, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}")
        
    def __import_btc_wallet(self, invest: entity.Investigation,object_btc: dict):
        btc = observable.wallet.Wallet(value=object_btc["wallet-address"]).save()
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
        invest.link_to(btc, "imported_by_misp", f"misp {self.misp_event['Orgc']['name']}")
    
    
    def __import_c2_list(self, invest: entity.Investigation,object_c2_list: dict):
            list_c2_ip  = filter(lambda x: x["type"] == "c2-ip", object_c2_list["Attribute"])
            list_c2_domain  = filter(lambda x: x["type"] == "c2-ipport", object_c2_list["Attribute"])
            for c2 in list_c2_ip:
                obs_yeti=self.attr_misp_to_yeti(invest,c2)
                obs_yeti.link_to_tag(object_c2_list['threat'],timedelta(days=30))        
            for c2 in list_c2_domain:
                ip,port = c2["value"].split("|")
                obs_yeti=observable.TYPE_MAPPING[MISP_Attribute_TO_IMPORT["ip-src"]](value=ip)
                obs_yeti.link_to_tag(object_c2_list['threat'],timedelta(days=30))
                obs_yeti.add_context("misp",{"port":port})

        

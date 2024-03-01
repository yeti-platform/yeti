import logging

from core.schemas import entity, observable

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

    def obs_misp_to_yeti(self,invest: entity.Investigation, object_misp: dict):
        if object_misp["name"] in self.func_by_type:
            self.func_by_type[object_misp["name"]](invest,object_misp)
        else:
            print(f"Object {object_misp['name']} not imported")        

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

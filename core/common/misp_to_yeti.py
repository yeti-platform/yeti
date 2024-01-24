from core.schemas import observable
MISP_TYPES_TO_IMPORT = {
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
    }

class MispToYeti:
    
    def __init__(self, misp_event):
        self.misp_event = misp_event

    def attr_misp_to_yeti(self, attribute:dict) -> observable.Observable:
        if attribute.get("type") in MISP_TYPES_TO_IMPORT:
            obs_yeti = observable.TYPE_MAPPING[MISP_TYPES_TO_IMPORT[attribute.get("type")]](value=attribute.get("value")).save()
            print(f"Attribute {attribute.get('value')} imported")
            return obs_yeti

    def add_context_by_misp(self,attribute_misp:dict,event:dict,obs_yeti:observable.Observable)-> dict:
        context = {}
        event_id = attribute_misp.get("event_id")
        context["Org"] = event.get("Org")['name']
        context['event_id'] = event_id
        if attribute_misp.get("comment"):
            context['comment'] = attribute_misp.get("comment")
        
        obs_yeti.add_context('misp',context)

    def obs_misp_to_yeti(self, object_misp:dict):
        objs_type = object_misp.get("type")
        links = []
        for attr in object_misp.get("Attribute"):
            obs_yeti = self.attr_misp_to_yeti(attr)
            links.append(obs_yeti)     
        obs_yeti = links.pop()
        for obj_to_link in links:
            obs_yeti.link_to(obj_to_link,f'link_by_misp_{objs_type}','misp')

    def misp_to_yeti(self):
        for object_misp in self.misp_event.get("Object"):
            self.obs_misp_to_yeti(object_misp)
            
        for attribute_misp in self.misp_event.get("Attribute"):
            obs_yeti = self.attr_misp_to_yeti(attribute_misp)
            if obs_yeti:
                self.add_context_by_misp(attribute_misp,self.misp_event,obs_yeti)
            else:
                print(f"Attribute {attribute_misp} not imported")

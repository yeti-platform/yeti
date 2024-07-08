import logging
from datetime import timedelta
from io import StringIO

from idstools import rule

from core import taskmanager
from core.schemas import entity, indicator, task


class ETOpen(task.FeedTask):

    __SOURCE = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules"

    _defaults = {
        "frequency": timedelta(days=1),
        "name": "ETOpen",
        "description": "ETOpen ruleset",
        "source": __SOURCE,
    }

    def run(self):
        response = self._make_request(self.__SOURCE)
        
        if not response:
            return

        for line in  StringIO(response.text).readlines():
            if line.startswith("#"):
                continue
            self.analyze(line)
    
    def analyze(self, line:str):

        rule_suricata = rule.parse(line)
        if not rule_suricata:
            return

        rule_suricata["sid"]
        rule_suricata["msg"]

        ind_suricator = indicator.Suricata(
            name=rule_suricata["msg"],
            pattern = line,
            metadata=rule_suricata.metadata,
            diamond=indicator.DiamondModel.infrastructure,
        ).save()

        if 'cve' in ','.join(rule_suricata.metadata):
            for ind_cve in self.__extract_cve(rule_suricata.metadata):      
                ind_suricator.link_to(ind_cve, "affect", "ETOpen")
        
        if 'malware family' in ','.join(rule_suricata.metadata):
            
            for in_malware_family in self.__extract_malware_family(rule_suricata.metadata):
                ind_suricator.link_to(in_malware_family, "affect", "ETOpen")
        
        tags = self.__extract_tags(rule_suricata.metadata)
        if tags:
            ind_suricator.tag(tags)
        if 'mitre_tactic_id' in ','.join(rule_suricata.metadata):
            for ind_mitre_attack in self.__extract_mitre_attack(rule_suricata.metadata):
                if ind_mitre_attack:
                    ind_suricator.link_to(ind_mitre_attack, "affect", "ETOpen")
                
    def __extract_cve(self, metadata: list):
        for meta in metadata:
            if meta.startswith("cve"):
                _,cve = meta.split(" ")
                if '_' in cve:
                    cve = cve.replace("_", "-")
                ind_cve = entity.Vulnerability.find(name=cve)
                if not ind_cve:
                    ind_cve = entity.Vulnerability(name=cve).save()
                yield ind_cve
    
    def __extract_malware_family(self,metadata: list):
        for meta in metadata:
          if 'malware family' in meta:
            _,malware_family = meta.split(" ")
            ind_malware_family = entity.Malware.find(name=malware_family)
            if not ind_malware_family:
                ind_malware_family = entity.Malware(name=malware_family).save()
            yield ind_malware_family
    
    def __extract_tags(self, metadata: list):
        tags = []
        for meta in metadata:
            if meta.startswith("tag"):
                _,tag = meta.split(" ")
                tags.append(tag)
        return tags

    def __extract_mitre_attack(self, metadata: list):
        for meta in metadata:
            if "mitre_tactic_id" in meta:
                _,mitre_id = meta.split(" ")
                ind_mitre_attack = entity.AttackPattern.find(aliases=mitre_id)
                yield ind_mitre_attack

taskmanager.TaskManager.register_task(ETOpen)

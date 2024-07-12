import datetime
import logging
from datetime import timedelta, timezone
from io import StringIO

from idstools import rule

from core import taskmanager
from core.config.config import yeti_config
from core.schemas import entity, indicator, task


class ETOpen(task.FeedTask):
    _SOURCE = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules"

    _defaults = {
        "frequency": timedelta(days=1),
        "name": "ETOpen",
        "description": "ETOpen ruleset",
        "source": _SOURCE,
    }

    def run(self):
        response = self._make_request(self._SOURCE, no_cache=True)

        if not response:
            return

        for line in StringIO(response.text).readlines():
            if line.startswith("#"):
                continue
            rule_suricata = rule.parse(line)
            if not rule_suricata:
                continue
            self.analyze(rule_suricata)

    def analyze(self, rule_suricata):
        if not self._filter_rule(rule_suricata.metadata):
            return
        ind_suricata_rule = indicator.Suricata(
            name=rule_suricata["msg"],
            pattern=rule["raw"],
            metadata=rule_suricata.metadata,
            diamond=indicator.DiamondModel.infrastructure,
            sid=rule_suricata["sid"],
        ).save()
        for meta in rule_suricata.metadata:
            if "cve" in meta:
                ind_cve = self._extract_cve(rule_suricata.metadata)
                ind_suricata_rule.link_to(ind_cve, "affect", "ETOpen")

            if "malware family" in meta:
                in_malware_family = self._extract_malware_family(meta)
                ind_suricata_rule.link_to(in_malware_family, "affect", "ETOpen")

            if "mitre_tactic_id" in meta:
                ind_mitre_attack = self._extract_mitre_attack(rule_suricata.metadata)
                ind_suricata_rule.link_to(ind_mitre_attack, "affect", "ETOpen")
        tags = self._extract_tags(rule_suricata.metadata)
        if tags:
            ind_suricata_rule.tag(tags)

    def _extract_cve(self, meta: str):
        _, cve = meta.split(" ")
        if "_" in cve:
            cve = cve.replace("_", "-")
        ind_cve = entity.Vulnerability.find(name=cve)
        if not ind_cve:
            ind_cve = entity.Vulnerability(name=cve).save()
        return ind_cve

    def _extract_malware_family(self, meta: str):
        _, malware_family = meta.split(" ")
        ind_malware_family = entity.Malware.find(name=malware_family)
        if not ind_malware_family:
            ind_malware_family = entity.Malware(name=malware_family).save()
        return ind_malware_family

    def _extract_tags(self, metadata: list):
        tags = []
        for meta in metadata:
            if meta.startswith("tag"):
                _, tag = meta.split(" ")
                tags.append(tag)
        return tags

    def _extract_mitre_attack(self, meta: str):
        _, mitre_id = meta.split(" ")
        ind_mitre_attack, nb_ent = entity.Entity.filter(
            query_args={"type": entity.EntityType.attack_pattern},
            aliases=[("text", mitre_id)],
        )
        if nb_ent != 0:
            return ind_mitre_attack[0]

    def _filter_rule(self, metadata):
        if not self.last_run:
            for meta in metadata:
                if "created_at" in meta:
                    _, date_create = meta.split(" ")
                    start_time = yeti_config.get("etopen", "start_time")
                    try:
                        d_start_time = datetime.datetime.strptime(
                            start_time, "%Y-%m-%d"
                        )
                        logging.debug(f"start_time: {d_start_time}")
                        return d_start_time < datetime.datetime.strptime(
                            date_create, "%Y_%m_%d"
                        )
                    except ValueError:
                        raise ValueError(
                            f"Invalid start_time format {start_time}, please use the format %Y-%m-%d"
                        )
        else:
            for meta in metadata:
                if "updated_at" in meta:
                    _, date_update = meta.split(" ")
                    date_filtering = datetime.datetime.strptime(
                        date_update, "%Y_%m_%d"
                    ).replace(tzinfo=timezone.utc)
                    return self.last_run < date_filtering
        return False


taskmanager.TaskManager.register_task(ETOpen)

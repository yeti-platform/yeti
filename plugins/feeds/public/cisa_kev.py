import logging
from datetime import datetime, timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import entity, task


def _cves_as_dict(data):
    cves = dict()
    for vulnerability in data.get('vulnerabilities', []):
        cve_id = vulnerability.get('cve', {}).get('id', '')
        if not len(cve_id):
            continue
        cves[cve_id] = vulnerability
    return cves

def _extract_cvss_metric(cve):
    metrics = cve.get('metrics', {})
    metric_version = 0
    for metric in metrics:
        version = float('.'.join(list(metric.replace('cvssMetricV', ''))))
        if version > metric_version:
            metric_version = version
    if metric_version == 0:
        return 0, {}
    metric_str = str(metric_version).replace('.', '')
    cvss_metric = metrics.get(f'cvssMetricV{metric_str}', [])
    if len(cvss_metric):
        return metric_version, cvss_metric[0]
    else:
        return 0, {}

class CisaKEV(task.FeedTask):
    _defaults = {
        "frequency": timedelta(hours=1),
        "name": "CisaKEV",
        "description": "Imports the list of of known exploited vulnerablities published by CISA",
        "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    }

    CISA_SOURCE: ClassVar["str"] = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_SOURCE: ClassVar["str"] = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev"

    def run(self):
        response = self._make_request(self.CISA_SOURCE)
        if not response:
            logging.warning(f"Unable to fetch feed from {self.CISA_SOURCE}")
            return
        kev_json = response.json()
        response = self._make_request(self.NVD_SOURCE)
        if not response:
            logging.warning(f"Unable to fetch feed from {self.NVD_SOURCE}")
            nvd_json = {}
        else:
            nvd_json = _cves_as_dict(response.json())
        for entry in kev_json.get('vulnerabilities', list()):
            cve_id = entry.get('cveID')
            cve_details = nvd_json.get(cve_id, {})
            self.analyze_entry(entry, cve_details)


    def _analyze_cve_details(self, cve_details: dict):
        """Analyzes an entry as specified in nist nvd json."""
        if not isinstance(cve_details, dict) or len(dict) == 0:
            return 0, 'none', ''
        cve = cve_details.get('cve')
        cvss_version, cvss_metric = _extract_cvss_metric(cve)
        if cvss_version == 0:
            return 0, 'none', ''
        cvss_data = cvss_metric.get('cvssData', {})
        base_score = cvss_data.get('baseScore', 0)
        description = "#### Details\n\n"
        for cve_description in cve.get('descriptions', []):
            if cve_description.get('lang') == 'en':
                description += cve_description.get('value') + '\n'
        description += f"#### CVSS {cvss_version} Severity and Metrics\n\n"
        description += f"* **Vector:** {cvss_data.get('vectorString')}\n"
        description += f"* **Impact Score:** {cve.get('impactScore')}\n"
        description += f"* **Exploitability Score:** {cve.get('exploitabilityScore')}\n"
        if cvss_version == 2:
            severity = cvss_metric.get('baseSeverity', 'none').lower()
            description += f"* **Access Vector (AV):** {cvss_data.get('accessVector').capitalize()}\n"
            description += f"* **Access Complexity (C):**: {cvss_data.get('accessComplexity').capitalize()}\n"
            description += f"* **Authentication (AU):** {cvss_data.get('authentication').capitalize()}\n"
            description += f"* **Confidentiality (C):**: {cvss_data.get('confidentialityImpact').capitalize()}\n"
            description += f"* **Integrigty (I):**: {cvss_data.get('integrityImpact').capitalize()}\n"
            description += f"* **Availability (A):** {cvss_data.get('availabilityImpact').capitalize()}\n\n"
        else:
            severity = cvss_data.get('baseSeverity', 'none').lower()
            description += f"* **Attack Vector (AV):** {cvss_data.get('attackVector').capitalize()}\n"
            description += f"* **Attack Complexity (AC):** {cvss_data.get('attackComplexity').capitalize()}\n"
            description += f"* **Privileges Required (PR):** {cvss_data.get('privilegesRequired').capitalize()}\n"
            description += f"* **User Interaction (UI):** {cvss_data.get('userInteraction').capitalize()}\n"
            description += f"* **Scope (S):** {cvss_data.get('scope').capitalize()}\n"
            description += f"* **Confidentiality (C):** {cvss_data.get('confidentialityImpact').capitalize()}\n"
            description += f"* **Integrety (I):** {cvss_data.get('integrityImpact').capitalize()}\n"
            description += f"* **Availability (A):** {cvss_data.get('availabilityImpact').capitalize()}\n\n"
        description += "#### References\n\n"
        for reference in cve.get('references', []):
            tags = " ".join([f"`{tag}`" for tag in reference.get('tags', [])])
            description += f"* {reference.get('url')} {tags}\n"
        return base_score, severity, description


    def analyze_entry(self, entry: dict, cve_details: dict):
        """Analyzes an entry as specified in cisa kev json."""
        try:
            created = datetime.strptime(entry["dateAdded"], "%Y-%m-%d")
        except ValueError as error:
            logging.error("Error parsing kev %s: %s", entry["dateAdded"], error)
            return

        cve_id = entry.get('cveID', None)
        if cve_id is None:
            return 
        reference = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
        description = "#### Summary\n\n"
        description = entry.get("shortDescription") + "\n\n"
        description += f"* Added to KEV: {entry['dateAdded']}\n"
        description += f"* Vendor/Project: {entry.get('vendorProject')}\n"
        description += f"* Product: {entry.get('product')}\n"
        known_ransom_campaign = entry.get("knownRansomwareCampaignUse", "Unknown")
        description += f"* Known to be used in ransomware campaigns: {known_ransom_campaign}\n\n"
        base_score, severity, cve_description = self._analyze_cve_details(cve_details)
        description += cve_description

        name = f"{cve_id} - {entry.get('vulnerabilityName')}"
        vulnerability = entity.Vulnerability(
            name=name, 
            description=description, 
            created=created,
            reference=reference,
            base_score=base_score,
            severity=severity
        ).save()
        vulnerability.tag({entry.get("cveID"), 'cisa-kev'})

taskmanager.TaskManager.register_task(CisaKEV)

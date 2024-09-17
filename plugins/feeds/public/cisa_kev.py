import logging
from datetime import datetime, timedelta
from typing import ClassVar

from core import taskmanager
from core.schemas import task
from core.schemas.entities.vulnerability import Vulnerability


def _cves_as_dict(data):
    cves = dict()
    for vulnerability in data.get("vulnerabilities", []):
        cve_id = vulnerability.get("cve", {}).get("id", "")
        if not len(cve_id):
            continue
        cves[cve_id] = vulnerability
    return cves


def _extract_cvss_metric(cve):
    metrics = cve.get("metrics", {})
    metric_version = 0
    for metric in metrics:
        version = float(".".join(list(metric.replace("cvssMetricV", ""))))
        if version > metric_version:
            metric_version = version
    if metric_version == 0:
        return 0, {}
    metric_str = str(metric_version).replace(".", "")
    cvss_metric = metrics.get(f"cvssMetricV{metric_str}", [])
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

    CISA_SOURCE: ClassVar[
        "str"
    ] = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_SOURCE: ClassVar[
        "str"
    ] = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev"

    def run(self):
        response = self._make_request(self.CISA_SOURCE, sort=False)
        if not response:
            logging.info(f"Skipping: no updates from {self.CISA_SOURCE}")
            return
        kev_json = response.json()
        response = self._make_request(self.NVD_SOURCE)
        if not response:
            logging.info(f"No updates from {self.NVD_SOURCE}")
            nvd_json = {}
        else:
            nvd_json = _cves_as_dict(response.json())
        for entry in kev_json.get("vulnerabilities", list()):
            cve_id = entry.get("cveID", "")
            if not cve_id:
                continue
            cve_details = nvd_json.get(cve_id, {})
            self.analyze_entry(entry, cve_details)

    def _analyze_cve_details(self, cve_details: dict):
        """Analyzes an entry as specified in nist nvd json."""
        cve = cve_details.get("cve", {})
        cvss_version, cvss_metric = _extract_cvss_metric(cve)
        if cvss_version == 0:
            return 0, "none", ""
        cvss_data = cvss_metric.get("cvssData", {})
        base_score = cvss_data.get("baseScore", 0)
        description = "#### Details\n\n"
        for cve_description in cve.get("descriptions", []):
            if cve_description.get("lang") == "en":
                en_description = cve_description.get("value", "")
                if len(en_description):
                    description += f"{en_description}\n"
        description += f"#### CVSS {cvss_version} Severity and Metrics\n\n"
        description += f"* **Vector:** {cvss_data.get('vectorString', 'N/A')}\n"
        description += f"* **Impact Score:** {cve.get('impactScore', 'N/A')}\n"
        description += (
            f"* **Exploitability Score:** {cve.get('exploitabilityScore', 'N/A')}\n"
        )
        if cvss_version == 2:
            severity = cvss_metric.get("baseSeverity", "none").lower()
            description += f"* **Access Vector (AV):** {cvss_data.get('accessVector', 'N/A').capitalize()}\n"
            description += f"* **Access Complexity (C):**: {cvss_data.get('accessComplexity', 'N/A').capitalize()}\n"
            description += f"* **Authentication (AU):** {cvss_data.get('authentication', 'N/A').capitalize()}\n"
            description += f"* **Confidentiality (C):**: {cvss_data.get('confidentialityImpact', 'N/A').capitalize()}\n"
            description += f"* **Integrigty (I):**: {cvss_data.get('integrityImpact', 'N/A').capitalize()}\n"
            description += f"* **Availability (A):** {cvss_data.get('availabilityImpact', 'N/A').capitalize()}\n\n"
        else:
            severity = cvss_data.get("baseSeverity", "none").lower()
            description += f"* **Attack Vector (AV):** {cvss_data.get('attackVector', 'N/A').capitalize()}\n"
            description += f"* **Attack Complexity (AC):** {cvss_data.get('attackComplexity', 'N/A').capitalize()}\n"
            description += f"* **Privileges Required (PR):** {cvss_data.get('privilegesRequired', 'N/A').capitalize()}\n"
            description += f"* **User Interaction (UI):** {cvss_data.get('userInteraction', 'N/A').capitalize()}\n"
            description += (
                f"* **Scope (S):** {cvss_data.get('scope', 'N/A').capitalize()}\n"
            )
            description += f"* **Confidentiality (C):** {cvss_data.get('confidentialityImpact', 'N/A').capitalize()}\n"
            description += f"* **Integrety (I):** {cvss_data.get('integrityImpact', 'N/A').capitalize()}\n"
            description += f"* **Availability (A):** {cvss_data.get('availabilityImpact', 'N/A').capitalize()}\n\n"
        urls = ""
        for reference in cve.get("references", []):
            url = reference.get("url", "")
            if not len(url):
                continue
            tags = " ".join([f"`{tag}`" for tag in reference.get("tags", [])])
            if len(tags):
                urls += f"* {reference.get('url')} {tags}\n"
            else:
                urls += f"* {reference.get('url')}\n"
        if len(urls):
            description += f"#### References\n\n{urls}"
        return base_score, severity, description

    def analyze_entry(self, entry: dict, cve_details: dict):
        """Analyzes an entry as specified in cisa kev json."""
        try:
            created = datetime.strptime(entry["dateAdded"], "%Y-%m-%d")
        except ValueError as error:
            logging.error("Error parsing kev %s: %s", entry["dateAdded"], error)
            return

        cve_id = entry["cveID"]
        reference = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        description = "#### Summary\n\n"
        description = entry.get("shortDescription") + "\n\n"
        description += f"* Added to KEV: {entry['dateAdded']}\n"
        description += f"* Vendor/Project: {entry.get('vendorProject', 'N/A')}\n"
        description += f"* Product: {entry.get('product', 'N/A')}\n"
        known_ransom_campaign = entry.get("knownRansomwareCampaignUse", "Unknown")
        description += (
            f"* Known to be used in ransomware campaigns: {known_ransom_campaign}\n\n"
        )
        if cve_details:
            base_score, severity, cve_description = self._analyze_cve_details(
                cve_details
            )
            description += cve_description
        else:
            base_score = 0.0
            severity = "none"

        name = f"{cve_id}"
        title = entry.get("vulnerabilityName", "")
        vulnerability = Vulnerability(
            name=name,
            title=title,
            description=description,
            created=created,
            reference=reference,
            base_score=base_score,
            severity=severity,
        ).save()
        vulnerability.tag({entry.get("cveID"), "cisa-kev"})


taskmanager.TaskManager.register_task(CisaKEV)

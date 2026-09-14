import unittest

from plugins.feeds.public.cisa_kev import _extract_cvss_metric


class ExtractCvssMetricTest(unittest.TestCase):
    def test_no_metrics(self):
        self.assertEqual(_extract_cvss_metric({}), (0, {}))
        self.assertEqual(_extract_cvss_metric({"metrics": {}}), (0, {}))

    def test_ssvc_key_is_ignored(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                "ssvcV203": [{"options": [{"Exploitation": "active"}]}],
            }
        }
        version, metric = _extract_cvss_metric(cve)
        self.assertEqual(version, 3.1)
        self.assertEqual(metric, {"cvssData": {"baseScore": 9.8}})

    def test_ssvc_only_returns_nothing(self):
        cve = {"metrics": {"ssvcV203": [{"options": []}]}}
        self.assertEqual(_extract_cvss_metric(cve), (0, {}))

    def test_v2_only(self):
        cve = {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}}
        version, metric = _extract_cvss_metric(cve)
        self.assertEqual(version, 2.0)
        self.assertEqual(version, 2)
        self.assertEqual(metric, {"cvssData": {"baseScore": 7.5}})

    def test_highest_version_wins(self):
        cve = {
            "metrics": {
                "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}],
                "cvssMetricV30": [{"cvssData": {"baseScore": 8.1}}],
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
            }
        }
        version, metric = _extract_cvss_metric(cve)
        self.assertEqual(version, 3.1)
        self.assertEqual(metric, {"cvssData": {"baseScore": 9.8}})

    def test_v40_wins_over_v31(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                "cvssMetricV40": [{"cvssData": {"baseScore": 9.3}}],
            }
        }
        version, metric = _extract_cvss_metric(cve)
        self.assertEqual(version, 4.0)
        self.assertEqual(metric, {"cvssData": {"baseScore": 9.3}})

    def test_empty_metric_list(self):
        cve = {"metrics": {"cvssMetricV31": []}}
        self.assertEqual(_extract_cvss_metric(cve), (0, {}))

    def test_unknown_keys_do_not_raise(self):
        cve = {"metrics": {"somethingElseV9": [{}], "cvssMetric": [{}]}}
        self.assertEqual(_extract_cvss_metric(cve), (0, {}))


if __name__ == "__main__":
    unittest.main()

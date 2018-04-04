from datetime import timedelta

from core import Feed


class UrlHaus(Feed):
    default_values = {
        "frequency":
            timedelta(minutes=20),
        "name":
            "UrlHaus",
        "source":
            "https://urlhaus.abuse.ch/downloads/csv/",
        "description":
            "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
    }

    def update(self):
        for line in self.update_csv(delimiter=',',quotechar='"'):
            self.analyze(line)

    def analyze(self, line):

        if not line or line[0].startswith("#"):
            return

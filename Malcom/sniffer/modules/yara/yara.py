import os

from scapy.all import *
from bson.json_util import dumps as bson_dumps
from bson.json_util import loads as bson_loads
import yara

from Malcom.sniffer.modules.base_module import Module
from Malcom.auxiliary.toolbox import debug_output

classname = "Yara"


class Yara(Module):
    """Iterates over each flow and runs Yara rules against them"""
    def __init__(self, session):
        self.session = session
        self.display_name = "Yara"
        self.name = "yara"

        self.rules = self.load_yara_rules(os.path.dirname(os.path.realpath(__file__)))
        self.matches = self.load_entry() or {}

        super(Yara, self).__init__()

    def bootstrap(self, args):
        content = self.add_static_tags(self.content())
        return content

    def content(self):
        content = "<table class='table table-condensed'><tr><th>Flow</th><th>Rule</th><th>Param</th><th>Match</th><th>Offset</th></tr>"

        for flow in self.session.flows.values():
            if flow.fid not in self.matches:
                self.matches[flow.fid] = self.match_yara(flow.payload)
            if self.matches[flow.fid]:
                for rule, match in self.matches[flow.fid].items():
                    m = match[0][0]
                    content +=  "<tr><td><a class='switcher' data-flowid='{}'" +\
                                " href='#'>{} &#8594; {}</a></td>".format(flow.src_addr, flow.dst_addr)
                    content += "<td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(rule,
                                                                                          m[1],
                                                                                          repr(m[2]),
                                                                                          m[0],
                                                                                          )
            self.save_entry(self.matches)

        content += "</table>"
        return content

    def match_yara(self, data):
        matches = {}
        for m in self.rules.match(data=data):
            if matches.get(m.rule, False) == False:
                matches[m.rule] = []
            matches[m.rule].append(m.strings)
        return matches


    def load_yara_rules(self, path):
        debug_output("Compiling YARA rules from {}".format(path))
        if not path.endswith('/'):
            path += '/'  # add trailing slash if not present
        filepaths = {}
        for file in os.listdir(path):
            if file.endswith('.yar'):
                print file
                filepaths[file] = path + file
        debug_output("Loaded {} YARA rule files in {}".format(len(filepaths), path))
        return yara.compile(filepaths=filepaths)



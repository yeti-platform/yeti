from scapy.all import *
from Malcom.sniffer.modules.base_module import Module
from Malcom.auxiliary.toolbox import debug_output

classname = "PassiveDns"

# This is a dummy module to give an example of what modules can be used for
# PassiveDns is a very basic module that will go through all the packets
# in a capture and enumerate the DNS requests that are being made


class PassiveDns(Module):
    """This is a dummy module to show what modules can accomplish"""
    def __init__(self, session):
        self.session = session
        self.display_name = "Passive DNS"
        self.name = "passive_dns"
        self.dns_requests = {}

        super(PassiveDns, self).__init__()

    # This function defines what is sent back to the browser.
    # In this case, it only sends back a table, but it could eventually
    # send back JS code that could call other functions from the module
    # MANDATORY FUNCTION_

    def bootstrap(self, args):
        content = self.add_static_tags(self.content())
        return content

    # This is called for each packet that is processed during a sniffing session
    # MANDATORY FUNCTION
    def on_packet(self, pkt):
        IP_layer = IP if IP in pkt else IPv6
        if DNS in pkt and pkt[IP_layer].sport == 53:
            self.parse_dns_response(pkt)

    # This might as well have been named bootstrap, but is in a separate function
    # for illustration purposes
    def content(self):
        # Check if the session packets are set to 0 (i.e. session packets are not loaded in memory)
        if len(self.session.pkts) == 0:
            filename = self.session.pcap_filename
            self.session.pkts = sniff(stopper=self.session.stop_sniffing, filter=self.session.filter, prn=self.on_packet, stopperTimeout=1, offline=self.session.engine.setup['SNIFFER_DIR']+"/"+filename)
            # Eventually, this should be stored in the database.
            # We can access the model through self.session.model
            # It needs to be retrieved in session_info commands though

        content = "<table class='table table-condensed'><tr><th>Query</th><th>Answers</th><th>Count</th></tr>"
        for q in self.dns_requests:
            content += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(q, ", ".join(self.dns_requests[q]['answers']), self.dns_requests[q]['count'])
        content += "</table>"
        return content

    # This function does the DNS parsing heavy-lifting. May be easier
    # using dpkt instead of scapy
    def parse_dns_response(self, pkt):
        question = pkt[DNS].qd.qname
        if question not in self.dns_requests:
            self.dns_requests[question] = {'count': 0, 'answers': []}
        self.dns_requests[question]['count'] += 1

        response_types = [pkt[DNS].an, pkt[DNS].ns, pkt[DNS].ar]
        response_counts = [pkt[DNS].ancount, pkt[DNS].nscount, pkt[DNS].arcount]

        for i, response in enumerate(response_types):
            if response_counts[i] == 0:
                continue
            for rr in xrange(response_counts[i]):
                if response[rr].type not in [1, 2, 5, 15]:
                    debug_output('No relevant records in reply')
                    continue
                rr = response[rr]
                if rr.rdata not in self.dns_requests[question]['answers']:
                    self.dns_requests[question]['answers'].append(rr.rdata)
# encoding: utf-8

import collections
import logging
import pprint
from datetime import timedelta, datetime

import hammock
import requests
from mongoengine.errors import DoesNotExist
from requests import auth

from core.config.config import yeti_config
from core.entities import Actor, TTP, Campaign
from core.entities.malware import Malware
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url, File, Hash, Ip, Email, Text, Hostname, Tag

log = logging.getLogger('pp2yeti')

# add to yeti.conf
# [proofpoint]
# # The ProofPoint API credentials set must be obtained by an Tenant administrator
# api_user = 12345678-1234-1234-1234-1234585686896896
# api_password = wiq3890ijwdfwefwe8f9fwehiofwehkefwhiwefiohwefohi...
# # Then Tenant id is the uuid showing in the Web_UI queries
# tenant_id = 09872137821783-1234-1234-1234-121239086896896
# # do we want email metadata
# import_email_metadata = False


class ThreatInsight(Feed):
    """
    1) Pull messages Blocked from proofpoint API
    2) Group messages by threatID, so not to treat the same threat multiple time.
    3) _make_threat_nodes: extract the threat information (malicious Url or Hash)
    4) _get_threat_forensics_nodes: get the forensic evidence for that threat
    5) _add_events_nodes: extract and link the messages observables to the threat
    6) _make_entities: extract campaign info if it exists and link the threat to it
    7) _query_and_filter_previous_new_threat_for_campaign: query other threats associated to campaign and process them 
    """

    default_values = {
        "frequency": timedelta(minutes=30),
        "name": "ThreatInsight",
        "source": "https://tap-api-v2.proofpoint.com/v2/",
        "description": "This feed contains sandbox observables from blocked emails by Proofpoint",
    }

    def __init__(self, *args, **kwargs):
        super(ThreatInsight, self).__init__(*args, **kwargs)
        self.config = {
            'api_user': yeti_config.get('proofpoint', 'api_user'),
            'api_password': yeti_config.get('proofpoint', 'api_password'),
            'tenant_id': yeti_config.get('proofpoint', 'tenant_id'),
            'import_email_metadata': yeti_config.get('proofpoint', 'import_email_metadata'),
        }

    def update(self):
        self.api = ProofPointAPI(auth=auth.HTTPBasicAuth(self.config['api_user'], self.config['api_password']))
        self.siem_api = SIEMAPI(self.api)
        self.campaign_api = CampaignAPI(self.api)
        self.forensic_api = ForensicsAPI(self.api)
        # pull events for the period we didn't run
        time_period = self.siem_api.make_time_param(frequency=self.default_values['frequency'])
        messages = self.siem_api.get_messages_blocked(time_period)
        log.info("Downloaded {nb} message threats for the last period".format(nb=len(messages['messagesBlocked'])))
        # But efficient processing calls for getting all Threatid for all event.
        # then grouping event metadata for each threatid
        # then creating entries for that threatid, and these metadata.
        # That is the opposite of creating threatid for each event.

        # parse all messages to identify all unique threats
        threats = self._get_all_threats(messages['messagesBlocked'])
        for threat in threats:
            # group multiple email events associated to one threat
            events = self._get_messages_for_threat(messages['messagesBlocked'], threat)
            self.analyze({'threat': threat, 'events': events})
        return

    def analyze(self, threat_meta):
        threat = threat_meta['threat']
        events = threat_meta['events']
        log.info("%d messages blocked for threat %s", len(events), threat['threatID'])
        log.debug(pprint.pformat(threat))
        # make tags and context
        context = {'source': self.name, 'event_type': 'email_blocked', 'tlp': 'green'}
        tags = [Tag.get_or_create(name=threat['threatType']), Tag.get_or_create(name=threat['classification'])]
        tags = [{'name': t.name} for t in tags]

        # extract Url and/or Hash info from threat
        threat_nodes = self._make_threat_nodes(threat, context, tags)
        if threat_nodes is None:
            return

        # TODO verify if we want that. Indicators are probably in campaign_info
        # get all forensics report for this threat
        threat_forensics = self._get_threat_forensics_nodes(threat, threat_nodes, context, tags)
        if threat_forensics is not None:
            # attach all node to threat_nodes
            for _t_node in threat_nodes:
                _t_node.active_link_to(threat_forensics, "Drops", self.name)
                for _f in threat_forensics:
                    log.debug("{threatid} Drops {forensic}".format(threatid=_t_node.value, forensic=_f.value))

        # now attach each event to the threat_nodes
        events_node = self._add_events_nodes(events, context, tags)
        for email in events_node:
            email.active_link_to(threat_nodes, "Delivers", self.name)
            for _n in threat_nodes:
                log.debug("{email} Delivers {n}".format(email=email.value, n=_n.value))

        # so now our main threat is in threats[].
        # lets link to the campaign
        campaign, campaign_info = self._make_entities(threat)
        if campaign is not None:
            # attach this threat to the campaign
            log.info("Linking campaign to %d threat nodes", len(threat_nodes))
            campaign.action(threat_nodes, self.name, "Delivers")
            # campaign_info contains campaignMembers a list of threats (urls/malwares)
            # unroll and fetch them too if not duplicates
            # fields: id, subType, threat, threatStatus, threatTime, type
            threats_nodes2 = self._query_and_filter_previous_new_threat_for_campaign(campaign_info, context)
            log.info("Linking campaign to %d new threat nodes", len(threats_nodes2))
            # campaign.action(threats_nodes2, self.name, "Delivers")
            # even faster, dont look at clean_old
            campaign.active_link_to(threats_nodes2, "Delivers", self.name, clean_old=False)
        return

    @staticmethod
    def _query_and_filter_previous_new_threat_for_campaign(campaign_info, context):
        # get all threat for this campaign from the API
        # filter out the threat we already have in DB
        # return the net new threats
        # TODO: alternative solution, query by type, get all campaign threat, intersect sets
        # Q/A: why do i have to play with perf issues ?
        # only create Observables and link them when they do not exists.
        cls_action = {
            'COMPLETE_URL': Url,
            'NORMALIZED_URL': Url,
            'ATTACHMENT': Hash,
            'DOMAIN': Hostname,
            'HOSTNAME': Hostname
        }
        threats = []
        log.info("There are {nb} threat associated to campaign".format(nb=len(campaign_info['campaignMembers'])))
        for threat in campaign_info['campaignMembers']:
            # ATTACHMENT, COMPLETE_URL, NORMALIZED_URL, or DOMAIN
            # BUG #5: undocumentated value HOSTNAME, could be hostname or ip
            v = threat['threat']
            # t = threat['threatTime'][:10] # last_seen ?
            create_t = datetime.strptime(threat['threatTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
            # TODO threat['threatStatus'] in active, ...
            if threat['threatStatus'] != 'active':
                log.warning('Campaign threat - threatStatus %s unsupported', threat['threatStatus'])
                # FIXME Campaign threat - threatStatus falsePositive unsupported
            # threatStatus ?
            if threat['subType'] not in cls_action:
                log.error('Campaign threat - subtype %s unsupported', threat['subType'])
                continue
            cls = cls_action[threat['subType']]
            try:
                # if it exists, don't do anything. tags and context are the same
                cls.objects.get(value=v)
            except DoesNotExist:
                # otherwise return it to link to it.
                # threats.append(cls.get_or_create(value=v, context=[context], created=t))
                # tags named argument in constructor does not work the same as .tag()
                try:
                    o = cls.get_or_create(value=v, context=[context], created=create_t)
                    o.tag([threat['type'], threat['subType']])
                except DoesNotExist:
                    # wtf
                    log.error("{cls} {v} has a weird problem - FIXME".format(cls=cls, v=v))
                except ObservableValidationError:
                    try:
                        if threat['subType'] == 'HOSTNAME':  # could be an Ip
                            o = Ip.get_or_create(value=v, context=[context], created=create_t)
                    except ObservableValidationError as e:
                        log.error(e)
                        log.error(pprint.pformat(threat))
                        log.error("Campaign {name}".format(name=campaign_info['name']))
                        o = Text.get_or_create(value=v, context=[context], created=create_t)
                    o.tag([threat['type'], threat['subType']])
                threats.append(o)

        log.info("Found %d new threat on campaign, new to us", len(threats))
        # there is a bug here...
        log.debug(", ".join(["%s:%s" % (t.__class__.__name__, t.value) for t in threats]))
        return threats

    @staticmethod
    def _get_all_threats(messages):
        # parse all message metadata to identify all unique threats
        threats = dict()
        for msg in messages:
            # log.debug(pprint.pformat(msg))
            for infomap in msg['threatsInfoMap']:
                threats[infomap['threatID']] = infomap
        return threats.values()

    @staticmethod
    def _get_messages_for_threat(messages, threat):
        # get all messages associated to a threat
        events = [_ for _ in messages if len([t for t in _['threatsInfoMap'] if t['threatID'] == threat['threatID']])]
        return events

    @staticmethod
    def _make_threat_nodes(threat, context, tags):
        # extract Url and Hash info
        threats = dict()
        if threat['threatStatus'] != 'active':
            # FIXME, clear out false positive ?
            log.warning("threatStatus %s for threat %s", threat['threatStatus'], threat['threatID'])
            log.debug(pprint.pformat(threat))
            return None
        log.debug('_make_threat_nodes for threat %s', threat['threatID'])
        # threattype, classification
        # url, phish: url leads to phishing page (threat is url)
        # url, malware: url leads to malware download (threat is url, threatid is maybe sha256)
        # attachment, malware: attachement is malware (threat is sha256)
        # spam, url
        if threat['threatType'] == 'url':
            if threat['classification'] == 'phish':
                pass  # just keep the url
            elif threat['classification'] == 'malware':
                # get url and hash
                threats['attachment'] = threat
            elif threat['classification'] == 'spam':
                log.info('URL threat - ignore classification %s', threat['classification'])
            else:
                log.error('Type: url, Unsupported classification %s', threat['classification'])
                log.debug(pprint.pformat(threat))
                return None
            threats['url'] = threat
        elif threat['threatType'] == 'attachment':
            if threat['classification'] == 'malware':
                threats['attachment'] = threat
            else:
                log.error('Type: attachment, Unsupported classification %s', threat['classification'])
                log.debug(pprint.pformat(threat))
                return None
        else:
            log.error('Unsupported threatType %s classification %s', threat['threatType'], threat['classification'])
            log.debug(pprint.pformat(threat))
            return None
        # FIXME check if they exist already.
        # if they do, do not parse the threat a second time ?
        threat_nodes = []
        if 'url' in threats:
            threat_nodes.append(Url.get_or_create(value=threats['url']['threat'], context=[context]))
        if 'attachment' in threats:
            threat_nodes.append(Hash.get_or_create(value=threats['attachment']['threatID'], context=[context]))
        for o in threat_nodes:
            o.tag([t['name'] for t in tags])
        return threat_nodes

    def _make_entities(self, threat):
        # use the infomap to get the campaign info link from ProofPoint
        if threat['campaignID'] is None:
            return None, None
        log.debug('_make_entities for campaign %s', threat['campaignID'])
        # get the campaign info from pp
        campaign_info = self.campaign_api.get_campaign(campaign_id=threat['campaignID'])
        log.debug(pprint.pformat(campaign_info))
        # create/get the campaign
        _campaign = Campaign.get_or_create(name=campaign_info['name'],
                                           tags=[self.name],
                                           description=campaign_info['description']).save()
        if _campaign.description in [None, '']:
            # catch update to description
            _campaign.description = campaign_info['description']
            _campaign.save()

        # attribute the campaign with the ProofPoint actor denomination
        log.info('make Actor entities for %d actors', len(campaign_info['actors']))
        for actor in campaign_info['actors']:
            _actor = Actor.get_or_create(name=actor['name'], tags=[self.name]).save()
            _actor.action(_campaign, self.name)
            # put some links
            if _actor.description in [None, '']:
                _actor.description = self._make_actor_web_url(actor['id'])
                _actor.save()

        # for fam in campaign_info['families']:
        #     # BUG ? MalwareFamily.get_or_create not existing
        #     _fam = MalwareFamily.get_or_create(fam['name']).save()
        #     _campaign.action(_fam, self.name)
        #     # except mongoengine.errors.NotUniqueError:

        log.info('make Malware entities for {nb} malwares'.format(nb=len(campaign_info['malware'])))
        for mal in campaign_info['malware']:
            _mal = Malware.get_or_create(name=mal['name'], tags=[self.name]).save()
            _campaign.action(_mal, self.name)

        log.info('make TTP entities for {nb} techniques'.format(nb=len(campaign_info['techniques'])))
        for ttp in campaign_info['techniques']:
            _t = TTP.get_or_create(name=ttp['name'], killchain="3", tags=[self.name]).save()
            # _t.killchain = "3"
            # _t.description = "Macro-enabled MS Office document"
            # _t.save()
            # Link.connect(_campaign, _t)
            _campaign.action(_t, self.name)

        return _campaign, campaign_info

    @staticmethod
    def _get_evidence_id(evidence):
        # add attributes for the known evidence type
        if evidence['type'] in ['behavior', 'attachment']:
            return 'behavior'  # these are attributes of the threat
        elif evidence['type'] in ['file', 'dropper']:
            if 'sha256' in evidence['what']:
                return evidence['what']['sha256']
            if 'md5' in evidence['what']:
                return evidence['what']['md5']
            if 'path' in evidence['what']:
                return evidence['what']['path']
        elif evidence['type'] == 'cookie':
            pass
        elif evidence['type'] == 'dns':
            return evidence['what']['host']
        elif evidence['type'] == 'ids':
            return evidence['what']['ids']
        elif evidence['type'] == 'mutex':
            return evidence['what']['name']
        elif evidence['type'] == 'network':
            if 'ip' in evidence['what']:
                return evidence['what']['ip']
            elif 'domain' in evidence['what']:
                return evidence['what']['domain']
        elif evidence['type'] == 'process':
            # TODO this is more a TTP
            # {
            #     u'display': u'Process started from "C:\\Windows\\System32\\cmd.exe" /S /C echo 1111 >
            # C:\\Users\\(username)\\AppData\\Local\\Temp\\xGXDzn.txt',
            #     u'malicious': True,
            #     u'platforms': [{u'name': u'Windows 7', u'os': u'win', u'version': u'win7'}],
            #     u'time': 0,
            #     u'type': u'process',
            #     u'what': {u'action': u'create',
            #               u'path': u'"C:\\Windows\\System32\\cmd.exe" /S /C echo 1111 >
            # C:\\Users\\(username)\\AppData\\Local\\Temp\\xGXDzn.txt'}},
            pass
        elif evidence['type'] == 'registry':
            return evidence['key']
        elif evidence['type'] == 'url':
            return evidence['what']['url']

    @staticmethod
    def _make_context_from_notes(evidence_list):
        notes = list(set([e['note'] for e in evidence_list if 'note' in e]))
        context = dict()
        if len(notes) == 1:
            context['note'] = notes[0]
        elif len(notes) > 1:
            for i, note in enumerate(notes):
                context['note_%02d' % i] = notes[i]
        return context

    def _get_threat_forensics_nodes(self, threat, threat_nodes, general_context, tags):
        # For this threat, get associated forensics reports
        log.debug('_get_threat_forensics threatID: %s', threat['threatID'])
        # TODO: includeCampaignForensics=True ?
        results = self.forensic_api.get_reports_from_threat(threat_id=threat['threatID'])
        report_forensics = []

        # merges all evidences before processing.
        evidences = collections.defaultdict(list)
        for report in results['reports']:
            for evidence in report['forensics']:
                if not evidence['malicious']:
                    continue
                # get the evidence id
                _id = self._get_evidence_id(evidence)
                evidences[_id].append(evidence)

        # 1) merge all behavior notes for behavior and attachment type
        # DO NOT del evidences['behavior']. some file drop are documented there
        context = general_context.copy()
        _ctx = self._make_context_from_notes(evidences['behavior'])
        context.update(_ctx)

        # 2) Change threat context
        for t in threat_nodes:
            t.add_context(context, replace_source=True)

        # now the context is of each forensic piece.
        # remove the behavior/attachment stuff
        del evidences['behavior']

        # now threat each malicious evidence and merge relevant fields
        for _id, evidence_list in evidences.items():
            if len(evidence_list) == 0:
                continue  # can happen with behavior and defaultdict
            if len(evidence_list) > 1 and _id != 'behavior':
                log.warning('Multiple evidence for {id}'.format(id=_id))
                log.debug(pprint.pformat(evidence_list))
                log.debug('-'*40)
            threat_forensics = []

            # get all forensic evidence
            for evidence in evidence_list:
                try:
                    nodes = self._get_threat_forensics_nodes_inner(evidence, general_context, tags)
                    threat_forensics.extend(nodes)
                except ObservableValidationError as e:
                    log.error(e)
                    log.error(pprint.pformat(evidence))
                    log.error('threat_forensics threatID was %s', threat['threatID'])

            # keep track of all reports
            report_forensics.extend(threat_forensics)
        return report_forensics

    def _get_threat_forensics_nodes_inner(self, evidence, general_context, tags):
        # create context from notes
        context = general_context.copy()
        _ctx = self._make_context_from_notes([evidence])
        context.update(_ctx)
        # add evidence['type'] and unicify tags
        tags = [{'name': _} for _ in set([evidence['type']] + [d['name'] for d in tags])]
        # create Tags in DB
        for _ in tags:
            Tag.get_or_create(name=_['name'])
        #
        threat_forensics = []

        # technical hack: set optional comments values
        for optional in ['action', 'rule', 'path', 'rule']:
            if optional not in evidence['what']:
                evidence['what'][optional] = None

        # add attributes for the known evidence type
        if evidence['type'] in ['file', 'dropper']:
            if 'path' in evidence['what']:
                threat_forensics.append(File.get_or_create(value=evidence['what']['path'], context=[context]))
            if 'md5' in evidence['what']:
                threat_forensics.append(Hash.get_or_create(value=evidence['what']['md5'], context=[context]))
            if 'sha256' in evidence['what']:
                threat_forensics.append(Hash.get_or_create(value=evidence['what']['sha256'], context=[context]))
        elif evidence['type'] == 'cookie':
            pass
        elif evidence['type'] == 'dns':
            threat_forensics.append(Hostname.get_or_create(value=evidence['what']['host'], context=[context]))
        elif evidence['type'] == 'ids':
            threat_forensics.append(Text.get_or_create(value=evidence['what']['ids'], context=[context]))
            pass
        elif evidence['type'] == 'mutex':
            threat_forensics.append(Text.get_or_create(value=evidence['what']['name'], context=[context]))
        elif evidence['type'] == 'network':
            if 'ip' in evidence['what']:
                # FIXME port, type
                threat_forensics.append(Ip.get_or_create(value=evidence['what']['ip'], context=[context]))
            elif 'domain' in evidence['what']:
                threat_forensics.append(
                    Hostname.get_or_create(value=evidence['what']['domain'], context=[context]))
        elif evidence['type'] == 'process':
            pass
        elif evidence['type'] == 'registry':
            # threat_forensics.append(evidence['what']['key'])
            # threat_forensics.append(evidence['what']['value'])
            pass
        elif evidence['type'] == 'url':
            # BUG yeti-#115 ObservableValidationError: Invalid URL: http://xxxxx-no-tld/
            threat_forensics.append(Url.get_or_create(value=evidence['what']['url'], context=[context]))
            # add note as tag because its a signature
            if 'note' in evidence:
                threat_forensics[-1].tag(evidence['note'].replace('.', '_').strip('_'))
        # tag all of that
        for o in threat_forensics:
            o.tag([t['name'] for t in tags])
        return threat_forensics

    def _add_events_nodes(self, events, context, tags):
        log.debug('_add_events_nodes on {nb} events'.format(nb=len(events)))
        attach_unsupported = dict([(_, 0) for _ in ['UNSUPPORTED_TYPE', 'TOO_SMALL', None]])
        event_nodes = list()
        for msg in events:
            create_t = datetime.strptime(msg['messageTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
            # PPS unique value
            guid = Text.get_or_create(value='proofpoint://%s' % msg['GUID'], created=create_t, context=[context])
            log.debug('Event {msg}'.format(msg=msg['messageID']))
            message_contents = list()
            src_ip = Ip.get_or_create(value=msg['senderIP'], created=create_t, context=[context])
            src_ip.tag(['MTA'])
            guid.active_link_to([src_ip], "MTA src ip", self.name)
            # new event
            event_nodes.append(guid)
            #
            if self.config['import_email_metadata']:
                # email details
                # messageID
                message_id = Email.get_or_create(value=msg['messageID'], created=create_t, context=[context])
                guid.active_link_to([message_id], "seen in", self.name)
                # sender
                _s1 = Email.get_or_create(value=msg['sender'], created=create_t, context=[context])
                _s1.tag(['sender'])
                guid.active_link_to([_s1], "sender", self.name)
                if 'headerFrom' in msg:
                    # header From
                    _s2 = Email.get_or_create(value=msg['headerFrom'], created=create_t, context=[context])
                    _s2.tag(['sender'])
                    guid.active_link_to([_s2], "headerFrom", self.name)

            # FIXME is that a duplicate of attachment-malware ?
            # attachment events
            for attach in msg['messageParts']:
                if attach['sandboxStatus'] in ['THREAT']:
                    md5 = Hash.get_or_create(value=attach['md5'], created=create_t, context=[context])
                    md5.tag([t['name'] for t in tags])
                    fname = File.get_or_create(value=attach['filename'], created=create_t, context=[context])
                    fname.tag([t['name'] for t in tags])
                    # this should be a DUP from threat_nodes in analyse()
                    sha_threat = Hash.get_or_create(value=attach['sha256'], created=create_t, context=[context])
                    sha_threat.active_link_to([md5, fname], "relates", self.name)
                    sha_threat.tag([t['name'] for t in tags])
                    message_contents.append(sha_threat)
                    # link the 3 together
                elif attach['sandboxStatus'] in ['UNSUPPORTED_TYPE', 'TOO_SMALL', None]:
                    attach_unsupported[attach['sandboxStatus']] += 1
                    log.debug(pprint.pformat(attach))
                # add context to the hashes
                guid.active_link_to(message_contents, "delivers", self.name)
        _stats = ', '.join("%s: %d" % (k, v) for k, v in attach_unsupported.items())
        log.warning('Ignored unsupported attachments: %s', _stats)
        for o in event_nodes:
            o.tag([t['name'] for t in tags])
        return event_nodes

    def _make_tenant_base_url(self):
        # Web UI URL for humans
        ti_base_url = "https://threatinsight.proofpoint.com"
        tenant_base_url = "%s/%s" % (ti_base_url, self.config['tenant_id'])
        return tenant_base_url

    def _make_actor_web_url(self, actor_id):
        return '/'.join([self._make_tenant_base_url(), 'actor', actor_id])

    def _make_campaign_web_url(self, campaign_id):
        return '/'.join([self._make_tenant_base_url(), 'campaign', campaign_id])


def _json(response):
    return _filter_response(response).json()


def _response(response):
    return _filter_response(response)


def _filter_response(response):
    if response.status_code == 429:
        raise requests.ConnectionError(response.status_code, response.text)
    elif response.status_code != 200:
        raise requests.ConnectionError(response.status_code, response.text)
    return response


class ProofPointAPI(hammock.Hammock):
    def __init__(self, *args, **kwargs):
        self.__endpoint = 'https://tap-api-v2.proofpoint.com/v2'
        hammock.Hammock.__init__(self, self.__endpoint, *args, **kwargs)
        pass


class CampaignAPI:
    def __init__(self, api):
        self.__api = api

    # curl "https://tap-api-v2.proofpoint.com/v2/campaign/<campaignId> --user "$PRINCIPAL:$SECRET " -s
    def get_campaign(self, campaign_id):
        return _json(self.__api.campaign(campaign_id).GET())


class ForensicsAPI:
    def __init__(self, api):
        self.__api = api

    # curl "https://tap-api-v2.proofpoint.com/v2/forensics?threatId=<threatId>&includeCampaignForensics=false"
    #       --user "$PRINCIPAL:$SECRET" -s
    def get_reports_from_threat(self, threat_id, with_campaign_forensics=False):
        return _json(self.__api.forensics.GET(
            params={'threatId': threat_id, 'includeCampaignForensics': str(with_campaign_forensics).lower()}))

    # curl "https://tap-api-v2.proofpoint.com/v2/forensics?campaignId=<campaignId>" --user "$PRINCIPAL:$SECRET" -s
    def get_reports_from_campaign(self, campaign_id):
        return _json(self.__api.forensics.GET(params={'campaignId': campaign_id}))


class SIEMAPI:
    def __init__(self, api):
        self.__api = api
        self.__params = {'format': 'JSON'}

    @staticmethod
    def make_time_param(frequency=None, interval=None, since_seconds=None, since_time=None):
        if frequency is not None:  # timedelta
            return {'sinceSeconds': frequency.seconds}
        elif interval is not None:
            return {'interval': interval}
        elif since_seconds is not None:
            return {'sinceSeconds': since_seconds}
        elif since_time is not None:
            return {'sinceTime': since_time}
        else:
            raise ValueError('One time param must be specified')

    def params_update(self, time_param):
        params = self.__params.copy()
        params.update(time_param)
        return params

    def get_clicks_blocked(self, time_param):
        params = self.params_update(time_param)
        return _json(self.__api.siem.clicks.blocked.GET(params=params))

    def get_clicks_permitted(self, time_param):
        params = self.params_update(time_param)
        return _json(self.__api.siem.clicks.permitted.GET(params=params))

    def get_messages_blocked(self, time_param):
        params = self.params_update(time_param)
        return _json(self.__api.siem.messages.blocked.GET(params=params))

    def get_messages_delivered(self, time_param):
        params = self.params_update(time_param)
        return _json(self.__api.siem.messages.delivered.GET(params=params))

    def get_issues(self, time_param):
        params = self.params_update(time_param)
        return _json(self.__api.siem.issues.GET(params=params))

    # curl "https://tap-api-v2.proofpoint.com/v2/forensics?threatId=<threatId>&includeCampaignForensics=false"
    #       --user "$PRINCIPAL:$SECRET" -s
    def get_all(self, time_param):
        params = self.params_update(time_param)
        return _json(self.__api.siem.all.GET(params=params))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    feed = ThreatInsight()
    feed.name = ThreatInsight.default_values['name']
    feed.update()

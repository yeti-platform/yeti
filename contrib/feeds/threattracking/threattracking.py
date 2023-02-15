# encoding: utf-8

import logging
from datetime import timedelta

import hammock
import requests
import simplejson as json
from mongoengine.errors import DoesNotExist

from core.config.config import yeti_config
from core.entities import Actor, Campaign, Malware
from core.feed import Feed

# # add configuration to yeti.conf
# [threattracking]
# # https://developers.google.com/sheets/api/quickstart/python
# # activate google sheet api in https://console.developers.google.com/apis/api/sheets.googleapis.com/overview?project=api-project-xxxx
# # create an API key account https://console.developers.google.com/apis/credentials
# google_api_key = "wefkjlwfklweklfwefhklwefhklwefhkl"
#
# # The threat tracking spreadsheet key here (http://apt.threattracking.com)
# # https://docs.google.com/spreadsheets/u/1/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml
# # (this is not a confidential key. It is the public spreadsheet id. keep this unmodified.
# sheet_key = "1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU"


class ThreatTracking(Feed):
    default_values = {
        "frequency": timedelta(days=30),
        "name": "ThreatTracking",
        "source": "http://apt.threattracking.com",
        "description": "This feed contains APT Actor information",
    }

    # define a static index table for each sheet
    target_sheet = {
        "China": {"aliases": "A3:L75", "campaigns": "M:P", "tools": "Q"},
        "Russia": {"aliases": "A3:L17", "campaigns": "M:R", "tools": "S"},
        "North Korea": {"aliases": "A3:J9", "campaigns": "K:L", "tools": "M"},
        "Iran": {"aliases": "A3:F18", "campaigns": "G:I", "tools": "J"},
        "Israel": {"aliases": "A3:B4", "campaigns": "C:D", "tools": "E"},
        "Middle East": {"aliases": "A3:D14", "campaigns": "E:F", "tools": "G"},
        "NATO": {"aliases": "A3:E4", "campaigns": "F:H", "tools": "I"},
        "Others": {"aliases": "A3:D19", "campaigns": "E:G", "tools": "H"},
        "Unknown": {"aliases": "A3:G24", "campaigns": "H:I", "tools": "J"},
    }

    def __init__(self, *args, **kwargs):
        super(ThreatTracking, self).__init__(*args, **kwargs)
        return

    def update(self):
        """ """
        params = {"key": yeti_config.get("threattracking", "google_api_key")}
        # , 'includeGridData': 'True'} - we don't want to do that. 200Mo file.

        base = "https://sheets.googleapis.com/v4/spreadsheets/" + yeti_config.get(
            "threattracking", "sheet_key"
        )
        self.api = hammock.Hammock(base, params=params)
        if False:
            r = self.api.GET()
            if r.status_code != 200:
                raise requests.ConnectionError(
                    "Return code for {query} is {code}".format(
                        query=r.request.url, code=r.status_code
                    )
                )
            sheets = r.json()["sheets"]
            json.dump(sheets, open("actor.sheets.json", "w"))
        else:
            sheets = json.load(open("actor.sheets.json", "r"))
        # print(pprint.pformat(sheets))
        for s_p in sheets:
            s = s_p["properties"]
            title = s["title"]
            if title in ["Home", "_Malware", "_Download", "_Schemes", "_Sources"]:
                continue
            size = s["gridProperties"]
            # print(title, size['columnCount'], size['rowCount'])
            actors_list_info = self.each_sheet_work(s)
            self.create_entities(title, actors_list_info)
        return

    def each_sheet_work(self, sheet):
        # 1. for each actor, get primary name and aliases
        # 2. get the names of campaign
        # 3. get then name of tools
        title = sheet["title"]
        # 1. for each actor, get primary name and aliases
        range_info = self.target_sheet[title]
        names = self.get_aliases(title, range_info)
        # 2. get the names of campaign
        campaigns = self.get_campaign(title, range_info)
        # 3. get then name of tools
        tools = self.get_tools(title, range_info)
        # merge them together
        # for names, campaigns, tools in zip(names, campaigns, tools):
        #     print(names[0], names[1:], campaigns, tools)
        return zip(names, campaigns, tools)

    def get_aliases(self, sheet_name, range_info):
        """returns the list of list of aliases.
        The first name in the list is the primary name"""
        actor_primary_name_range = "!".join([sheet_name, range_info["aliases"]])
        res = self.api.values.GET(actor_primary_name_range).json()
        actor_names = res["values"]
        r_names = []
        for i, actor_aliases in enumerate(actor_names):
            while "" in actor_aliases:
                actor_aliases.remove("")
            while "?" in actor_aliases:
                actor_aliases.remove("?")
            while "???" in actor_aliases:
                actor_aliases.remove("???")
            if len(actor_aliases) == 0:
                actor_aliases.append(sheet_name + "-ACTOR-%d" % i)
            else:
                l = []
                for alias in actor_aliases:
                    if "," in alias:
                        l.extend(alias.split(","))
                    else:
                        l.append(alias)
                actor_aliases = l
            # can't use a set
            actor_aliases = [n.strip() for n in actor_aliases]
            r_names.append(actor_aliases)
        return r_names

    @staticmethod
    def _get_numeric_range(range_info, start_col, end_col):
        range_info_size = range_info["aliases"]
        start, end = range_info_size.split(":")
        # get the numeric ranges
        row_start, row_end = start[1:], end[1:]
        # bring it back together
        return ":".join([start_col + row_start, end_col + row_end])

    def get_campaign(self, sheet_name, range_info):
        """returns the list of list of campaigns."""
        campaign_range = range_info["campaigns"].split(":")
        campaign_value_range = self._get_numeric_range(
            range_info, campaign_range[0], campaign_range[1]
        )
        campaign_value_range = "!".join([sheet_name, campaign_value_range])
        _ = self.api.values.GET(campaign_value_range).json()
        campaign_names = _["values"]
        r_names = []
        for i, campaigns in enumerate(campaign_names):
            while "" in campaigns:
                campaigns.remove("")
            campaigns = list(set(campaigns))
            r_names.append(campaigns)
        return r_names

    def get_tools(self, sheet_name, range_info):
        """returns the list of list of tools."""
        tool_col = range_info["tools"]
        tool_value_range = self._get_numeric_range(range_info, tool_col, tool_col)
        tool_value_range = "!".join([sheet_name, tool_value_range])
        _ = self.api.values.GET(tool_value_range).json()
        tools_names = _["values"]
        r_names = []
        for i, tools in enumerate(tools_names):
            if len(tools) > 0:
                tools = tools[0].split(",")
                tools = [t.strip() for t in tools]
                tools = list(set(tools))
                while "" in tools:
                    tools.remove("")
            r_names.append(tools)
        return r_names

    def create_entities(self, sheet_name, actors_list_info):
        for actor_names, campaigns, tools in actors_list_info:
            primary = actor_names[0]
            # create Actors with aliases
            _actor = Actor.get_or_create(name=primary)
            _actor.aliases = actor_names[1:]
            _actor.save()
            # create the campaign
            for c in campaigns:
                # logging.info(repr(c))
                # BUG Issue #120 - is there a bug where two entities cannot have the same name
                # Naikon the actor conflicts with Naikon the campaign
                _campaign = ""
                try:
                    _campaign = Campaign.get_or_create(name=c)
                except DoesNotExist:
                    _campaign = Campaign.get_or_create(name="CAMPAIGN-" + c)
                _actor.action(_campaign, self.name)
            # create the tools
            for mal in tools:
                _mal = ""
                try:
                    _mal = Malware.get_or_create(name=mal)
                except DoesNotExist:
                    _mal = Malware.get_or_create(name="MALWARE-" + mal)
                _actor.action(_mal, self.name)
        return


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("threattracking").setLevel(level=logging.DEBUG)
    feed = ThreatTracking()
    feed.name = ThreatTracking.default_values["name"]
    feed.update()

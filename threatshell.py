##############################################################################
# Author: Tommy Stallings <tommy.stallings@salesforce.com>
# Copyright (c) 2016, Salesforce.com, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#
#     * Neither the name of Salesforce.com nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
##############################################################################


# TODO: load commands dynamically...maybe...
from dateutil import parser as date_parser
from threatshell.commands.q import AutoQuery
from threatshell.commands.threat_q import ThreatQ
from threatshell.commands.geoip import GeoTools
from threatshell.commands.infoblox import Infoblox
from threatshell.commands.passivetotal import PassiveTotal
from threatshell.commands.riskiq import RiskIQ
from threatshell.commands.novetta import Novetta
from threatshell.commands.conf_manager import ConfigManager
from threatshell.commands.shadow_server import ShadowServer
from threatshell.commands.cymru import Cymru
from threatshell.commands.opendns import OpenDNS_API
from threatshell.commands.umbrella import Umbrella
from threatshell.commands.threat_exchange import ThreatExchange
from threatshell.common.constants import TS_DIR
from threatshell.common.config import Config
from threatshell.common.colors import green, red, magenta, yellow, bold
from threatshell.common.log import (
    init_logging,
    init_console_logger,
    init_file_logger
)
from threatshell.common.logo import logo
from threatshell.doctypes.generic import ThreatshellIndex
from threatshell.utils.argparse_utils import (
    validate_datetime,
    ConvertDateTimeAction
)

from cmd import Cmd
from elasticsearch_dsl import connections

import argparse
import json
import logging
import re
import readline
import shlex
import subprocess
import sys
import time
import traceback
import uuid

if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind ^I rl_complete")
    print (
        "Detected libedit! Don't use it, it sucks! " +
        "History scroll with arrows doesn't work so well " +
        "in libedit because I haven't figured out how to " +
        "get it to ignore color sequences. It doesn't honor " +
        "the readline standard of 0x01 and 0x02 to ignore " +
        "character sequences which causes it to jumble the " +
        "line while moving through previous commands >:("
    )
else:
    readline.parse_and_bind("tab: complete")

log = logging.getLogger(__name__)
es_tracer = logging.getLogger('elasticsearch.trace')
es_tracer.propagate = True

config = Config()
session_uuid = str(uuid.uuid4())

es_connections = [
    x.strip() for x in config.get("ElasticSearch", "servers").split(",")
]

connections.connections.create_connection(
    hosts=es_connections
)

ip_regex = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
tags = []


def build_shell_line():

    current_tags = list(tags)
    shell_line = ""
    if tags:
        if len(current_tags) > 1:
            shell_line = "[%s]+ %s " % (
                magenta(
                    current_tags[0],
                    readline=True
                ),
                green(
                    bold(
                        "tsh>",
                        readline=True
                    ),
                    readline=True
                )
            )
        else:
            shell_line = "[%s] %s " % (
                magenta(
                    current_tags[0],
                    readline=True
                ),
                green(
                    bold(
                        "tsh>",
                        readline=True
                    ),
                    readline=True
                )
            )
    else:
        shell_line = green(
            bold(
                "tsh> ",
                readline=True
            ),
            readline=True
        )
    return shell_line


class MyPrompt(Cmd):

    history_file = "%s/tshell_history" % TS_DIR

    def __init__(self, args):

        Cmd.__init__(self)

        self.args = args
        self.threat_q = ThreatQ(config)
        self.geo_tools = GeoTools(config)
        self.infoblox = Infoblox(config)
        self.passive_total = PassiveTotal(config)
        self.riq = RiskIQ(config)
        self.novetta = Novetta(config)
        self.config_manager = ConfigManager(config)
        self.ss = ShadowServer()
        self.cymru = Cymru()
        self.opendns = OpenDNS_API(config)
        self.umbrella = Umbrella(config)
        self.tx = ThreatExchange(config)

        self.module_map = {}
        for entry in dir(self):
            entry = getattr(self, entry)
            if hasattr(entry, "__module__"):
                if "commands" in entry.__module__:
                    self.module_map[entry.__module__] = entry

        try:
            readline.read_history_file(self.history_file)
        except IOError:
            pass

        readline.set_history_length(300)  # TODO: Maybe put this in a config

    def _convert(self, t):
        return date_parser.parse(t)

    def _default(self, x):
        if(
            hasattr(x, "_d_") and
            getattr(x, "_d_") is not None and
            getattr(x, "_d_") != {}
        ):
            return x._d_

        return str(x)

    def _handle_response(self, es_docs):

        global tags

        if not isinstance(es_docs, list):
            es_docs = [es_docs]

        for es_doc in es_docs:
            try:
                setattr(es_doc, "session_uuid", session_uuid)
                setattr(es_doc, "tags", list(tags))

                # print "%s: %s" % (
                #     es_doc._type,
                #     json.dumps(es_doc, indent=4, default=self._default)
                # )

                es_doc.save()
                doc_name = "%s.%s Record" % (
                    ".".join(
                        es_doc.__module__.split(".")[2:]
                    ),
                    es_doc.__class__.__name__
                )
                print yellow(
                    "\n%s\n%s" % (
                        doc_name,
                        "-" * len(doc_name)
                    )
                )
                print json.dumps(es_doc, indent=4, default=self._default)

            except Exception as e:
                print str(es_docs)
                log.error(
                    "[%s]: %s - %s" % (
                        e.__class__.__name__,
                        e.message,
                        str(es_doc)
                    )
                )

    # TODO: Add openDNS
    def do_q(self, cmd_args):
        # """Query ThreatQ for an indicator"""
        """ OUT OF DATE! NEEDS TO BE UPDATED"""
        # print "Function not ready for use"
        # return
        parser = argparse.ArgumentParser(
            usage="q",
        )
        parser.add_argument(
            "--ip",
            action="store",
            nargs="+",
            default=None,
            required=False,
            help="Specify one or more IPs to auto query"
        )
        parser.add_argument(
            "--url",
            action="store",
            nargs="+",
            default=None,
            required=False,
            help="Specify one or more urls to auto query"
        )
        parser.add_argument(
            "--domain",
            action="store",
            nargs="+",
            default=None,
            required=False,
            help="Specify one of more domains to auto query"
        )

        split_args = shlex.split(cmd_args)
        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        def organize(args):
            kwargs = args._get_kwargs()
            arg_dict = {}

            for a in kwargs:
                if a[1] is None:
                    continue
                if not isinstance(a[1], list):
                    arg_dict[a[0]] = [a[1]]
                else:
                    arg_dict[a[0]] = a[1]

            return arg_dict

        indicators = organize(parsed_args)
        log.debug(json.dumps(indicators, indent=4))

        es_docs = []  # TODO: Make this multi-threaded
        # display_docs = []
        for t in indicators.keys():
            log.debug("Getting methods for indicator type %s" % t)
            methods = AutoQuery.query_table.get(t)

            if methods is None:
                log.warn("No methods found for type %s" % t)
                continue

            for m in methods:
                try:
                    instance = self.module_map.get(m.__module__)
                    func = getattr(instance, m.__name__)
                    # m_class = str(func.im_class).split(".")[-1]
                    # m_name = m.__name__
                    results = func(indicators[t])
                    es_docs.extend(results)
                    # for res in results:
                    #     display_docs.append(
                    #         {m_class + "." + m_name: res.response.to_dict()}
                    #     )
                except Exception, e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    lines = traceback.format_exception(
                        exc_type,
                        exc_value,
                        exc_traceback
                    )
                    lines = "\n\t".join([x.strip() for x in lines])

                    log.error(
                        "Error executing function %s - [%s]: %s\n\t%s" % (
                            m.__name__,
                            e.__class__.__name__,
                            str(e),
                            lines
                        )
                    )

        # for doc in display_docs:
        #     print json.dumps(doc, indent=4)
        self._handle_response(es_docs)

    def do_tq_status(self, cmd_args):
        """List ThreatQ Indicator Statuses"""
        jdata = self.threat_q.indicator_statuses(cmd_args)
        if jdata:
            print json.dumps(jdata, indent=4)

    def do_tq_types(self, cmd_args):
        """List ThreatQ Indicator Types"""
        jdata = self.threat_q.indicator_types(cmd_args)
        if jdata:
            print json.dumps(jdata, indent=4)

    def do_tq_add(self, cmd_args):
        """Add an indicator to ThreatQ. See --help for required arguments"""
        resp_content = self.threat_q.add_indicator(cmd_args)
        print resp_content

    def do_tqcs(self, cmd_args):
        """
        ThreatQ change status
        Change indicator status in ThreatQ. See --help for required arguments
        """
        resp_content = self.threat_q.update_indicator_status(cmd_args)
        print resp_content

    def do_tq_search(self, cmd_args):
        """
        Search ThreatQ for an indicator
        """
        resp_content = self.threat_q.query(cmd_args)
        if resp_content:
            print json.dumps(resp_content, indent=4)

    def do_geo_update(self, cmd_args):
        """Update (or install) the geo IP database"""
        db_names = self.geo_tools.update()
        if db_names:
            print "Successfully downloaded:\n\n\t%s\n" % "\n\t".join(db_names)
        else:
            print "Update appears to have failed :'("

    def do_geo(self, cmd_args):
        """Use geolocation to find a given domain name or IP address"""
        if not self.geo_tools.can_geolocate():
            print (
                "Unable to do geolocation - no DB files. Use geo_update to " +
                "download them"
            )
            return
        es_doc = self.geo_tools.city_lookup(cmd_args)
        if es_doc:
            self._handle_response(es_doc)

    def do_geo_country(self, cmd_args):
        """
        Use geolocation to find the country hosting a given domain name
         or IP address. This command supports additional arguments.
         See geo_country --help for more info.
        """
        if not self.geo_tools.can_geolocate():
            print (
                "Unable to do geolocation - no DB files. Use geo_update to " +
                "download them"
            )
            return
        es_doc = self.geo_tools.country_lookup(cmd_args)
        if es_doc:
            self._handle_response(es_doc)

    def do_geo_asn(self, cmd_args):
        """
        Use geolocation to find the ASN information of a given domain
         or IP address
        """
        if not self.geo_tools.can_geolocate():
            print (
                "Unable to do geolocation - no DB files. Use geo_update to " +
                "download them"
            )
            return
        es_doc = self.geo_tools.as_lookup(cmd_args)
        if es_doc:
            self._handle_response(es_doc)

    def do_iblx(self, cmd_args):
        """
        Infoblox
        Lookup the given target in infoblox
        """
        parser = argparse.ArgumentParser(
            usage="iblx"
        )
        parser.add_argument(
            "indicator",
            action="store",
            help="Specify the indicator to query for"
        )

        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return
        es_docs = self.infoblox.search(parsed_args.indicator)
        if es_docs:
            self._handle_response(es_docs)

    def do_pt_account(self, cmd_args):
        """
        Title: PassiveTotal account info
        Description: Get information about your PassiveTotal account
        Arguments: No
        """
        account_info = self.passive_total.get_account_info()
        print json.dumps(account_info, indent=4)

    def do_pt_ahist(self, cmd_args):
        """
        Title: PassiveTotal account history
        Description: Get historical information about your PassiveTotal account
        Arguments: No
        """
        account_hist = self.passive_total.get_account_history()
        print json.dumps(account_hist, indent=4)

    def do_pt_notifications(self, cmd_args):
        """
        Title: PassiveTotal account notifications
        Description: Get notifications posted to your PassiveTotal account
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_notifications"
        )
        parser.add_argument(
            "-t",
            "--type",
            action="store",
            required=False,
            default=None,
            help=(
                "Specify the notification type to retrieve"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        notifications = self.passive_total.get_account_notifications(
            params=dict(parsed_args._get_kwargs())
        )
        print json.dumps(notifications, indent=4)

    def do_pt_org_info(self, cmd_args):
        """
        Title: PassiveTotal Organization information
        Description: Get information about your account's organization
        Arguments: No
        """
        org_details = self.passive_total.get_organization_details()
        print json.dumps(org_details, indent=4)

    def do_pt_org_teamstream(self, cmd_args):
        """
        Title: PassiveTotal Organization teamstream
        Description: Get the teamstream for your account's organization
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_org_teamstream"
        )
        parser.add_argument(
            "-s",
            "--source",
            action="store",
            required=False,
            default=None,
            choices=["web", "api"],
            help="Source of the action"
        )
        parser.add_argument(
            "-dt",
            action="store",
            metavar="MM-DD-YYYY HH:MM:SS",
            required=False,
            default=None,
            type=validate_datetime,
            help="Datetime to be used as a filter"
        )
        parser.add_argument(
            "-t",
            "--type",
            action="store",
            required=False,
            default=None,
            choices=["search", "classify", "tag", "watch"],
            metavar="TYPE",
            help=(
                "Type of tagstream event to retrieve. Choose from any of " +
                "the following: %s" % (
                    ", ".join(["search", "classify", "tag", "watch"])
                )
            )
        )
        parser.add_argument(
            "-f",
            "--focus",
            action="store",
            required=False,
            default=None,
            help=(
                "Specify a specific value that was used as the focus of the " +
                "tagstream"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        org_teamstream = self.passive_total.get_organization_teamstream(
            params=dict(parsed_args._get_kwargs())
        )
        print json.dumps(org_teamstream, indent=4)

    def do_pt_source_config(self, cmd_args):
        """
        Title: PassiveTotal Intel Source Configuration
        Description: Get details and configurations for intel sources
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_source_config"
        )
        parser.add_argument(
            "sources",
            action="store",
            nargs="*",
            help="Name of intel source(s) to pull back"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        source_configs = self.passive_total.get_source_details(
            parsed_args.sources
        )
        print json.dumps(source_configs, indent=4)

    def do_pt_pdns(self, cmd_args):
        """
        Title: PassiveTotal Passive DNS
        Description: Get passive DNS data from PassiveTotal
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_pdns"
        )
        parser.add_argument(
            "domains",
            action="store",
            nargs="+",
            help="One or more domains to query for"
        )
        parser.add_argument(
            "-d",
            "--direction",
            action="store",
            choices=["next", "previous"],
            default=None,
            required=False,
            help="Pagination direction"
        )
        parser.add_argument(
            "-p",
            "--page",
            action="store",
            default=None,
            required=False,
            help="Page ID to request"
        )
        parser.add_argument(
            "-s",
            "--sources",
            action="store",
            default=None,
            required=False,
            nargs="+",
            help="select one or more sources to process with"
        )
        parser.add_argument(
            "-b",
            "--start",
            action="store",
            metavar="yyyy-mm-dd",  # TODO: Add validation
            default=None,
            required=False,
            help="only show data starting on given date"
        )
        parser.add_argument(
            "-e",
            "--end",
            action="store",
            metavar="yyyy-mm-dd",
            required=False,
            default=None,
            help="only show data up to given date"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        doms = params["domains"]

        del params["domains"]
        if params["sources"]:
            params["sources"] = ",".join(params["sources"])

        es_docs = self.passive_total.get_passive_dns(doms, params=params)
        self._handle_response(es_docs)

    def do_pt_unique_pdns(self, cmd_args):
        """
        Title: PassiveTotal Unique Passive DNS
        Description: Get passive DNS data from PassiveTotal
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_unique_pdns"
        )
        parser.add_argument(
            "domains",
            action="store",
            nargs="+",
            help="One or more domains to query for"
        )
        parser.add_argument(
            "-d",
            "--direction",
            action="store",
            choices=["next", "previous"],
            default=None,
            required=False,
            help="Pagination direction"
        )
        parser.add_argument(
            "-p",
            "--page",
            action="store",
            default=None,
            required=False,
            help="Page ID to request"
        )
        parser.add_argument(
            "-s",
            "--sources",
            action="store",
            default=None,
            required=False,
            nargs="+",
            help="select one or more sources to process with"
        )
        parser.add_argument(
            "-b",
            "--start",
            action="store",
            metavar="yyyy-mm-dd",  # TODO: Add validation
            default=None,
            required=False,
            help="only show data starting on given date"
        )
        parser.add_argument(
            "-e",
            "--end",
            action="store",
            metavar="yyyy-mm-dd",
            required=False,
            default=None,
            help="only show data up to given date"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        doms = params["domains"]

        del params["domains"]
        if params["sources"]:
            params["sources"] = ",".join(params["sources"])

        es_docs = self.passive_total.get_unique_passive_dns(
            doms,
            params=params
        )
        self._handle_response(es_docs)

    def do_pt_domain_enrich(self, cmd_args):
        """
        Title: PassiveTotal Domain Enrichment
        Description: Get domain enrichment metadata from PassiveTotal
        Arguments: yes
        """

        parser = argparse.ArgumentParser(
            usage="pt_domain_enrich"
        )
        parser.add_argument(
            "domains",
            action="store",
            nargs="+",
            help="specify one or more domains to get enrichment for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_domain_enrichment(parsed_args.domains)
        self._handle_response(es_docs)

    def do_pt_ip_enrich(self, cmd_args):
        """
        Title: PassiveTotal IP Enrichment
        Description: Get IP enrichment metadata from PassiveTotal
        Arguments: yes
        """

        parser = argparse.ArgumentParser(
            usage="pt_ip_enrich"
        )
        parser.add_argument(
            "ips",
            action="store",
            nargs="+",
            help="specify one or more ips to get enrichment for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_ip_enrichment(parsed_args.ips)
        self._handle_response(es_docs)

    def do_pt_malware_enrich(self, cmd_args):
        """
        Title: PassiveTotal Malware Enrichment
        Description: Get malware enrichment metadata from PassiveTotal
        Arguments: yes
        """

        parser = argparse.ArgumentParser(
            usage="pt_malware_enrich"
        )
        parser.add_argument(
            "query",
            action="store",
            nargs="+",
            help="specify one or more ips to get enrichment for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_malware_enrichment(parsed_args.query)
        self._handle_response(es_docs)

    def do_pt_osint_enrich(self, cmd_args):
        """
        Title: PassiveTotal OSInt Enrichment
        Description: Get OSInt enrichment metadata from PassiveTotal
        Arguments: yes
        """

        parser = argparse.ArgumentParser(
            usage="pt_osint_enrich"
        )
        parser.add_argument(
            "query",
            action="store",
            nargs="+",
            help="specify one or more indicators to get enrichment for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_osint_enrichment(parsed_args.query)
        self._handle_response(es_docs)

    def do_pt_subdom_enrich(self, cmd_args):
        """
        Title: PassiveTotal Subdomain Enrichment
        Description: Get Subdomain enrichment metadata from PassiveTotal
        Arguments: yes
        """

        parser = argparse.ArgumentParser(
            usage="pt_subdom_enrich"
        )
        parser.add_argument(
            "query",
            action="store",
            nargs="+",
            help="specify one or more domains to get enrichment for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_subdomain_enrichment(
            parsed_args.query
        )
        self._handle_response(es_docs)

    def do_pt_whois(self, cmd_args):
        """
        Title: PassiveTotal Whois lookup
        Description: Get whois data from PassiveTotal
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_whois"
        )
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            help="specify one or more domains/ips to get whois data for"
        )
        parser.add_argument(
            "-c",
            "--compact_record",
            action="store_true",
            default=False,
            required=False,
            help="compress the whois record into deduplicated format"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        del params["queries"]

        es_docs = self.passive_total.get_whois(
            parsed_args.queries,
            params=params
        )
        self._handle_response(es_docs)

    def do_pt_whois_search(self, cmd_args):
        """
        Title: PassiveTotal Whois Search
        Description: Search fields in Whois data from PassiveTotal
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_whois_search"
        )
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            help="specify one or more domains to get whois data for"
        )
        parser.add_argument(
            "-f",
            "--field",
            action="store",
            choices=[
                "name",
                "domain",
                "email",
                "organization",
                "address",
                "phone",
                "nameserver"
            ],
            required=True,
            default=None,
            metavar="FIELD",
            help=(
                "Whois field to execute search on. Searchable fields can " +
                "any of the following: %s" % (
                    ", ".join(
                        [
                            "name",
                            "domain",
                            "email",
                            "organization",
                            "address",
                            "phone",
                            "nameserver"
                        ]
                    )
                )
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        del params["queries"]

        es_docs = self.passive_total.search_whois(
            parsed_args.queries,
            params=params
        )
        self._handle_response(es_docs)

    def do_pt_add_tags(self, cmd_args):
        """
        Title: PassiveTotal Add tags
        Description: Add tags to the associated query value
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_add_tags"
        )
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="Add tags to this indicator"
        )
        parser.add_argument(
            "-t",
            "--tags",
            action="store",
            nargs="+",
            required=True,
            default=None,
            help="The tags to be added"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        resp = self.passive_total.add_tags(params)
        print json.dumps(resp, indent=4)

    def do_pt_get_tags(self, cmd_args):
        """
        Title: PassiveTotal Get Tags
        Description: Get tags for the associated query value
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_get_tags"
        )
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="Get tags for this indicator"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        resp = self.passive_total.get_tags(parsed_args.query)
        print json.dumps(resp, indent=4)

    def do_pt_rm_tags(self, cmd_args):
        """
        Title: PassiveTotal Remove tags
        Description: Remove tags for the associated query value
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_rm_tags"
        )
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="Add tags to this indicator"
        )
        parser.add_argument(
            "-t",
            "--tags",
            action="store",
            nargs="+",
            required=True,
            default=None,
            help="The tags to be removed"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        resp = self.passive_total.rm_tags(params)
        print json.dumps(resp, indent=4)

    def do_pt_class(self, cmd_args):
        """
        Title: PassiveTotal Classification
        Description: Get the PassiveTotal threat classification for a domain
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_class"
        )
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            default=None,
            help="Indicator to classify"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_classification_status(
            parsed_args.queries
        )
        self._handle_response(es_docs)

    def do_pt_search_tags(self, cmd_args):
        """
        Title: PassiveTotal Search tags
        Description: Search tags for the associated query value
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_search_tags"
        )
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            default=None,
            help="Add tags to this indicator"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        docs = self.passive_total.search_tags(parsed_args.queries)
        print json.dumps(docs, indent=4)

    def do_pt_compromised(self, cmd_args):
        """
        Title: PassiveTotal Compromised History
        Description: Check PassiveTotal to see if site was ever compromised
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_compromised"
        )
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            default=None,
            help="Domain(s) and/or IP(s) to check history of"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_compromised_status(
            parsed_args.queries
        )
        self._handle_response(es_docs)

    def do_pt_check_ddns(self, cmd_args):
        """
        Title: PassiveTotal Dynamic DNS Check
        Description: Check PassiveTotal to see if domain is on ddns
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_check_ddns"
        )
        parser.add_argument(
            "domains",
            action="store",
            nargs="+",
            default=None,
            help="Domain(s) to check"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.check_dynamic_dns(
            parsed_args.domains
        )
        self._handle_response(es_docs)

    def do_pt_check_monitor(self, cmd_args):
        """
        Title: PassiveTotal Monitoring Status
        Description: Check if you are monitoring a given domain/IP
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_check_monitor"
        )
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            default=None,
            help="Domain(s) and/or IP(s) to check monitoring status of"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        docs = self.passive_total.get_monitor_status(parsed_args.queries)
        print json.dumps(docs, indent=4)

    def do_pt_check_sinkhole(self, cmd_args):
        """
        Title: PassiveTotal Check Sinkhole Status
        Description: Check if the given IP is a sinkhole
        Arguments: yes
        """
        parser = argparse.ArgumentParser(
            usage="pt_check_sinkhole"
        )
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            default=None,
            help="IP(s) to check sinkhole status of"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        docs = self.passive_total.get_sinkhole_status(parsed_args.queries)
        print json.dumps(docs, indent=4)

    def do_pt_set_class(self, cmd_args):
        """
        Title: PassiveTotal Set Classification
        Description: Set the classification for a domain/IP
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_set_class")
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="The domain or IP to classify"
        )
        parser.add_argument(
            "-c",
            "--classification",
            action="store",
            required=True,
            default=None,
            choices=[
                "malicious",
                "suspicious",
                "non-malicious",
                "unknown"
            ],
            metavar="CLASS",
            help=(
                (
                    "Classification for the given indicator. Choose from " +
                    "one of the following: %s"
                ) % (
                    ", ".join(
                        [
                            "malicious",
                            "suspicious",
                            "non-malicious",
                            "unknown"
                        ]
                    )
                )
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        resp = self.passive_total.set_classification_status(params)
        print json.dumps(resp, indent=4)

    def do_pt_set_compromised(self, cmd_args):
        """
        Title: PassiveTotal Set Compromised Status
        Description: Set the compromised status for a domain/IP
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_set_compromised")
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="The domain or IP to set compromised status for"
        )
        parser.add_argument(
            "-s",
            "--status",
            action="store",
            required=True,
            default=None,
            type=lambda x: str(x).lower() == "true" or str(x).lower() == "t",
            help=(
                "Classification for the given indicator. Can be true/false " +
                "or t/f for short"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        resp = self.passive_total.set_compromised_status(params)
        print json.dumps(resp, indent=4)

    def do_pt_set_ddns(self, cmd_args):
        """
        Title: PassiveTotal Set Dynamic DNS Status
        Description: Set the dynamic DNS status for a domain
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_set_ddns")
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="The domain to set dynamic DNS status for"
        )
        parser.add_argument(
            "-s",
            "--status",
            action="store",
            required=True,
            default=None,
            type=lambda x: str(x).lower() == "true" or str(x).lower() == "t",
            help=(
                "Status for the given indicator. Can be true/false " +
                "or t/f for short"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        resp = self.passive_total.set_ddns_status(params)
        print json.dumps(resp, indent=4)

    def do_pt_set_monitor(self, cmd_args):
        """
        Title: PassiveTotal Set Monitor Status
        Description: Set the monitoring status for a domain/IP
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_set_monitor")
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="The domain or IP to set monitor status for"
        )
        parser.add_argument(
            "-s",
            "--status",
            action="store",
            required=True,
            default=None,
            type=lambda x: str(x).lower() == "true" or str(x).lower() == "t",
            help=(
                "Classification for the given indicator. Can be true/false " +
                "or t/f for short"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        resp = self.passive_total.set_monitor_status(params)
        print json.dumps(resp, indent=4)

    def do_pt_set_sinkhole(self, cmd_args):
        """
        Title: PassiveTotal Set Sinkhole Status
        Description: Set the sinkhole status for an IP
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_set_sinkhole")
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="The IP to set sinkhole status for"
        )
        parser.add_argument(
            "-s",
            "--status",
            action="store",
            required=True,
            default=None,
            type=lambda x: str(x).lower() == "true" or str(x).lower() == "t",
            help=(
                "Classification for the given indicator. Can be true/false " +
                "or t/f for short"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        resp = self.passive_total.set_sinkhole_status(params)
        print json.dumps(resp, indent=4)

    def do_pt_host_components(self, cmd_args):
        """
        Title: PassiveTotal Get Host Components
        Description: Get detailed information about a host
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_host_components")
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            default=None,
            help="The domain(s) to get component iformation for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_host_components(parsed_args.queries)
        self._handle_response(es_docs)

    def do_pt_host_trackers(self, cmd_args):
        """
        Title: PassiveTotal Get Host Trackers
        Description: Get tracking codes for a domain or IP
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_host_trackers")
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            default=None,
            help="The domain or IP to get tracking codes for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_host_trackers(parsed_args.queries)
        self._handle_response(es_docs)

    def do_pt_tracker_search(self, cmd_args):
        """
        Title: PassiveTotal Search Host Trackers
        Description: Get hosts matching a specific tracking ID
        Arguments: yes
        """
        trackers = [
            "YandexMetricaCounterId",
            "ClickyId",
            "GoogleAnalyticsAccountNumber",
            "GoogleAnalyticsTrackingId",
            "NewRelicId",
            "MixpanelId"
        ]
        parser = argparse.ArgumentParser(usage="pt_tracker_search")
        parser.add_argument(
            "query",
            action="store",
            default=None,
            help="The value to use for the search"
        )
        parser.add_argument(
            "--type",
            action="store",
            required=True,
            default=None,
            metavar="TRACKER",
            choices=trackers,
            help=(
                "The type of tracker to use for the search. Allowed " +
                "choices are the following - %s"
            ) % (", ".join(trackers))
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        es_docs = self.passive_total.search_host_trackers(params)
        self._handle_response(es_docs)

    def do_pt_ssl_history(self, cmd_args):
        """
        Title: PassiveTotal SSL Cert History
        Description: Get the SSL Cert history for a given IP or domain
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_ssl_history")
        parser.add_argument(
            "queries",
            action="store",
            nargs="+",
            help="The domain or IP to get cert history for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_ssl_cert_history(parsed_args.queries)
        self._handle_response(es_docs)

    def do_pt_get_ssl_cert(self, cmd_args):
        """
        Title: PassieTotal Get SSL Cert
        Description: Get the SSL certificate for the given sha1
        Arguments: yes
        """
        parser = argparse.ArgumentParser(usage="pt_get_ssl_cert")
        parser.add_argument(
            "queries",
            nargs="+",
            action="store",
            help="One or more sha1 hashes to get ssl certs for"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.passive_total.get_ssl_cert(parsed_args.queries)
        self._handle_response(es_docs)

    def do_pt_search_ssl(self, cmd_args):
        """
        Title: PassiveTotal SSL Cert Search
        Description: Search SSL Cert fields for particular values
        Arguments: yes
        """
        fields = [
            "issuerSurname",
            "subjectOrganizationName",
            "issuerCountry",
            "issuerOrganizationUnitName",
            "fingerprint",
            "subjectOrganizationUnitName",
            "serialNumber",
            "subjectEmailAddress",
            "subjectCountry",
            "issuerGivenName",
            "subjectCommonName",
            "issuerCommonName",
            "issuerStateOrProvinceName",
            "issuerProvince",
            "subjectStateOrProvinceName",
            "sha1",
            "sslVersion",
            "subjectStreetAddress",
            "subjectSerialNumber",
            "issuerOrganizationName",
            "subjectSurname",
            "subjectLocalityName",
            "issuerStreetAddress",
            "issuerLocalityName",
            "subjectGivenName",
            "subjectProvince",
            "issuerSerialNumber",
            "issuerEmailAddress"
        ]
        parser = argparse.ArgumentParser(usage="pt_search_ssl")
        parser.add_argument(
            "query",
            action="store",
            help="The value of the field to search with"
        )
        parser.add_argument(
            "-f",
            "--field",
            action="store",
            metavar="FIELD",
            choices=fields,
            help=(
                "The field to search. Valid choices are - %s"
            ) % ", ".join(fields)
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        params = dict(parsed_args._get_kwargs())
        es_docs = self.passive_total.search_ssl_certs(params)
        self._handle_response(es_docs)

    def do_riq_pdns(self, cmd_args):
        """
        RiskIQ passive DNS for IPs and Domains
        """
        es_doc = self.riq.passive_dns(cmd_args)
        if es_doc:
            self._handle_response(es_doc)

    def do_nvwhois(self, cmd_args):
        """
        Look up whois information using the Novetta whois API
        """
        es_doc = self.novetta.whodat(cmd_args)
        if es_doc:
            self._handle_response(es_doc)

    def do_ss_asorigin(self, cmd_args):
        """
        Look up ASN origin information about the given domain or
        IP from Shadow Server
        """
        parser = argparse.ArgumentParser(
            usage="ss_asorigin"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s)/IP(s) to query for. Can be a space " +
                "delimited list of domains and/or IPs"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = []
        if len(parsed_args.indicator) == 1:
            es_docs = self.ss.asn_origin(parsed_args.indicator[0])
        else:
            es_docs = self.ss.batch_asn_origin(parsed_args.indicator)

        if es_docs:
            self._handle_response(es_docs)

    def do_ss_aspeers(self, cmd_args):
        """
        Look up ASN peer information about a given domain or IP from
        Shadow Server
        """
        parser = argparse.ArgumentParser(
            usage="ss_aspeers"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s)/IP(s) to query for. Can be a space " +
                "delimited list of domains and/or IPs"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = []
        if len(parsed_args.indicator) == 1:
            es_docs = self.ss.asn_peers(parsed_args.indicator[0])
        else:
            es_docs = self.ss.batch_asn_peers(parsed_args.indicator)

        if es_docs:
            self._handle_response(es_docs)

    def do_ss_asnum_prefix(self, cmd_args):
        """
        Look up ASN prefix information for an ASN number from
        Shadow Server ASN
        """
        es_doc = self.ss.asnum_to_prefix(cmd_args)
        if es_doc:
            self._handle_response(es_doc)

    def do_cymru_asinfo(self, cmd_args):
        """
        Look up ASN information about a given domain or IP from
        Cymru
        """
        parser = argparse.ArgumentParser(
            usage="cymru_asinfo"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s)/IP(s) to query for. Can be a space " +
                "delimited list of domains and/or IPs"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = []
        if len(parsed_args.indicator) == 1:
            es_docs = self.cymru.asn_info(parsed_args.indicator[0])
        else:
            es_docs = self.cymru.batch_asn_info(parsed_args.indicator)

        if es_docs:
            self._handle_response(es_docs)

    def do_cymru_asnum_info(self, cmd_args):
        """
        Look up ASN information about a given ASN number from
        Cymru
        """
        parser = argparse.ArgumentParser(
            usage="cymru_asnum_info"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the number(s) to query for. Can be a space " +
                "delimited list of ASN numbers"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = []
        if len(parsed_args.indicator) == 1:
            es_docs = self.cymru.asnum_to_name(parsed_args.indicator[0])
        else:
            es_docs = self.cymru.batch_asnum_to_name(parsed_args.indicator)

        if es_docs:
            self._handle_response(es_docs)

    def do_odns_category(self, cmd_args):
        """
        Look up category information for a given domain from
        OpenDNS. See -h or --help for additional options
        """
        parser = argparse.ArgumentParser(
            usage="odns_category"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s) to query for. Can be a space " +
                "delimited list of domains"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.opendns.request_categories_batch(
            parsed_args.indicator
        )
        if es_docs:
            self._handle_response(es_docs)

    def do_odns_dns_info(self, cmd_args):
        """
        Look up DNS info for a given domain or IP from OpenDNS.
        Use -h or --help for additional options
        """
        parser = argparse.ArgumentParser(
            usage="odns_dns_info"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s)/IP(s) to query for. Can be a space " +
                "delimited list of domains"
            )
        )
        parser.add_argument(
            "-rt",
            "--record_type",
            choices=["a", "ns", "mx", "txt", "cname"],
            action="store",
            default="a",
            required=False,
            help="Specify the type of DNS record to look up info for"
        )
        parser.add_argument(
            "-irt",
            "--ip_record_type",
            choices=["a", "ns"],
            action="store",
            default="a",
            required=False,
            help="Specify the type of DNS records for IP lookup info"
        )

        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        domains = []
        ips = []

        es_docs = []
        for indicator in parsed_args.indicator:
            if ip_regex.match(indicator):
                ips.append(indicator)
            else:
                domains.append(indicator)

        if domains:
            es_docs += self.opendns.request_dns_info(
                domains,
                rtype=parsed_args.record_type
            )
        if ips:
            es_docs += self.opendns.request_ip_dns_info(
                ips,
                rtype=parsed_args.ip_record_type
            )
        if es_docs:
            self._handle_response(es_docs)

    def do_odns_mal_index(self, cmd_args):
        """
        Look up malicious status of domain from OpenDNS.
        Use the -h or --help for additional options
        """
        parser = argparse.ArgumentParser(
            usage="odns_mal_index"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s) to query for. Can be a space " +
                "delimited list of domains"
            )
        )
        parser.add_argument(
            "-b",
            "--use_batch",
            required=False,
            action="store_true",
            default=False,
            help="Use the batch lookup rather than a request per domain"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = []
        if parsed_args.use_batch:
            es_docs = self.opendns.request_known_malicious_index_batch(
                parsed_args.indicator
            )
        else:
            es_docs = self.opendns.request_known_malicious_index(
                parsed_args.indicator
            )

        if es_docs:
            self._handle_response(es_docs)

    def do_odns_co_occurs(self, cmd_args):
        """
        Look up co-occurring domains for a given domain from
        OpenDNS. Use -h or --help for additional options
        """
        parser = argparse.ArgumentParser(
            usage="odns_co_occurs"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s) to query for. Can be a space " +
                "delimited list of domains"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.opendns.request_co_occurences(parsed_args.indicator)
        if es_docs:
            self._handle_response(es_docs)

    def do_odns_related_doms(self, cmd_args):
        """
        Look up related domains for a given domain from OpenDNS.
        Use -h or --help for additional options
        """
        parser = argparse.ArgumentParser(
            usage="odns_related_doms"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s) to query for. Can be a space " +
                "delimited list of domains"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.opendns.request_related_domains(parsed_args.indicator)
        if es_docs:
            self._handle_response(es_docs)

    def do_odns_security_info(self, cmd_args):
        """
        Look up OpenDNS secure graph security feature rankings.
        Use -h or --help for additional options
        """
        parser = argparse.ArgumentParser(
            usage="odns_security_info"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the domain(s) to query for. Can be a space " +
                "delimited list of domains"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.opendns.request_security_info(parsed_args.indicator)
        if es_docs:
            self._handle_response(es_docs)

    def do_odns_whois_email(self, cmd_args):
        """
        Look up whois information from a given email or space delimited
        list of emails from OpenDNS
        """
        parser = argparse.ArgumentParser(
            usage="odns_whois_email"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the email(s) to query for. Can be a space " +
                "delimited list of emails"
            )
        )
        parser.add_argument(
            "-l",
            "--limit",
            action="store",
            required=False,
            default=10,
            help="Set the limit of entries to be returned"
        )
        # TODO: add opt to filter for only current domains
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.opendns.request_whois_email(
            parsed_args.indicator,
            limit=parsed_args.limit
        )
        if es_docs:
            self._handle_response(es_docs)

    def do_odns_whois(self, cmd_args):
        """
        Look up whois information for a given domain from OpenDNS
        """
        parser = argparse.ArgumentParser(
            usage="odns_whois"
        )
        parser.add_argument(
            "indicator",
            action="store",
            help=("Specify the domain to query for")
        )
        parser.add_argument(
            "-t",
            "--history",
            action="store_true",
            required=False,
            default=False,
            help="Look up historical whois for the given domain"
        )
        parser.add_argument(
            "-l",
            "--limit",
            action="store",
            required=False,
            default=10,
            help="Set the limit of history entries to be returned"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.opendns.request_whois_domain(
            parsed_args.indicator,
            limit=parsed_args.limit,
            history=parsed_args.history
        )
        if es_docs:
            self._handle_response(es_docs)

    def do_odns_whois_ns(self, cmd_args):
        """
        Look up whois information from a given name server or space delimited
        list of name servers from OpenDNS
        """
        parser = argparse.ArgumentParser(
            usage="odns_whois_ns"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the name server(s) to query for. Can be a space " +
                "delimited list of emails"
            )
        )
        parser.add_argument(
            "-l",
            "--limit",
            action="store",
            required=False,
            default=10,
            help="Set the limit of entries to be returned"
        )
        # TODO: add opt to filter for only current domains
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.opendns.request_whois_nameserver(
            parsed_args.indicator,
            limit=parsed_args.limit
        )
        if es_docs:
            self._handle_response(es_docs)

    def do_odns_mal_doms(self, cmd_args):
        """
        Look up the latest malicious domains for a given IP address
        or a space delimited list of IP addresses
        """
        parser = argparse.ArgumentParser(
            usage="odns_mal_doms"
        )
        parser.add_argument(
            "indicator",
            action="store",
            nargs="+",
            help=(
                "Specify the name server(s) to query for. Can be a space " +
                "delimited list of emails"
            )
        )

        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.opendns.request_mal_domains_for_ip(
            parsed_args.indicator
        )
        if es_docs:
            self._handle_response(es_docs)

    def do_umbrella_block(self, cmd_args):
        """
        Add a URL/domain to the OpenDNS Umbrella service block list
        """
        parser = argparse.ArgumentParser(
            usage="umbrella_block"
        )
        parser.add_argument(
            "url",
            action="store",
            help=(
                "Specify the URL/domain to block in Umbrella"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        response = self.umbrella.add_blocked_domain(parsed_args.url)
        if response:
            print json.dumps(response, indent=4)

    def do_umbrella_list(self, cmd_args):
        """
        List domains that are blocked via the OpenDNS Umbrella service
        """
        response = self.umbrella.list_blocked_domains()
        if response:
            print json.dumps(response, indent=4)

    def do_umbrella_unblock(self, cmd_args):
        """
        Remove a domain from the OpenDNS Umbrella service
        """
        response = self.umbrella.delete_blocked_domain(cmd_args)
        if response:
            print json.dumps(response, indent=4)

    def do_tx_members(self, cmd_args):
        es_docs = self.tx.search_members()

        if not es_docs:
            return

        if not isinstance(es_docs, list):
            es_docs = [es_docs]

        for es_doc in es_docs:
            print json.dumps(es_doc.response.to_dict(), indent=4)

    def do_tx_malware_search(self, cmd_args):

        parser = argparse.ArgumentParser(
            usage="tx_malware_search"
        )
        parser.add_argument(
            "-t",
            "--term",
            action="store",
            required=False,
            default=None,
            help=(
                "Specify a freeform string or hash associated with a " +
                "malware sample. Use --exact_match option to make this " +
                "match exactly"
            )
        )
        parser.add_argument(
            "-l",
            "--limit",
            action="store",
            required=False,
            default=10,
            type=int,
            help=(
                "Set a limit on the number of results returned on each page"
            )
        )
        parser.add_argument(
            "-p",
            "--page_limit",
            action="store",
            required=False,
            default=1,
            type=int,
            help=(
                "Set a limit on the number of pages returned"
            )
        )
        parser.add_argument(
            "-s",
            "--since",
            action=ConvertDateTimeAction,
            metavar="MM-DD-YYYY HH:MM:SS",
            required=False,
            default=(
                time.strftime(
                    "%m-%d-%Y %H:%M:%S",
                    time.localtime(
                        int(time.time()) - 60 * 60
                    )
                )
            ),
            type=validate_datetime,
            help=(
                "Specify a starting datetime to search from. Defaults to " +
                "one hour ago from time command is run"
            )
        )
        parser.add_argument(
            "-u",
            "--until",
            action=ConvertDateTimeAction,
            metavar="MM-DD-YYYY HH:MM:SS",
            required=False,
            default=time.strftime("%m-%d-%Y %H:%M:%S", time.localtime()),
            type=validate_datetime,
            help=(
                "Specify an ending datetime to search until. Defaults to " +
                "time this command is run"
            )
        )
        parser.add_argument(
            "-x",
            "--exact_match",
            action="store_true",
            default=False,
            required=False,
            help=(
                "Specify that the search term must be an exact match"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.tx.search_malware(
            term=parsed_args.term,
            since=parsed_args.since,
            until=parsed_args.until,
            limit=parsed_args.limit,
            page_limit=parsed_args.page_limit,
            exact=parsed_args.exact_match
        )

        if not es_docs:
            return

        if not isinstance(es_docs, list):
            es_docs = [es_docs]

        for es_doc in es_docs:
            print json.dumps(es_doc.response.to_dict(), indent=4)

    def do_tx_indicator_search(self, cmd_args):

        parser = argparse.ArgumentParser(
            usage="tx_indicator_search"
        )
        parser.add_argument(
            "-t",
            "--term",
            action="store",
            required=False,
            default=None,
            help=(
                "Specify a freeform string or hash associated with a " +
                "malware sample. Use --exact_match option to make this " +
                "match exactly"
            )
        )
        parser.add_argument(
            "-i",
            "--indicator_type",
            choices=[
                "adjust_token",
                "api_key",
                "as_number",
                "banner",
                "cmd_line",
                "cookie_name",
                "crx",
                "debug_string",
                "dest_port",
                "directory_queried",
                "domain",
                "email_address",
                "file_created",
                "file_deleted",
                "file_moved",
                "file_name",
                "file_opened",
                "file_read",
                "file_written",
                "get_param",
                "hash_imphash",
                "hash_md5",
                "hash_sha1",
                "hash_sha256",
                "hash_ssdeep",
                "html_id",
                "http_request",
                "ip_address",
                "ip_subnet",
                "isp",
                "latitude",
                "launch_agent",
                "location",
                "longitude",
                "malware_name",
                "memory_alloc",
                "memory_protect",
                "memory_written",
                "mutant_created",
                "mutex",
                "name_server",
                "other_file_op",
                "password",
                "password_salt",
                "payload_data",
                "payload_type",
                "post_data",
                "protocol",
                "referer",
                "registrar",
                "registry_key",
                "reg_key_created",
                "reg_key_deleted",
                "reg_key_enumerated",
                "reg_key_monitored",
                "reg_key_opened",
                "signature",
                "source_port",
                "telephone",
                "uri",
                "user_agent",
                "volume_queried",
                "webstorage_key",
                "web_payload",
                "whois_name",
                "whois_addr1",
                "whois_addr2",
                "xpi"
            ],
            required=False,
            default=None,
            help=(
                "Specify one or more threat indicator types to search for"
            )
        )
        parser.add_argument(
            "-y",
            "--threat_type",
            choices=[
                "bad_actor",
                "compromised_credential",
                "command_exec",
                "malicious_ad",
                "malicious_api_key",
                "malicious_content",
                "malicious_domain",
                "malicious_inject",
                "malicious_ip",
                "malicious_subnet",
                "malicious_ssl_cert",
                "malicious_url",
                "malware_artifacts",
                "malware_sample",
                "proxy_ip",
                "signature",
                "web_request",
                "whitelist_domain",
                "whitelist_ip",
                "whitelist_url"
            ],
            required=False,
            default=None,
            help=(
                "Specify one or more threat types to search for"
            )
        )
        parser.add_argument(
            "-l",
            "--limit",
            action="store",
            required=False,
            default=10,
            type=int,
            help=(
                "Set a limit on the number of results returned on each page"
            )
        )
        parser.add_argument(
            "-p",
            "--page_limit",
            action="store",
            required=False,
            default=1,
            type=int,
            help=(
                "Set a limit on the number of pages returned"
            )
        )
        parser.add_argument(
            "-s",
            "--since",
            action=ConvertDateTimeAction,
            metavar="MM-DD-YYYY HH:MM:SS",
            required=False,
            default=(
                time.strftime(
                    "%m-%d-%Y %H:%M:%S",
                    time.localtime(
                        int(time.time()) - 60 * 60
                    )
                )
            ),
            type=validate_datetime,
            help=(
                "Specify a starting datetime to search from. Defaults to " +
                "one hour ago from time command is run"
            )
        )
        parser.add_argument(
            "-u",
            "--until",
            action=ConvertDateTimeAction,
            metavar="MM-DD-YYYY HH:MM:SS",
            required=False,
            default=time.strftime("%m-%d-%Y %H:%M:%S", time.localtime()),
            type=validate_datetime,
            help=(
                "Specify an ending datetime to search until. Defaults to " +
                "time this command is run"
            )
        )
        parser.add_argument(
            "-x",
            "--exact_match",
            action="store_true",
            default=False,
            required=False,
            help=(
                "Specify that the search term must be an exact match"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.tx.search_indicators(
            term=parsed_args.term,
            indicator_type=parsed_args.indicator_type,
            threat_tyep=parsed_args.threat_type,
            since=parsed_args.since,
            until=parsed_args.until,
            limit=parsed_args.limit,
            page_limit=parsed_args.page_limit,
            exact=parsed_args.exact_match
        )

        if not es_docs:
            print magenta("Nothin'...", readline=True)
            return

        if not isinstance(es_docs, list):
            es_docs = [es_docs]

        for es_doc in es_docs:
            print json.dumps(es_doc.response.to_dict(), indent=4)

    def do_tx_descriptor_search(self, cmd_args):

        parser = argparse.ArgumentParser(
            usage="tx_descriptor_search"
        )
        parser.add_argument(
            "-t",
            "--term",
            action="store",
            required=False,
            default=None,
            help=(
                "Specify a freeform string or hash associated with a " +
                "malware sample. Use --exact_match option to make this " +
                "match exactly"
            )
        )
        parser.add_argument(
            "-i",
            "--indicator_type",
            choices=[
                "adjust_token",
                "api_key",
                "as_number",
                "banner",
                "cmd_line",
                "cookie_name",
                "crx",
                "debug_string",
                "dest_port",
                "directory_queried",
                "domain",
                "email_address",
                "file_created",
                "file_deleted",
                "file_moved",
                "file_name",
                "file_opened",
                "file_read",
                "file_written",
                "get_param",
                "hash_imphash",
                "hash_md5",
                "hash_sha1",
                "hash_sha256",
                "hash_ssdeep",
                "html_id",
                "http_request",
                "ip_address",
                "ip_subnet",
                "isp",
                "latitude",
                "launch_agent",
                "location",
                "longitude",
                "malware_name",
                "memory_alloc",
                "memory_protect",
                "memory_written",
                "mutant_created",
                "mutex",
                "name_server",
                "other_file_op",
                "password",
                "password_salt",
                "payload_data",
                "payload_type",
                "post_data",
                "protocol",
                "referer",
                "registrar",
                "registry_key",
                "reg_key_created",
                "reg_key_deleted",
                "reg_key_enumerated",
                "reg_key_monitored",
                "reg_key_opened",
                "signature",
                "source_port",
                "telephone",
                "uri",
                "user_agent",
                "volume_queried",
                "webstorage_key",
                "web_payload",
                "whois_name",
                "whois_addr1",
                "whois_addr2",
                "xpi"
            ],
            required=False,
            default=None,
            help=(
                "Specify one or more threat indicator types to search for"
            )
        )
        parser.add_argument(
            "-y",
            "--threat_type",
            choices=[
                "bad_actor",
                "compromised_credential",
                "command_exec",
                "malicious_ad",
                "malicious_api_key",
                "malicious_content",
                "malicious_domain",
                "malicious_inject",
                "malicious_ip",
                "malicious_subnet",
                "malicious_ssl_cert",
                "malicious_url",
                "malware_artifacts",
                "malware_sample",
                "proxy_ip",
                "signature",
                "web_request",
                "whitelist_domain",
                "whitelist_ip",
                "whitelist_url"
            ],
            required=False,
            default=None,
            help=(
                "Specify one or more threat types to search for"
            )
        )
        parser.add_argument(
            "-o",
            "--owner",
            required=False,
            type=int,
            default=None,
            help=(
                "The AppID of the owner for the descriptor"
            )
        )
        parser.add_argument(
            "-l",
            "--limit",
            action="store",
            required=False,
            default=10,
            type=int,
            help=(
                "Set a limit on the number of results returned on each page"
            )
        )
        parser.add_argument(
            "-p",
            "--page_limit",
            action="store",
            required=False,
            default=1,
            type=int,
            help=(
                "Set a limit on the number of pages returned"
            )
        )
        parser.add_argument(
            "-s",
            "--since",
            action=ConvertDateTimeAction,
            metavar="MM-DD-YYYY HH:MM:SS",
            required=False,
            default=(
                time.strftime(
                    "%m-%d-%Y %H:%M:%S",
                    time.localtime(
                        int(time.time()) - 60 * 60
                    )
                )
            ),
            type=validate_datetime,
            help=(
                "Specify a starting datetime to search from. Defaults to " +
                "one hour ago from time command is run"
            )
        )
        parser.add_argument(
            "-u",
            "--until",
            action=ConvertDateTimeAction,
            metavar="MM-DD-YYYY HH:MM:SS",
            required=False,
            default=time.strftime("%m-%d-%Y %H:%M:%S", time.localtime()),
            type=validate_datetime,
            help=(
                "Specify an ending datetime to search until. Defaults to " +
                "time this command is run"
            )
        )
        parser.add_argument(
            "-x",
            "--exact_match",
            action="store_true",
            default=False,
            required=False,
            help=(
                "Specify that the search term must be an exact match"
            )
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = self.tx.search_descriptors(
            term=parsed_args.term,
            indicator_type=parsed_args.indicator_type,
            threat_type=parsed_args.threat_type,
            owner=parsed_args.owner,
            since=parsed_args.since,
            until=parsed_args.until,
            limit=parsed_args.limit,
            page_limit=parsed_args.page_limit,
            exact=parsed_args.exact_match
        )

        if not es_docs:
            print magenta("Nothin'...", readline=True)
            return

        if not isinstance(es_docs, list):
            es_docs = [es_docs]

        for es_doc in es_docs:
            print json.dumps(es_doc.response.to_dict(), indent=4)

    def do_tx_get_malware_info(self, cmd_args):

        parser = argparse.ArgumentParser(
            usage="tx_descriptor_search"
        )

        parser.add_argument(
            "indicator_id",
            help=(
                "Specify the ThreatExchange ID for the malware object to " +
                "lookup information for"
            )
        )

        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        es_docs = []
        es_docs.append(
            self.tx.get_malware_object(parsed_args.indicator_id)
        )
        es_docs.append(
            self.tx.get_malware_objects_dropped(parsed_args.indicator_id)
        )
        es_docs.append(
            self.tx.get_malware_objects_dropped_by(parsed_args.indicator_id)
        )
        es_docs.append(
            self.tx.get_malware_object_families(parsed_args.indicator_id)
        )
        es_docs.append(
            self.tx.get_malware_object_indicators(parsed_args.indicator_id)
        )

        for es_doc in es_docs:
            try:
                print json.dumps(es_doc.response.to_dict(), indent=4)
            except:
                print "\n!! %s\n" % es_doc

    def do_tx_get_malware_obj(self, cmd_args):
        print json.dumps(
            self.tx.get_malware_object(cmd_args).response.to_dict(),
            indent=4
        )

    # TODO: Add batch methods
    def do_config_add(self, cmd_args):
        """
        Add a section or option to the config or change the existing
        value of something in the config. DON"T FORGET TO SAVE CHANGES!
        """
        parser = argparse.ArgumentParser(description="config_add")
        parser.add_argument(
            "section",
            help=(
                "The section that will contain the specified option. " +
                "Can be a new section or existing"
            )
        )
        parser.add_argument(
            "option",
            help=(
                "The option name that is being set or updated. " +
                "Can be a new option or existing"
            )
        )
        parser.add_argument(
            "value",
            help="The value to be set"
        )

        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        self.config_manager.set_option(
            parsed_args.section,
            parsed_args.option,
            parsed_args.value
        )

    def do_config_remove(self, cmd_args):
        """
        Add a section or option to the config or change the existing
        value of something in the config. DON"T FORGET TO SAVE CHANGES!
        """
        parser = argparse.ArgumentParser(description="config_remove")
        parser.add_argument(
            "section",
            help=(
                "The section that will contain the specified option. " +
                "Must be an existing section"
            )
        )
        parser.add_argument(
            "option",
            help=(
                "The option name that is removed. Must be an existing " +
                "option"
            )
        )

        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        self.config_manager.remove_option(
            parsed_args.section,
            parsed_args.option
        )

    def do_config_dump(self, cmd_args):
        """
        Dump the config into a plaintext file in the threatshell
        directory. If the plaintext file is detected on the next
        run of threatshell, it will be loaded and the existing
        encrypted config file will be overwritten with the newly
        encrypted file
        """
        parser = argparse.ArgumentParser(description="config_dump")
        parser.add_argument(
            "-s",
            "--screen",
            required=False,
            action="store_true",
            default=False,
            help="Dump the config to screen for viewing only"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        data = self.config_manager.dump_config(to_screen=parsed_args.screen)
        if data is not None:
            print data

    def do_config_save(self, cmd_args):
        """
        Save all config changes. Even changes via a dumped config.
        Note that saving a modified dump file will require a restart
        of threatshell to take effect
        """
        self.config_manager.save()

    def do_list_tags(self, cmd_args):
        """
        List all of the current tags for this session
        """
        print ", ".join(sorted(list(tags)))

    def do_add_tags(self, cmd_args):
        """
        Add new tags to the current session. See -h or --help for
        additional information
        """
        parser = argparse.ArgumentParser(description="add_tags")
        parser.add_argument(
            "tags",
            action="store",
            default=[],
            nargs="+",
            help="One or more space delimited tags to be added"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        global tags
        tags = tags.symmetric_difference(set(parsed_args.tags))
        self.prompt = build_shell_line()

    def do_remove_tags(self, cmd_args):
        """
        Remove one or more tags from the current session. See -h or
        --help for additional information
        """
        parser = argparse.ArgumentParser(description="remove_tags")
        parser.add_argument(
            "tags",
            action="store",
            default=[],
            nargs="*",
            help="One or more space delimited tags to be added"
        )
        parser.add_argument(
            "-a",
            "--all",
            action="store_true",
            default=False,
            required=False,
            help="Remove all tags"
        )
        split_args = shlex.split(cmd_args)

        try:
            parsed_args = parser.parse_args(args=split_args)
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        global tags

        if parsed_args.all:
            tags = set([])
        else:
            remove_tags = set(parsed_args.tags)
            tags = tags.symmetric_difference(tags.intersection(remove_tags))

        self.prompt = build_shell_line()

    def do_logo(self, cmd_args):
        """errrmehgerrd ascii artz :D"""
        logo()

    def _exit_func(self):
        readline.write_history_file(self.history_file)
        print "Bye"
        sys.exit(0)

    def do_exit(self, cmd_args):
        """Quitter"""
        self._exit_func()

    def do_quit(self, cmd_args):
        """Quitter"""
        self._exit_func()

    def do_EOF(self, cmd_args):
        """
        Exit threatshell via ^D
        """
        print ""
        self._exit_func()

    def do_shell(self, cmd_args):
        """
        Execute a bash command
        """
        split_args = shlex.split(cmd_args)
        try:
            p = subprocess.Popen(
                split_args,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE
            )
            p.wait()
            comms = p.communicate()
            print comms[0]
            if comms[1]:
                log.error(comms[1])
        except Exception, e:
            log.error(
                (
                    "[%s]: %s - Don't forget that aliased commands aren't " +
                    "available"
                ) % (
                    e.__class__.__name__,
                    str(e)
                )
            )


def main(args):

    if(
        (
            not args.enable_console_log and
            args.disable_file_log
        ) or
        args.disable_logging
    ):
        logging.disable(logging.FATAL)

    elif args.disable_file_log and args.enable_console_log:
        init_console_logger(
            log_level=eval("logging.%s" % args.console_level.upper())
        )

    elif not args.enable_console_log:
        init_file_logger(
            log_level=eval("logging.%s" % args.log_level.upper())
        )

    else:
        init_logging(
            con_level=eval("logging.%s" % args.console_level.upper()),
            f_level=eval("logging.%s" % args.log_level.upper())
        )

    if args.enable_web_log:
        import httplib
        httplib.HTTPConnection.debuglevel = 1
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    logging.getLogger().setLevel(logging.DEBUG)
    logo()

    start_message = "Fighting evil"

    while True:

        shell_line = build_shell_line()
        try:
            prompt = MyPrompt(args)
            prompt.prompt = shell_line
            prompt.cmdloop(start_message)
        except Exception, e:
            print red(
                "[%s]: %s" % (e.__class__.__name__, e.message),
                readline=True
            )
            traceback.print_exc()
            start_message = red(
                (
                    "Whoopsies, looks like there was an error - " +
                    "please report it in github for a fix"
                ),
                readline=True
            )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Threat shell...for huntin' all the things! :D"
    )

    parser.add_argument(
        "--geo_ip_db",
        action="store",
        required=False,
        default="%s/GeoIP.dat" % TS_DIR,
        help="Specify an alternate Geo IP database file"
    )

    parser.add_argument(
        "--geo_asn_db",
        action="store",
        required=False,
        default="%s/GeoIPASNum.dat" % TS_DIR,
        help="Specify an alternate Geo IP ASN database file"
    )

    parser.add_argument(
        "--log_level",
        action="store",
        required=False,
        choices=["debug", "info", "warn", "error", "critical", "fatal"],
        default="debug",
        help="Specify logging level"
    )

    parser.add_argument(
        "--console_level",
        action="store",
        required=False,
        choices=["debug", "info", "warn", "error", "critical", "fatal"],
        default="info",
        help="Specify console logging level"
    )

    parser.add_argument(
        "--enable_console_log",
        action="store_true",
        default=False,
        required=False,
        help=(
            "Turn on console log messages " +
            "(set logging level with --console_level)"
        )
    )

    parser.add_argument(
        "--enable_web_log",
        action="store_true",
        default=False,
        required=False,
        help="Enable requests' logging to see requests being made"
    )

    parser.add_argument(
        "--disable_file_log",
        action="store_true",
        default=False,
        required=False,
        help="Turn off logging to file"
    )

    parser.add_argument(
        "--disable_logging",
        action="store_true",
        default=False,
        required=False,
        help=(
            "Disable all logging (analogous to --disable_file_log " +
            "without enabling console logging)"
        )
    )

    parser.add_argument(
        "--session_tags",
        action="store",
        default=[],
        nargs="+",
        required=False,
        help=(
            "Add keyword tags to the current threatshell session for " +
            "extra searching power in ES"
        )
    )

    args = parser.parse_args()
    tags = set(args.session_tags)
    try:
        ThreatshellIndex.create()
    except:
        pass
    main(args)

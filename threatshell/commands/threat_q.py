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

import argparse
import logging
import json
import requests
import shlex

# To disable this annoying message
#  InsecureRequestWarning: Unverified HTTPS request is being made.
#  Adding certificate verification is strongly advised.
#
# Will want to maybe make this an option later
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

log = logging.getLogger(__name__)


# TODO - add status code checking and error handling on bad status codes
class ThreatQ:

    def __init__(self, config):
        self.url = config.get("ThreatQ", "url")
        if self.url[-1] == "/":
            self.url = self.url[0:-1]
        self.key = config.get("ThreatQ", "key")

    def _get_status_map(self):
        statuses = self.indicator_statuses(None)
        status_map = {}
        for item in statuses:
            status_name = item["indicator_status"]
            status_id = item["indicator_status_id"]
            status_map[status_name] = status_id

        return status_map

    def _get_type_map(self):
        types = self.indicator_types(None)
        type_map = {}
        for item in types:
            indicator_type = item["indicator_type"]
            type_id = item["indicator_type_id"]
            type_map[indicator_type] = type_id

        return type_map

    def query(self, args):

        parser = argparse.ArgumentParser(usage="tq_search")
        parser.add_argument(
            "indicator",
            action="store",
            help="Specify the indicator to query for"
        )

        try:
            parsed_args = parser.parse_args(args=shlex.split(args))
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return {}

        query_url = "%s/api/search/" % self.url
        params = {"api_key": self.key}
        data = {"indicator": parsed_args.indicator}

        r = requests.post(query_url, params=params, data=data, verify=False)

        jdata = r.json()
        if not jdata:
            jdata = {parsed_args.indicator: "Nothin'..."}
        return jdata

    def indicator_statuses(self, args):

        query_url = "%s/api/indicator-statuses" % self.url
        params = {"api_key": self.key}
        r = requests.get(query_url, params=params, verify=False)

        jdata = r.json()
        if not jdata:
            jdata = {}
        return jdata

    def indicator_types(self, args):

        query_url = "%s/api/indicator-types" % self.url
        params = {"api_key": self.key}
        r = requests.get(query_url, params=params, verify=False)

        jdata = r.json()
        if not jdata:
            jdata = {}
        return jdata

    def add_indicator(self, args):

        type_map = self._get_type_map()
        status_map = self._get_status_map()

        parser = argparse.ArgumentParser(usage="tq_add")
        parser.add_argument(
            "indicator",
            action="store",
            help="Specify the indicator to be added"
        )

        parser.add_argument(
            "-c",
            "--class_type",
            action="store",
            choices=["network", "host"],
            metavar="TYPE",
            required=True,
            help=(
                "Specify indicator class. Valid choices are: %s"
            ) % ", ".join(["network", "host"])
        )

        parser.add_argument(
            "-t",
            "--type",
            action="store",
            choices=type_map.keys(),
            metavar="TYPE",
            required=True,
            help=(
                "Specify the indicator type. Valid choices are: %s"
            ) % (", ".join(type_map.keys()))
        )

        parser.add_argument(
            "-s",
            "--status",
            action="store",
            choices=status_map.keys(),
            metavar="STATUS",
            required=True,
            help=(
                "Specify the indicator status. Valid choices are: %s"
            ) % ", ".join(status_map.keys())
        )

        try:
            parsed_args = parser.parse_args(args=shlex.split(args))
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return {}

        query_url = "%s/api/indicators/" % self.url
        params = {
            "api_key": self.key,
            "indicator": parsed_args.indicator,
            "indicator_class": parsed_args.class_type,
            "indicator_type_id": str(type_map[parsed_args.type]),
            "indicator_status_id": str(status_map[parsed_args.status])
        }

        r = requests.post(
            query_url,
            params=params,
            verify=False
        )

        if r.status_code != 200:
            log.error("[tqadd] Got back status code %s" % r.status_code)
            return {
                parsed_args.indicator: "Failed with error code %s" % (
                    r.status_code
                )
            }

        rc = r.content
        if not rc:
            return "No reply"
        return rc

    def update_indicator_status(self, args):

        status_map = self._get_status_map()

        parser = argparse.ArgumentParser(usage="tqcs")
        parser.add_argument(
            "indicator_id",
            action="store",
            help="Specify the indicator ID to change the status of"
        )

        parser.add_argument(
            "--class_type",
            action="store",
            choices=["network", "host"],
            required=True,
            help="indicator class"
        )

        parser.add_argument(
            "--status",
            action="store",
            choices=status_map.keys(),
            required=True,
            help="indicator status to set indicator to"
        )
        try:
            parsed_args = parser.parse_args(args=shlex.split(args))
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return {}

        query_url = "%s/api/indicators/%s" % (
            self.url,
            parsed_args.indicator_id
        )
        params = {
            "api_key": self.key,
            "indicator_class": parsed_args.class_type,
            "indicator_status_id": str(status_map[parsed_args.status])
        }
        data = {
            "indicator_id": parsed_args.indicator_id
        }

        r = requests.put(query_url, data=data, params=params, verify=False)
        if r.status_code != 200:
            log.error(
                "[tqcs] Failed to update status - error code %s" % (
                    r.status_code
                )
            )
            return {
                parsed_args.indicator_id: "Failed with error code %s" % (
                    r.status_code
                )
            }

        rc = r.content
        if not rc:
            return "No reply"
        return rc

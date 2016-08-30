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

from threatshell.doctypes.generic import GenericDoc

from Crypto.Hash import HMAC, SHA
from elasticsearch_dsl import String
from requests.auth import HTTPBasicAuth

import argparse
import base64
import logging
import re
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


class RiskIQDoc(GenericDoc):

    response = String()


class RiskIQ:

    def __init__(self, config):
        self.key = config.get("RiskIQ", "key")
        self.token = config.get("RiskIQ", "token")
        self.url = "https://ws.riskiq.net"
        self.json_header = "application/json"
        self.xml_header = "text/xml"
        self.dns_name = "v1/dns/name"
        self.dns_data = "v1/dns/data"

    def _build_doc(self, term, response, successful):
        return RiskIQDoc(
            response=response,
            successful=successful,
            term=term
        )

    def _get_indicator(self, params):

        indicator = None

        if params.get("ip") is not None:
            indicator = params["ip"]
        elif params.get("name") is not None:
            indicator = params["name"]
        else:
            indicator = params["raw"]

        return indicator

    def _error(self, arg, endpoint, resp):

        message = "Failed on endpoint %s with status code %s - %s" % (
            endpoint,
            resp.status_code,
            resp.content
        )

        log.error(message)
        record = {"error": message}

        return self._build_doc(arg, record, False)

    def _query(self, endpoint, params):

        # TODO: Figure this bullshit out
        import httplib
        httplib.HTTPConnection.debuglevel = 1
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

        query_url = "%s/%s" % (self.url, endpoint)

        hmac = HMAC.new(self.key, digestmod=SHA)

        param_string = "=".join(params.items()[0])
        sig_data = "GET\n/%s\n%s\n\n" % (endpoint, param_string)

        log.debug(sig_data)

        hmac.update(sig_data)
        signature = hmac.digest()
        encoded = base64.b64encode(signature)

        r = requests.get(
            query_url,
            params=params,
            verify=False,
            headers={
                "Accept": self.json_header,
                "Authorization": "RiskIQ %s:%s" % (self.token, encoded)
            }
        )
        if r.status_code != requests.codes.ok:
            return self._error(
                self._get_indicator(params),
                endpoint,
                r
            )

        return r.json()

    def _ba_query(self, endpoint, params):

        query_url = "%s/%s" % (self.url, endpoint)
        indicator = self._get_indicator(params)

        r = requests.get(
            query_url,
            params=params,
            verify=False,
            auth=HTTPBasicAuth(self.token, self.key),
            headers={"Accept": self.json_header}
        )

        if r.status_code == 204:
            record = {indicator: "No results found"}
            return self._build_doc(indicator, record, False)

        if r.status_code != requests.codes.ok:
            record = {indicator: "%s: %s" % (r.status_code, r.content)}
            return self._build_doc(
                indicator,
                record,
                False
            )

        record = {indicator: r.json()}
        return self._build_doc(indicator, record, True)

    def passive_dns(self, args):

        parser = argparse.ArgumentParser(
            usage="riq_pdns",
            epilog=(
                "See docs at " +
                "https://sf.riskiq.net/crawlview/api/docs/controllers/" +
                "DnsController.html for more details"
            )
        )

        parser.add_argument(
            "indicator",
            action="store",
            help="Specify the indicator to query for"
        )

        parser.add_argument(
            "--data",
            action="store_true",
            default=False,
            required=False,
            help=(
                "query for matches in the resource record data rather " +
                "than by resource record names"
            )
        )

        parser.add_argument(
            "--raw",
            action="store_true",
            default=False,
            required=False,
            help=(
                "Indicate that the given indicator should be used as a raw " +
                "string in the search criteria"
            )
        )

        parser.add_argument(
            "--rr_type",
            action="store",
            choices=["A", "NS", "MX", "TXT", "PTR"],
            default=None,
            required=False,
            help=(
                "Filter results by a resource record type"
            )
        )

        parser.add_argument(
            "--limit",
            action="store",
            default=None,
            required=False,
            help=(
                "Specify a maximum number of results to be returned " +
                "(A default of 100 is imposed by RiskIQ)"
            )
        )

        try:
            parsed_args = parser.parse_args(args=shlex.split(args))
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid argument for query (use -h or --help " +
                    "to see command options)"
                )
            return

        endpoint = self.dns_name
        if parsed_args.data:
            endpoint = self.dns_data

        params = {}
        if parsed_args.rr_type is not None:
            params["rrType"] = parsed_args.rr_type

        if parsed_args.raw:
            params["raw"] = parsed_args.indicator.encode("hex")
        else:
            if re.match(
                "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
                parsed_args.indicator
            ):
                params["ip"] = parsed_args.indicator
            else:
                params["name"] = parsed_args.indicator

        if parsed_args.limit is not None:
            params["maxResults"] = parsed_args.limit

        return self._ba_query(endpoint, params)

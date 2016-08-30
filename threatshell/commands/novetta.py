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

from elasticsearch_dsl import String

import argparse
import logging
import requests
import shlex

log = logging.getLogger(__name__)


class NovettaDoc(GenericDoc):

    response = String()


class Novetta:

    def __init__(self, config):
        self.key = config.get("Novetta", "key")
        self.url = "https://whodat.novetta-arg.com"
        self.raw = "v0/raw"
        self.parsed = "v0/parsed"

    def _error(self, arg, endpoint, resp):
        log.error(
            "Failed to query whodat endpoint %s - %s: %s" % (
                endpoint,
                resp.status_code,
                resp.content
            )
        )
        record = {
            arg: "Failed on endpoint %s with status code %s - %s" % (
                endpoint,
                resp.status_code,
                resp.content
            )
        }
        return self._build_doc(arg, record, False)

    def _query(self, endpoint, indicator):

        query = "%s/%s/%s" % (self.url, endpoint, indicator)
        auth_header = {
            "Authorization": "Bearer %s" % self.key
        }

        response = requests.get(
            query,
            verify=False,
            headers=auth_header
        )

        if response.status_code == 202:
            message = "Queued for processing. Check back later"
            record = {indicator: message}
            return self._build_doc(indicator, record, False)

        if response.status_code == 204:
            record = {
                indicator: (
                    "The service was unable to parse the results. Try using " +
                    "the --raw option"
                )
            }
            return self._build_doc(indicator, record, False)

        if response.status_code != requests.codes.ok:
            return self._error(indicator, endpoint, response)

        record = {}
        if endpoint == self.raw:
            record = {indicator: response.content}
        else:
            record = {indicator: response.json()}

        return self._build_doc(indicator, record, True)

    def _build_doc(self, term, response, successful):
        return NovettaDoc(
            response=response,
            term=term,
            successful=successful
        )

    def whodat(self, args):

        parser = argparse.ArgumentParser(
            usage="nvwhois"
        )

        parser.add_argument(
            "indicator",
            action="store",
            help="Specify the indicator to query for"
        )

        parser.add_argument(
            "--raw",
            action="store_true",
            default=False,
            required=False,
            help=(
                "Query for the unparsed whois data"
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

        endpoint = self.parsed
        if parsed_args.raw:
            endpoint = self.raw

        return self._query(endpoint, parsed_args.indicator)

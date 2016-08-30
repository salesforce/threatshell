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

import datetime
import json
import requests


class Umbrella:

    def __init__(self, config):

        url = "https://s-platform.api.opendns.com/1.0"
        self.api_token = config.get("Umbrella", "api_token")
        self.block_endpoint = "%s/events" % url
        self.query_endpoint = "%s/domains" % url

    def list_blocked_domains(self):

        params = {
            "customerKey": self.api_token
        }

        res = requests.get(
            self.query_endpoint,
            params=params,
            headers={"Content-Type": "application/json"}
        )

        if res.status_code != requests.codes.ok:
            return {
                "error": "[%s]: %s" % (res.status_code, res.content)
            }

        return res.json()

    def add_blocked_domain(self, url):

        if "/" in domain:
            domain = url.split("/")[2]

        params = {
            "customerKey": self.api_token
        }

        time_stamp = datetime.datetime.strftime(
            datetime.datetime.now(),
            '%Y-%m-%dT%H:%M:%S.0Z'
        )

        body = {
            "alertTime": time_stamp,
            "deviceId": "cbc387aa-fffb-490e-a75a-0056f49eca11",
            "deviceVersion": "1.0",
            "dstDomain": domain,
            "dstUrl": url,
            "eventTime": time_stamp,
            "protocolVersion": "1.0a",
            "providerName": "Security Platform"
        }

        res = requests.post(
            self.block_endpoint,
            params=params,
            data=json.dumps(body),
            headers={"Content-Type": "application/json"}
        )

        if res.status_code != requests.codes.ok:
            return {
                "error": "[%s]: %s" % (res.status_code, res.content)
            }

    def delete_blocked_domain(self, domain):

        params = {
            "customerKey": self.api_token,
            "where[name]": domain
        }

        res = requests.delete(
            self.query_endpoint,
            params=params,
            headers={"Content-Type": "application/json"}
        )

        if res.status_code != requests.codes.ok:
            return {
                "error": "[%s]: %s" % (res.status_code, res.content)
            }

        return res.json()

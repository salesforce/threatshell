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

import logging
import requests

log = logging.getLogger(__name__)


class InfobloxDoc(GenericDoc):

    response = String()


class Infoblox:

    def __init__(self, config):
        self.url = config.get("Infoblox", "url")
        self.api_endpoint = "%s/wapi/v1.7.1" % self.url
        self.search_api = "%s/search" % self.api_endpoint

        self.user = config.get("Infoblox", "username")
        self.passwd = config.get("Infoblox", "password")

    def _build_error(self, term, message):
        record = {term: {"error": message}}
        return self._build_doc(
            term,
            record,
            False
        )

    def _build_doc(self, term, response, successful):
        return InfobloxDoc(
            response=response,
            successful=successful,
            term=term
        )

    def search(self, search_target):

        lease_params = {
            '_return_type': 'json-pretty',
            'objtype': 'lease',
            'search_string~': search_target
        }

        full_detail_params = {
            '_return_type': 'json-pretty',
            '_return_fields+': ",".join([
                'discovered_data',
                'is_invalid_mac',
                'hardware',
                'client_hostname',
                'ends',
                'never_ends',
                'never_starts',
                'next_binding_state',
                'on_commit',
                'on_expiry',
                'on_release',
                'option',
                'protocol',
                'remote_id',
                'served_by',
                'server_host_name'
            ])
        }

        r = requests.get(
            self.search_api,
            params=lease_params,
            auth=(self.user, self.passwd),
            verify=False
        )

        if r.status_code != requests.codes.ok:
            message = "No leases found (Bad error code - [%s]: %s)" % (
                r.status_code,
                r.content
            )
            log.error(message)
            return self._build_error(search_target, message)

        refs = r.json()

        if len(refs) == 0:
            message = "No leases found"
            return self._build_error(search_target, message)

        if refs[0].get('_ref') is None:
            message = "No leases found"
            return self._build_error(search_target, message)

        details = []
        for seq, ref_type in enumerate(refs):

            lease = refs[seq]['_ref']
            query_lease = "%s/%s" % (self.api_endpoint, lease)
            r = requests.get(
                query_lease,
                params=full_detail_params,
                auth=(self.user, self.passwd),
                verify=False
            )

            # TODO: maybe some es error feed back here
            if r.status_code != requests.codes.ok:
                log.info(
                    "lease %s for %s not found - %s: %s" % (
                        lease,
                        search_target,
                        r.status_code,
                        r.content
                    )
                )
                continue

            lease_detail = r.json()
            # ref = lease_detail["_ref"]
            # del lease_detail["_ref"]
            # lease_detail["ref"] = ref
            details.append({search_target: lease_detail})

        docs = []
        for entry in details:
            docs.append(
                self._build_doc(
                    search_target,
                    entry,
                    True
                )
            )
        return docs

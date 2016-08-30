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

import json
import logging
import requests

log = logging.getLogger(__name__)


class ThreatExchangeDoc(GenericDoc):

    response = String()


class MalwareObject:

    class TEFields(list):

        def __init__(self):
            list.__init__(self)
            self.fields = [
                "id",
                "added_on",
                "crx",
                "imphash",
                "md5",
                "sha1",
                "sha256",
                "pe_rich_header",
                "sample",
                "password",
                "sample_type",
                "share_level",
                "ssdeep",
                "status",
                "submitter_count",
                "victim_count",
                "xpi"
            ]
            self.field_mapping = dict(
                [(val, i) for i, val in enumerate(self.fields)]
            )

        def __getitem__(self, index):
            if isinstance(index, int):
                return self.fields[index]
            else:
                index = self.field_mapping.get(index)
                if index is None:
                    return None
                else:
                    return self.fields[index]

        def __iter__(self):
            for f in self.fields:
                yield f

        def all(self):
            return self.fields

    def __init__(self, jdata):

        self.malware_id = jdata.get("id")
        self.added_on = jdata.get("added_on")
        self.chrome_ext_id = jdata.get("crx")
        self.imphash = jdata.get("imphash")
        self.md5 = jdata.get("md5")
        self.sha1 = jdata.get("sha1")
        self.sha256 = jdata.get("sha256")
        self.rich_hash = jdata.get("pe_rich_header")
        self.sample = jdata.get("sample")
        self.sample_passwd = jdata.get("password")
        self.sample_type = jdata.get("sample_type")
        self.tlp = jdata.get("share_level")
        self.ssdeep = jdata.get("ssdeep")
        self.malicious_status = jdata.get("status")
        self.submission_count = jdata.get("submitter_count")
        self.victim_count = jdata.get("victim_count")
        self.ff_ext_id = jdata.get("xpi")

    def __str__(self):
        return json.dumps(vars(self), indent=4)

    def get_id(self):
        return self.malware_id

    def get_added_date(self):
        return self.added_on

    def get_chrome_extension_id(self):
        return self.chrome_ext_id

    def get_firefox_extension_id(self):
        return self.ff_ext_id

    def get_imphash(self):
        return self.imphash

    def get_md5(self):
        return self.md5

    def get_sha1(self):
        return self.sha1

    def get_sha256(self):
        return self.sha256

    def get_ssdeep(self):
        return self.ssdeep

    def get_rich_hash(self):
        return self.rich_hash

    def get_tlp(self):
        return self.tlp

    def get_sample(self):
        return self.sample

    def get_password(self):
        return self.sample_password

    def get_sample_type(self):
        return self.sample_type

    def get_malicious_status(self):
        return self.malicious_status

    def get_submission_count(self):
        return self.submission_count

    def get_victim_count(self):
        return self.victim_count


class MalwareFamilyObject:

    class TEFields(list):

        def __init__(self):
            list.__init__(self)
            self.fields = [
                "id",
                "added_on",
                "aliases",
                "description",
                "family_type",
                "malicious",
                "name",
                "sample_count",
                "submitter_count"
            ]
            self.field_mapping = dict(
                [(val, i) for i, val in enumerate(self.fields)]
            )

        def __getitem__(self, index):
            if isinstance(index, int):
                return self.fields[index]
            else:
                index = self.field_mapping.get(index)
                if index is None:
                    return None
                else:
                    return self.fields[index]

        def __iter__(self):
            for f in self.fields:
                yield f

        def all(self):
            return self.fields

    def __init__(self, jdata):

        self.family_id = jdata.get("id")
        self.added_on = jdata.get("added_on")
        self.alias_list = jdata.get("aliases")
        self.description = jdata.get("description")
        self.family_type = jdata.get("family_type")
        self.malicious_status = jdata.get("malicious")
        self.family_name = jdata.get("name")
        self.sample_count = jdata.get("sample_count")
        self.submission_count = jdata.get("submitter_count")

    def __str__(self):
        return json.dumps(vars(self), indent=4)

    def get_id(self):
        return self.family_id

    def get_added_date(self):
        return self.added_on

    def get_aliases(self):
        return self.alias_list

    def get_description(self):
        return self.description

    def get_family_type(self):
        return self.family_type

    def get_malicious_status(self):
        return self.malicious_status

    def get_family_name(self):
        return self.family_name

    def get_family_sample_count(self):
        return self.sample_count

    def get_submission_count(self):
        return self.submission_count


class ThreatIndicatorObject:

    class TEFields(list):

        def __init__(self):
            list.__init__(self)
            self.fields = [
                "id",
                "added_on",
                "confidence",
                "description",
                "expired_on",
                "passwords",
                "report_urls",
                "severity",
                "share_level",
                "status",
                "submitter_count",
                "threat_types",
                "type"
            ]
            self.field_mapping = dict(
                [(val, i) for i, val in enumerate(self.fields)]
            )

        def __getitem__(self, index):
            if isinstance(index, int):
                return self.fields[index]
            else:
                index = self.field_mapping.get(index)
                if index is None:
                    return None
                else:
                    return self.fields[index]

        def __iter__(self):
            for f in self.fields:
                yield f

        def all(self):
            return self.fields

    def __init__(self, jdata):

        self.indicator_id = jdata.get("id")
        self.added_on = jdata.get("added_on")
        self.confidence = jdata.get("confidence")
        self.description = jdata.get("description")
        self.expired_on = jdata.get("expired_on")
        self.passwords = jdata.get("passwords")
        self.report_urls = jdata.get("report_urls")
        self.severity = jdata.get("severity")
        self.tlp = jdata.get("share_level")
        self.malicious_status = jdata.get("status")
        self.submission_count = jdata.get("submitter_count")
        self.threat_types = jdata.get("threat_types")
        self.indicator_type = jdata.get("type")

    def __str__(self):
        return json.dumps(vars(self), indent=4)

    def get_id(self):
        return self.indicator_id

    def get_added_date(self):
        return self.added_on

    def get_confidence_level(self):
        return self.confidence

    def get_description(self):
        return self.description

    def get_expiration_date(self):
        return self.expired_on

    def get_password_hashes(self):
        return self.passwords

    def get_report_urls(self):
        return self.report_urls

    def get_severity(self):
        return self.severity

    def get_tlp(self):
        return self.tlp

    def get_malicious_status(self):
        return self.malicious_status

    def get_submission_count(self):
        return self.submission_count

    def get_threat_types(self):
        return self.threat_types

    def get_indicator_type(self):
        return self.indicator_type


class ThreatDescriptorObject:

    class TEFields(list):

        def __init__(self):
            list.__init__(self)
            self.fields = [
                "id",
                "added_on",
                "confidence",
                "description",
                "expired_on",
                "severity",
                "share_level",
                "status",
                "submitter_count",
                "threat_types",
                "type",
                "review_status",
                "last_updated",
                "owner",
                "indicator",
                "precision",
                "raw_indicator"
            ]
            self.field_mapping = dict(
                [(val, i) for i, val in enumerate(self.fields)]
            )

        def __getitem__(self, index):
            if isinstance(index, int):
                return self.fields[index]
            else:
                index = self.field_mapping.get(index)
                if index is None:
                    return None
                else:
                    return self.fields[index]

        def __iter__(self):
            for f in self.fields:
                yield f

        def all(self):
            return self.fields

    def __init__(self, jdata):

        self.descriptor_id = jdata.get("id")
        self.confidence = jdata.get("confidence")
        self.description = jdata.get("description")
        self.expired_on = jdata.get("expired_on")
        self.indicator = jdata.get("indicator")

        if self.indicator is not None:
            self.indicator = ThreatIndicatorObject(self.indicator)

        self.last_updated = jdata.get("last_updated")
        self.owner = jdata.get("owner")

        if self.owner is not None:
            self.owner = MemberObject(self.owner)

        self.precision = jdata.get("precision")
        self.raw_indicator = jdata.get("raw_indicator")
        self.review_status = jdata.get("review_status")
        self.severity = jdata.get("severity")
        self.tlp = jdata.get("share_level")
        self.malicious_status = jdata.get("status")
        self.submission_count = jdata.get("submitter_count")
        self.threat_types = jdata.get("threat_types")
        self.indicator_type = jdata.get("type")

    def __str__(self):
        return json.dumps(vars(self), indent=4)

    def get_id(self):
        self.descriptor_id

    def get_confidence_level(self):
        return self.confidence

    def get_description(self):
        return self.description

    def get_expiration_date(self):
        return self.expired_on

    def get_indicator(self):
        return self.indicator

    def get_last_updated_date(self):
        return self.last_updated

    def get_owner(self):
        return self.owner

    def get_precision(self):
        return self.precision

    def get_raw_indicator(self):
        return self.raw_indicator

    def get_review_status(self):
        return self.review_status

    def get_severity(self):
        return self.severity

    def get_tlp(self):
        return self.tlp

    def get_malicious_status(self):
        return self.malicious_status

    def get_submission_count(self):
        return self.submission_count

    def get_threat_types(self):
        return self.threat_types

    def get_indicator_type(self):
        return self.indicator_type


class MemberObject:

    def __init__(self, jdata):

        self.member_id = jdata.get("id")
        self.member_name = jdata.get("name")
        self.member_email = jdata.get("email")

    def __str__(self):
        return json.dumps(vars(self), indent=4)

    def get_id(self):
        return self.member_id

    def get_name(self):
        return self.member_name

    def get_email(self):
        return self.member_email


class ThreatExchange:

    def __init__(self, config):
        self.graph_url = "https://graph.facebook.com/v2.4"
        self.malware_endpoint = "%s/malware_analyses" % self.graph_url
        self.members_endpoint = "%s/threat_exchange_members" % self.graph_url
        self.indicators_endpoint = "%s/threat_indicators" % self.graph_url
        self.descriptors_endpoint = "%s/threat_descriptors" % self.graph_url

        self.app_id = config.get("ThreatExchange", "app_id")
        self.app_secret = config.get("ThreatExchange", "app_secret")
        self.token = "%s|%s" % (self.app_id, self.app_secret)

    def _build_doc(self, term, record, successful):

        return ThreatExchangeDoc(
            term=term,
            response=record,
            successful=successful
        )

    def _make_request(self, endpoint, params={}):

        params["access_token"] = self.token
        response = requests.get(endpoint, params=params)

        if response.status_code != requests.codes.ok:
            message = {
                "error": "[%s]: %s" % (
                    response.status_code,
                    response.json()
                )
            }
            return message

        return response.json()

    def _get_next_page(self, response):

        paging = response.get("paging")
        if paging is None:
            return None

        return paging.get("next")

    def _get_pages(self, next_page, limit=0):

        pages = []

        if limit == 0:
            limit = None

        while next_page is not None:

            log.debug("Fetching page %s" % next_page)
            response = self._make_request(next_page)

            if response.get("error") is not None:
                return response

            pages.extend(response.get("data"))

            if limit is not None:

                limit -= 1

                if limit == 0:
                    break

            next_page = self._get_next_page(response)

        return pages

    def search_malware(
        self,
        term=None,
        since=None,
        until=None,
        limit=10,
        exact=False,
        page_limit=1
    ):

        params = {
            "text": term,
            "since": since,
            "until": until,
            "limit": limit,
            "strict_text": exact
        }
        response = self._make_request(self.malware_endpoint, params)

        if response.get("error") is not None:
            return self._build_doc("malware_search", response, False)

        docs = response.get("data")

        if page_limit != 1:
            next_page = self._get_next_page(response)
            pages = self._get_pages(next_page, limit=page_limit)
            if not isinstance(pages, list):
                return self._build_doc("malware_search", pages, False)
            else:
                docs.extend(pages)

        for i, doc in enumerate(docs):
            docs[i] = self._build_doc("malware_search", doc, True)

        return docs

    def search_indicators(
        self,
        term=None,
        since=None,
        until=None,
        indicator_type=None,
        threat_type=None,
        exact=False,
        limit=10,
        page_limit=1
    ):

        if indicator_type is not None:
            indicator_type = indicator_type.upper()
        if threat_type is not None:
            threat_type = threat_type.upper()

        params = {
            "text": term,
            "since": since,
            "until": until,
            "limit": limit,
            "strict_text": exact,
            "type": indicator_type,
            "threat_type": threat_type
        }
        response = self._make_request(self.indicators_endpoint, params)

        docs = response.get("data")

        if page_limit != 1:
            next_page = self._get_next_page(response)
            pages = self._get_pages(next_page, limit=page_limit)
            if not isinstance(pages, list):
                return self._build_doc("indicator_search", pages, False)
            else:
                docs.extend(pages)

        for i, doc in enumerate(docs):
            docs[i] = self._build_doc("indicator_search", doc, True)

        return docs

    def search_descriptors(
        self,
        term=None,
        since=None,
        until=None,
        indicator_type=None,
        threat_type=None,
        exact=False,
        limit=10,
        page_limit=1,
        owner=None
    ):

        if indicator_type is not None:
            indicator_type = indicator_type.upper()
        if threat_type is not None:
            threat_type = threat_type.upper()

        params = {
            "text": term,
            "since": since,
            "until": until,
            "limit": limit,
            "strict_text": exact,
            "type": indicator_type,
            "threat_type": threat_type,
            "owner": owner
        }
        response = self._make_request(self.descriptors_endpoint, params)

        docs = response.get("data")

        if page_limit != 1:
            next_page = self._get_next_page(response)
            pages = self._get_pages(next_page, limit=page_limit)
            if not isinstance(pages, list):
                return self._build_doc("descriptor_search", pages, False)
            else:
                docs.extend(pages)

        for i, doc in enumerate(docs):
            docs[i] = self._build_doc("descriptor_search", doc, True)

        return docs

    def search_members(self):

        response = self._make_request(self.members_endpoint)

        if response.get("error") is not None:
            return self._build_doc("member_search", response, False)

        docs = response.get("data")
        for i, doc in enumerate(docs):
            docs[i] = self._build_doc("members_search", doc, True)

        return docs

    def _make_malware_request(self, query_url, params=None):

        if params is None:
            te_fields = MalwareObject.TEFields().all()
            params = {
                "fields": ",".join(te_fields)
            }

        response = self._make_request(query_url, params)
        return response

    def get_malware_object(self, malware_id):

        query_url = "%s/%s" % (self.graph_url, malware_id)
        response = self._make_malware_request(query_url)

        if response.get("error") is not None:
            return self._build_doc(malware_id, response, False)
        else:
            # TODO: Fix this
            malware_obj = MalwareObject(response)
            return self._build_doc(
                malware_id,
                # {"malware_obj": response},
                {"malware_obj": json.loads(str(malware_obj))},
                True
            )

    def get_malware_objects_dropped(self, malware_id):

        query_url = "%s/%s/dropped" % (self.graph_url, malware_id)
        response = self._make_malware_request(query_url)

        success = True
        if response.get("error") is not None:
            success = False

        # TODO: Iterate on "data" binding each result to an object
        # TODO: Make a pager method
        return self._build_doc(
            malware_id,
            {"dropped": response},
            success
        )

    def get_malware_objects_dropped_by(self, malware_id):

        query_url = "%s/%s/dropped_by" % (self.graph_url, malware_id)
        response = self._make_malware_request(query_url)

        success = True
        if response.get("error") is not None:
            success = False

        # TODO: Iterate on "data" binding each result to an object
        # TODO: Make a pager method
        return self._build_doc(
            malware_id,
            {"dropped_by": response},
            success
        )

    def get_malware_object_families(self, malware_id):

        query_url = "%s/%s/families" % (self.graph_url, malware_id)
        te_fields = MalwareFamilyObject.TEFields().all()
        params = {"fields": te_fields}

        response = self._make_malware_request(query_url, params=params)

        success = True
        if response.get("error") is not None:
            success = False

        return self._build_doc(
            malware_id,
            {"families": response},
            success
        )

    def get_malware_object_indicators(self, malware_id):

        query_url = "%s/%s/threat_indicators" % (self.graph_url, malware_id)
        te_fields = ThreatIndicatorObject.TEFields().all()
        params = {"fields": te_fields}

        response = self._make_malware_request(query_url, params=params)

        success = True
        if response.get("error") is not None:
            success = False

        return self._build_doc(
            malware_id,
            {"indicators": response},
            success
        )

    def get_malware_family_object(self, family_id):

        te_fields = MalwareFamilyObject.TEFields().all()
        params = {
            "fields": ",".join(te_fields)
        }

        query_url = "%s/%s" % (self.graph_url, family_id)
        response = self._make_request(query_url, params)

        success = True
        if response.get("error") is not None:
            success = False
            return self._build_doc(family_id, response, success)
        else:
            malware_family_obj = MalwareFamilyObject(response)
            return self._build_doc(family_id, str(malware_family_obj), success)

    def get_malware_family_variants(self, family_id):

        te_fields = MalwareObject.TEFields().all()
        params = {"fields": te_fields}
        query_url = "%s/%s/variants" % (self.graph_url, family_id)

        response = self._make_request(query_url, params)

        success = True
        if response.get("error") is not None:
            success = False

        return self._build_doc(family_id, response, success)

    def get_indicator_object(self, indicator_id):

        te_fields = ThreatIndicatorObject.TEFields().all()
        params = {"fields": te_fields}
        query_url = "%s/%s" % (self.graph_url, indicator_id)

        response = self._make_request(query_url, params)

        success = True
        if response.get("error") is not None:
            success = False
            return self._build_doc(indicator_id, response, success)
        else:
            return self._build_doc(
                indicator_id,
                str(ThreatIndicatorObject(response)),
                success
            )

    def get_indicator_descriptors(self, indicator_id):

        te_fields = ThreatDescriptorObject.TEFields().all()
        params = {"fields": te_fields}
        query_url = "%s/%s/descriptors" % (self.graph_url, indicator_id)

        response = self._make_request(query_url, params)

        success = True
        if response.get("error") is not None:
            success = False

        return self._build_doc(indicator_id, response, success)

    def get_related_indicators(self, indicator_id):

        te_fields = ThreatIndicatorObject.TEFields().all()
        params = {"fields": te_fields}
        query_url = "%s/%s/related" % (self.graph_url, indicator_id)

        response = self._make_request(query_url, params)

        success = True
        if response.get("error") is not None:
            success = False

        return self._build_doc(indicator_id, response, success)

    def get_indicator_malware(self, indicator_id):

        te_fields = MalwareObject.TEFields().all()
        params = {"fields": te_fields}
        query_url = "%s/%s/malware_analyses" % (self.graph_url, indicator_id)

        response = self._make_request(query_url, params)

        success = True
        if response.get("error") is not None:
            success = False

        return self._build_doc(indicator_id, response, success)

    def get_threat_descriptor_object(self, descriptor_id):

        te_fields = ThreatDescriptorObject.TEFields().all()
        params = {"fields": te_fields}
        query_url = "%s/%s" % (self.graph_url, descriptor_id)

        response = self._make_request(query_url, params)
        if response.get("error") is not None:
            return self._build_doc(descriptor_id, response, False)
        else:
            return self._build_doc(
                descriptor_id,
                str(ThreatDescriptorObject(response)),
                True
            )

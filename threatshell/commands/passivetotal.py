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

from threatshell.commands.q import AutoQuery
from threatshell.doctypes import passivetotal

import json
import logging
import requests

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


class PassiveTotal:

    def __init__(self, config):

        self.key = config.get("PassiveTotal", "key")
        self.username = config.get("PassiveTotal", "username")
        self.auth = (self.username, self.key)
        self.url = "https://api.passivetotal.org/v2"
        self.post_headers = {'Content-Type': 'application/json'}

        self.account = "%s/account" % self.url
        self.account_history = "%s/history" % self.account
        self.account_notifications = "%s/notifications" % self.account
        self.account_organization = "%s/organization" % self.account
        self.account_org_teamstream = (
            "%s/teamstream" % self.account_organization
        )
        self.account_sources = "%s/sources" % self.account

        self.dns = "%s/dns" % self.url
        self.pdns = "%s/passive" % self.dns
        self.unique_pdns = "%s/unique" % self.pdns

        self.enrichment = "%s/enrichment" % self.url
        self.malware_enrichment = "%s/malware" % self.enrichment
        self.osint_enrichment = "%s/osint" % self.enrichment
        self.subdomain_enrichment = "%s/subdomains" % self.enrichment

        self.whois = "%s/whois" % self.url
        self.whois_search = "%s/search" % self.whois

        self.actions = "%s/actions" % self.url
        self.action_tags = "%s/tags" % self.actions
        self.action_classification = "%s/classification" % self.actions
        self.action_compromised = "%s/ever-compromised" % self.actions
        self.action_dyndns = "%s/dynamic-dns" % self.actions
        self.action_monitor = "%s/monitor" % self.actions
        self.action_sinkhole = "%s/sinkhole" % self.actions
        self.action_tag_search = "%s/search" % self.action_tags

        self.host_attrs = "%s/host-attributes" % self.url
        self.host_attr_components = "%s/components" % self.host_attrs
        self.host_attr_trackers = "%s/trackers" % self.host_attrs
        self.tracker_search = "%s/trackers/search" % self.url

        self.ssl_certs = "%s/ssl-certificate" % self.url
        self.ssl_cert_history = "%s/history" % self.ssl_certs
        self.ssl_cert_search = "%s/search" % self.ssl_certs

    def _error(self, arg, endpoint, code, content):
        message = "Failed to query passive total endpoint %s - %s: %s" % (
            endpoint,
            code,
            content
        )
        log.error(message)
        record = {arg: {"error": message}}
        return (record, False)

    def _query(self, name, endpoint, params={}):

        r = requests.get(endpoint, params=params, verify=False, auth=self.auth)
        if r.status_code != requests.codes.ok:
            return self._error(name, endpoint, r.status_code, r.content)

        return ({name: r.json()}, True)

    def _post(self, endpoint, data=None):

        resp = requests.post(
            endpoint,
            auth=self.auth,
            data=json.dumps(data),
            headers=self.post_headers
        )

        if resp.status_code != requests.codes.ok:
            return self._error(
                "POST",
                endpoint,
                resp.status_code,
                resp.content
            )

        return {"POST": resp.json()}

    def get_account_info(self):
        jdata, status = self._query("account", self.account)
        account_info = passivetotal.AccountEntry(jdata["account"])
        setattr(account_info, "successful", status)
        return account_info

    def get_account_history(self):
        jdata, status = self._query("account_history", self.account_history)
        account_hist = passivetotal.AccountHistoryResponse(
            jdata["account_history"]
        )
        setattr(account_hist, "successful", status)
        return account_hist

    def get_account_notifications(self, params={}):
        jdata, status = self._query(
            "account_notifications",
            self.account_notifications,
            params=params
        )
        account_notifications = passivetotal.AccountNotificationResponse(
            jdata["account_notifications"]
        )
        setattr(account_notifications, "successful", status)
        return account_notifications

    def get_organization_details(self):
        jdata, status = self._query(
            "organization_details",
            self.account_organization
        )
        org_details = passivetotal.AccountOrganizationEntry(
            jdata["organization_details"]
        )
        setattr(org_details, "successful", status)
        return org_details

    def get_organization_teamstream(self, params={}):
        jdata, status = self._query(
            "organization_teamstream",
            self.account_org_teamstream,
            params=params
        )
        org_teamstream = passivetotal.AccountTeamStreamResponse(
            jdata["organization_teamstream"]
        )
        setattr(org_teamstream, "successful", status)
        return org_teamstream

    def get_source_details(self, sources=[]):

        if not sources:
            jdata, status = self._query(
                "source_details",
                self.account_sources
            )
            doc = passivetotal.AccountSourceResponse(jdata["source_details"])
            setattr(doc, "successful", status)

        if not isinstance(sources, list):
            sources = [sources]

        docs = []
        for source in sources:

            jdata, status = self._query(
                "source_details",
                self.account_sources,
                params={
                    "source": source
                }
            )
            docs.append(
                passivetotal.AccountSourceResponse(jdata["source_details"])
            )
            setattr(docs[-1], "successful", status)

        return docs

    @AutoQuery.use_on(["domain"])
    def get_passive_dns(self, domains, params={}):

        if not isinstance(domains, list):
            domains = [domains]

        docs = []
        for domain in domains:
            query_params = params
            query_params["query"] = domain
            jdata, status = self._query(
                domain,
                self.pdns,
                params=query_params
            )
            docs.append(passivetotal.PassiveDNSResponse(jdata[domain]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", domain)

        return docs

    @AutoQuery.use_on(["domain"])
    def get_unique_passive_dns(self, domains, params={}):

        if not isinstance(domains, list):
            domains = [domains]

        docs = []
        for domain in domains:
            query_params = params
            query_params["query"] = domain
            jdata, status = self._query(
                domain,
                self.unique_pdns,
                params=query_params
            )
            docs.append(passivetotal.PassiveDNSUnique(jdata[domain]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", domain)

        return docs

    @AutoQuery.use_on(["domain"])
    def get_domain_enrichment(self, domains, params={}):

        if not isinstance(domains, list):
            domains = [domains]

        docs = []
        for domain in domains:
            jdata, status = self._query(
                domain,
                self.enrichment,
                params={
                    "query": domain
                }
            )
            docs.append(passivetotal.DomainEnrichment(jdata[domain]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", domain)

        return docs

    @AutoQuery.use_on(["ip"])
    def get_ip_enrichment(self, ips, params={}):

        if not isinstance(ips, list):
            ips = [ips]

        docs = []
        for ip in ips:
            jdata, status = self._query(
                ip,
                self.enrichment,
                params={
                    "query": ip
                }
            )
            if status:

                location = {
                    "lat": jdata[ip].get("latitude"),
                    "lon": jdata[ip].get("longitude")
                }

                if jdata[ip].get("latitude") is not None:
                    del jdata[ip]["latitude"]

                if jdata[ip].get("longitude") is not None:
                    del jdata[ip]["longitude"]

                jdata[ip]["location"] = location

            docs.append(passivetotal.IPEnrichment(jdata[ip]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", ip)

        return docs

    @AutoQuery.use_on(["domain", "ip", "hash"])
    def get_malware_enrichment(self, queries, params={}):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.malware_enrichment,
                params={
                    "query": query
                }
            )
            docs.append(
                passivetotal.MalwareEnrichmentResponse(
                    jdata[query]
                )
            )
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", query)

        return docs

    @AutoQuery.use_on(["domain", "ip", "hash"])
    def get_osint_enrichment(self, queries, params={}):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.osint_enrichment,
                params={
                    "query": query
                }
            )
            docs.append(
                passivetotal.OSIntEnrichmentResponse(jdata[query])
            )
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", query)

        return docs

    @AutoQuery.use_on(["domain"])
    def get_subdomain_enrichment(self, domains, params={}):

        if not isinstance(domains, list):
            domains = [domains]

        docs = []
        for domain in domains:
            jdata, status = self._query(
                domain,
                self.subdomain_enrichment,
                params={
                    "query": domain
                }
            )
            docs.append(passivetotal.SubdomainEnrichment(jdata[domain]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", domain)

        return docs

    @AutoQuery.use_on(["domain", "ip"])
    def get_whois(self, queries, params={}):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            query_params = params
            query_params["query"] = query
            jdata, status = self._query(
                query,
                self.whois,
                params=query_params
            )

            whois_entry = passivetotal.WhoisEntry()
            for k, v in jdata[query].items():
                if v == "N/A":
                    v = None
                setattr(whois_entry, k, v)

            setattr(whois_entry, "successful", status)
            setattr(whois_entry, "term", query)

            docs.append(whois_entry)

        return docs

    @AutoQuery.use_on(["domain", "email", "nameserver", "phone"])
    def search_whois(self, queries, params={}):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            query_params = params
            query_params["query"] = query
            jdata, status = self._query(
                query,
                self.whois_search,
                params=query_params
            )
            docs.append(passivetotal.WhoisSearchResponse(jdata[query]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", query)

        return docs

    def add_tags(self, params):
        return self._post(self.action_tags, data=params)

    def get_tags(self, query):
        jdata, status = self._query(
            "pt_tags",
            self.action_tags,
            params={
                "query": query
            }
        )
        return jdata

    def rm_tags(self, params):
        resp = requests.delete(
            self.action_tags,
            auth=self.auth,
            headers=self.post_headers,
            data=json.dumps(params)
        )

        if resp.status_code != requests.codes.ok:
            return self._error(
                "DELETE",
                self.action_tags,
                resp.status_code,
                resp.content
            )

        return {"DELETE": resp.json()}

    def search_tags(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.action_tag_search,
                params={
                    "query": query
                }
            )
            docs.append(jdata)

        return docs

    def set_tags(self, params):
        resp = requests.put(
            self.action_tags,
            auth=self.auth,
            data=json.dumps(params),
            headers=self.post_headers
        )

        if resp.status_code != requests.codes.ok:
            return self._error(
                "PUT",
                self.action_tags,
                resp.status_code,
                resp.content
            )

        return {"PUT": resp.json()}

    @AutoQuery.use_on(["domain", "ip"])
    def get_classification_status(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.action_classification,
                params={
                    "query": query
                }
            )
            docs.append(passivetotal.ClassificationEntry(jdata[query]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", query)

        return docs

    @AutoQuery.use_on(["domain", "ip"])
    def get_compromised_status(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.action_compromised,
                params={
                    "query": query
                }
            )
            docs.append(passivetotal.CompromisedEntry(jdata[query]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", query)

        return docs

    @AutoQuery.use_on(["domain"])
    def check_dynamic_dns(self, domains):

        if not isinstance(domains, list):
            domains = [domains]

        docs = []
        for domain in domains:
            jdata, status = self._query(
                domain,
                self.action_dyndns,
                params={
                    "query": domain
                }
            )
            docs.append(passivetotal.DynamicDNSEntry(jdata[domain]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", domain)

        return docs

    def get_monitor_status(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.action_monitor,
                params={
                    "query": query
                }
            )
            docs.append(passivetotal.MonitorEntry(jdata[query]))
            setattr(docs[-1], "successful", status)

        return docs

    @AutoQuery.use_on(["ip"])
    def get_sinkhole_status(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.action_sinkhole,
                params={
                    "query": query
                }
            )
            docs.append(passivetotal.SinkholeEntry(jdata[query]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", query)

        return docs

    def set_classification_status(self, params):
        return self._post(self.action_classification, data=params)

    def set_compromised_status(self, params):
        return self._post(self.action_compromised, data=params)

    def set_ddns_status(self, params):
        return self._post(self.action_dyndns, data=params)

    def set_monitor_status(self, params):
        return self._post(self.action_monitor, data=params)

    def set_sinkhole_status(self, params):
        return self._post(self.action_sinkhole, data=params)

    def get_host_components(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.host_attr_components,
                params={
                    "query": query
                }
            )
            docs.append(passivetotal.HostAttributesResponse(jdata[query]))
            setattr(docs[-1], "successful", status)

        return docs

    @AutoQuery.use_on(["domain"])
    def get_host_trackers(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.host_attr_trackers,
                params={
                    "query": query
                }
            )
            docs.append(passivetotal.HostTrackerResponse(jdata[query]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", query)

        return docs

    def search_host_trackers(self, params):

        jdata, status = self._query(
            params["query"],
            self.tracker_search,
            params=params
        )
        doc = passivetotal.HostTrackerSearchResponse(jdata[params["query"]])
        setattr(doc, "successful", status)
        setattr(doc, "term", params["query"])
        return doc

    @AutoQuery.use_on(["ip", "sha1"])
    def get_ssl_cert_history(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.ssl_cert_history,
                params={
                    "query": query
                }
            )
            # TODO: Fix the results returning None because it's nested
            docs.append(passivetotal.SSLCertHistoryResponse(jdata[query]))
            setattr(docs[-1], "successful", status)
            setattr(docs[-1], "term", query)

        return docs

    @AutoQuery.use_on(["sha1"])
    def get_ssl_cert(self, queries):

        if not isinstance(queries, list):
            queries = [queries]

        docs = []
        for query in queries:
            jdata, status = self._query(
                query,
                self.ssl_certs,
                params={
                    "query": query
                }
            )
            entry = passivetotal.SSLCertEntry()
            for k, v in jdata.items():
                setattr(entry, k, v)

            setattr(entry, "successful", status)
            setattr(entry, "term", query)
            docs.append(entry)

        return docs

    def search_ssl_certs(self, params):

        jdata, status = self._query(
            "ssl_cert_search",
            self.ssl_cert_search,
            params=params
        )
        doc = passivetotal.SSLCertSearchResponse(jdata["ssl_cert_search"])
        setattr(doc, "successful", status)
        setattr(doc, "term", params["query"])
        return doc

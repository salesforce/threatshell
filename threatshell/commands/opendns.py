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
from threatshell.doctypes import opendns as opendns_docs
from netaddr import IPNetwork
import json
import logging
import requests

try:
    requests.packages.urllib3.disable_warnings()
except Exception, e:
    print "[%s]: %s" % (e.__class__.__name__, e.message)


log = logging.getLogger(__name__)


class OpenDNS_API:

    # TODO: figure out why the resp. code is always 200.
    # Currently it only changes to a 400 on the failed
    # batch request
    # odns_responses = { 200 : "OK" }

    # Start of OpenDNS_API Class

    def __init__(self, config):

        self.sgraph_dom = "https://investigate.api.opendns.com/%s"
        self.dns_req_url = self.sgraph_dom % "dnsdb/name/%s/%s.json"
        self.mal_idx_url = self.sgraph_dom % "domains/score/%s"
        self.malb_idx_url = self.sgraph_dom % "domains/score/"
        self.co_oc_url = self.sgraph_dom % "recommendations/name/%s.json"
        self.related_url = self.sgraph_dom % "links/name/%s.json"
        self.sec_info_url = self.sgraph_dom % "security/name/%s.json"
        self.ip_dns_url = self.sgraph_dom % "dnsdb/ip/%s/%s.json"
        self.cat_url = self.sgraph_dom % "domains/categories/"
        self.catb_url = self.sgraph_dom % "domains/categorization/"
        self.cats_url = self.sgraph_dom % (
            "domains/categorization/%s?showLables"
        )
        self.whois_email_url = self.sgraph_dom % "whois/emails/"
        self.whois_multi_email_url = self.sgraph_dom % "whois/emails"
        self.whois_ns_url = self.sgraph_dom % "whois/nameservers/"
        self.whois_multi_ns_url = self.sgraph_dom % "whois/nameservers"
        self.whois_url = self.sgraph_dom % "whois"
        self.ip_mal_doms_url = self.sgraph_dom % "ips/%s/latest_domains"
        self.asn_info = self.sgraph_dom % "bgp_routes/ip/%s/as_for_ip.json"
        self.asprefix_info = (
            self.sgraph_dom % "bgp_routes/asn/%s/prefixes_for_asn.json"
        )
        self.categories = {}
        self.header = {
            "Authorization": "Bearer %s" % config.get("OpenDNS", "api_token")
        }
        self.rtypes = ["a", "ns", "mx", "txt", "cname"]
        self.ip_rtypes = ["a", "ns"]
        self.last_json = None

    def _get_ip(self, ip_list):

        ip_strs = []
        if not isinstance(ip_list, list):
            ip = [ip_list]

        for ip in ip_list:
            try:

                ip_addr = IPNetwork(ip)

                if ip_addr.is_private():
                    log.warn(
                        "%s is a private address space - skipping" % ip_addr
                    )
                    continue

                ip_list = list(ip_addr)
                for ip_str in ip_list:
                    ip_strs.append(str(ip_str))

            except Exception, e:
                message = {"error": "IP error: %s" % str(e)}
                return message

        return ip_strs

    def _make_request(self, req, params=None):

        res = None
        if params is None:
            res = requests.get(req, verify=False, headers=self.header)
        else:
            res = requests.get(
                req,
                verify=False,
                headers=self.header,
                params=params
            )

        if res.status_code != requests.codes.ok:
            return {"error": "[%s]: %s" % (res.status_code, res.content)}

        self.last_json = res.content
        return res.json()

    def _get_categories(self):

        res = requests.get(self.cat_url, headers=self.header)
        if res.status_code != requests.codes.ok:
            res.raise_for_status()

        self.last_json = res.content
        self.categories = res.json()

    @AutoQuery.use_on(["domain"])
    def request_categories_batch(self, domain_list):

        if not isinstance(domain_list, list):
            domain_list = [domain_list]

        if not self.categories:
            self._get_categories()

        res = requests.post(
            self.catb_url,
            json.dumps(domain_list),
            headers=self.header,
            params={"showLables": True}
        )

        docs = []
        if res.status_code != requests.codes.ok:

            message = "[%s]: %s" % (res.status_code, res.content)
            log.error(message)

            for dom in domain_list:
                doc = opendns_docs.DomainCategorizationDoc()
                doc.successful = False
                doc.term = dom

            return docs

        data = res.json()
        for domain in domain_list:
            doc = opendns_docs.DomainCategorizationDoc(data.get(domain))
            doc.successful = True
            doc.term = domain
            docs.append(doc)

        return docs

    @AutoQuery.use_on(["domain"])
    def request_dns_info(self, domain_list, rtype="a"):

        if not isinstance(domain_list, list):
            domain_list = [domain_list]

        docs = []
        if rtype.lower() not in self.rtypes:
            log.error(
                "error: Record type '%s' is unsupported by OpenDNS" % rtype
            )
            return docs

        for domain in domain_list:

            req = self.dns_req_url % (rtype, domain)
            res = self._make_request(req)

            doc = opendns_docs.DomainResourceRecordDoc()
            doc.term = domain

            if res.get("error") is not None:
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)
            else:
                doc.successful = True
                for k, v in res.items():

                    if v is None:
                        v = {}

                    if k == "class":
                        k = "class_type"

                    elif k == "type":
                        k = "query_type"

                    setattr(doc, k, v)

                docs.append(doc)

        return docs

    def request_known_malicious_index(self, domain_list):

        if not isinstance(domain_list, list):
            domain_list = [domain_list]

        docs = []
        for domain in domain_list:

            req = self.mal_idx_url % domain
            res = self._make_request(req)

            doc = opendns_docs.DomainScoreDoc()
            doc.term = domain

            if res.get("error") is not None:
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                doc.domain = domain
                doc.status = "0"
                docs.append(doc)

            else:
                doc.successful = True
                doc.domain = domain
                doc.status = res.get(domain)
                docs.append(doc)

        return docs

    @AutoQuery.use_on(["domain"])
    def request_known_malicious_index_batch(self, domain_list):

        if not isinstance(domain_list, list):
            domain_list = [domain_list]

        res = requests.post(
            self.malb_idx_url,
            json.dumps(domain_list),
            headers=self.header
        )

        docs = []
        if res.status_code != requests.codes.ok:
            message = "[%s]: %s" % (res.status_code, res.content)
            log.error(message)
            return docs

        data = res.json()
        for domain in domain_list:
            doc = opendns_docs.DomainScoreDoc()
            doc.successful = True
            doc.term = domain
            doc.domain = domain
            doc.status = data.get(domain)
            docs.append(doc)

        return docs

    @AutoQuery.use_on(["domain"])
    def request_co_occurences(self, domain_list):

        if not isinstance(domain_list, list):
            domain_list = [domain_list]

        docs = []
        for domain in domain_list:

            req = self.co_oc_url % domain
            res = self._make_request(req)

            doc = opendns_docs.CoOccurrencesDoc()
            doc.term = domain

            if res.get("error") is not None:
                log.error("Error: %s" % res.get("error"))
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)

            else:
                doc.successful = True
                for k, v in res.items():

                    if v is None:
                        v = {}

                    if k == "pfs2":

                        new_pfs2 = []

                        for dom, score in v:
                            new_pfs2.append(
                                {
                                    "domain": dom,
                                    "score": score
                                }
                            )
                        setattr(doc, k, new_pfs2)

                    else:
                        setattr(doc, k, v)

                docs.append(doc)

        return docs

    @AutoQuery.use_on(["domain"])
    def request_related_domains(self, domain_list):

        if not isinstance(domain_list, list):
            domain_list = [domain_list]

        docs = []
        for domain in domain_list:

            req = self.related_url % domain
            res = self._make_request(req)

            doc = opendns_docs.RelatedDomainsDoc()
            doc.term = domain

            if res.get("error") is not None:
                log.error(res.get("error"))
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)

            else:
                doc.successful = True
                for k, v in res.items():

                    if v is None:
                        v = {}

                    if k == "tb1":
                        tb1 = []
                        for dom, score in v:
                            tb1.append(
                                {
                                    "domain": dom,
                                    "score": score
                                }
                            )
                        setattr(doc, k, tb1)

                    else:
                        setattr(doc, k, v)

                docs.append(doc)

        return docs

    @AutoQuery.use_on(["domain"])
    def request_security_info(self, domain_list):

        if not isinstance(domain_list, list):
            domain_list = [domain_list]

        docs = []
        for domain in domain_list:

            req = self.sec_info_url % domain
            res = self._make_request(req)

            doc = opendns_docs.DomainSecurityInfoDoc()
            doc.term = domain

            if res.get("error") is not None:
                log.error(res.get("error"))
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)

            else:
                doc.successful = True
                for k, v in res.items():

                    if v is None:
                        v = {}

                    if "geodiversity" in k:
                        tmp = []
                        for cc, score in v:
                            tmp.append(
                                {
                                    "country_code": cc,
                                    "score": score
                                }
                            )
                        setattr(doc, k, tmp)

                    else:
                        setattr(doc, k, v)

                docs.append(doc)

        return docs

    @AutoQuery.use_on(["ip"])
    def request_ip_dns_info(self, ips, rtype="a"):

        if not isinstance(ips, list):
            ips = [ips]

        rtype = rtype.lower()
        docs = []
        if rtype not in self.ip_rtypes:

            log.error(
                (
                    "Record type '%s' currently unsupported by OpenDNS for " +
                    "IP lookup"
                ) % rtype
            )

            return docs

        ip_strs = self._get_ip(ips)
        if isinstance(ip_strs, dict):
            log.error(ip_strs.get("error"))
            return docs

        for ip in ip_strs:

            req = self.ip_dns_url % (rtype, ip)
            res = self._make_request(req)

            doc = opendns_docs.IPResourceRecordHistoryDoc()
            doc.term = ip

            if res.get("error") is not None:
                log.error(res.get("error"))
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)

            else:
                doc.successful = True
                for k, v in res.items():
                    setattr(doc, k, v)
                docs.append(doc)

        return docs

    @AutoQuery.use_on(["email"])
    def request_whois_email(self, emails, limit=10):

        if not isinstance(emails, list):
            emails = [emails]

        request_url = ""
        params = {"limit": limit}
        if len(emails) == 1:
            request_url = self.whois_email_url + emails[0]
        else:
            request_url = self.whois_multi_email_url
            params["emailList"] = ",".join(emails)

        docs = []
        res = self._make_request(request_url, params=params)

        for email in emails:

            doc = opendns_docs.WhoisEmailToDomainDoc()
            doc.term = email

            if res.get("error") is not None:
                log.error(res.get("error"))
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)

            else:
                doc.successful = True
                for k, v in res.items():
                    setattr(doc, k, v)
                docs.append(doc)

        return docs

    @AutoQuery.use_on(["nameserver"])
    def request_whois_nameserver(self, name_servers, limit=10):

        if not isinstance(name_servers, list):
            name_servers = [name_servers]

        request_url = ""
        params = {"limit": limit}
        if len(name_servers) == 1:
            request_url = self.whois_ns_url + name_servers[0]
        else:
            request_url = self.whois_multi_ns_url
            params["nameServerList"] = ",".join(name_servers)

        docs = []
        res = self._make_request(request_url, params=params)

        for ns in name_servers:

            doc = opendns_docs.WhoisNameServerToDomainDoc()
            doc.term = ns

            if res.get("error") is not None:
                log.error(res.get("error"))
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)

            else:
                doc.successful = True
                for k, v in res.items():
                    setattr(doc, k, v)
                docs.append(doc)

        return docs

    # TODO: Handle raw records and stuff
    @AutoQuery.use_on(["domain"])
    def request_whois_domain(self, domains, limit=10, history=False):

        if not isinstance(domains, list):
            domains = [domains]

        docs = []
        for domain in domains:

            request_url = "%s/%s" % (self.whois_url, domain)

            if history:
                request_url = "%s/%s" % (request_url, "history")

            params = {"limit": limit}
            res = self._make_request(request_url, params=params)

            doc = opendns_docs.WhoisDomainRecordDoc()
            doc.term = domain

            # Historical records
            if isinstance(res, list):
                for entry in res:
                    doc = opendns_docs.WhoisDomainRecordDoc(entry)
                    doc.successful = True
                    docs.append(doc)

            elif res.get("error") is not None:
                log.error(res.get("error"))
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)

            else:
                doc.successful = True
                for k, v in res.items():
                    setattr(doc, k, v)
                docs.append(doc)

        return docs

    @AutoQuery.use_on(["ip"])
    def request_mal_domains_for_ip(self, ips):

        if not isinstance(ips, list):
            ips = [ips]

        docs = []

        for ip in ips:

            res = self._make_request(self.ip_mal_doms_url % ip)

            doc = opendns_docs.LatestMaliciousDomsDoc()
            doc.term = ip

            if isinstance(res, list):
                for entry in res:
                    d = opendns_docs.LatestMaliciousDomsDoc(entry)
                    d.successful = True
                    d.term = ip
                    docs.append(d)

            elif res.get("error") is not None:
                log.error(res.get("error"))
                doc.successful = False
                docs.append(doc)

            elif res is None:
                doc.successful = True
                docs.append(doc)

            else:
                doc.successful = True
                for k, v in res.items():
                    setattr(doc, k, v)
                docs.append(doc)

        return docs

    @AutoQuery.use_on(["ip"])
    def request_ip_asn_info(self, ips):

        if not isinstance(ips, list):
            ips = [ips]

        ips = self._get_ip(ips)
        docs = []

        if isinstance(ips, dict):
            log.error(ips.get("error"))
            return docs

        for ip in ips:

            request_url = self.asn_info % ip
            response = self._make_request(request_url)

            if isinstance(response, list):
                for entry in response:
                    doc = opendns_docs.ASInformationDoc(entry)
                    doc.successful = True
                    doc.term = ip
                    docs.append(doc)

            elif response.get("error") is not None:
                log.error(reponse.get("error"))
                doc = opendns_docs.ASInformationDoc()
                doc.successful = False
                doc.term = ip
                docs.append(doc)

            elif response is None:
                doc = opendns_docs.ASInformationDoc()
                doc.successful = True
                doc.term = ip
                docs.append(doc)

            else:
                doc = opendns_docs.ASInformationDoc(response)
                doc.successful = True
                doc.term = ip
                docs.append(doc)

        return docs

    @AutoQuery.use_on(["asnum"])
    def request_asprefix_info(self, asnums):

        if not isinstance(asnums, list):
            asnums = [asnums]

        docs = []
        for asnum in asnums:

            request_url = self.asprefix_info % asnum
            response = self._make_request(request_url)

            if isinstance(response, list):
                for entry in response:
                    doc = opendns_docs.ASPrefixInformationDoc(entry)
                    doc.successful = True
                    doc.term = asnum
                    docs.append(doc)

            elif response.get("error") is not None:
                log.error(reponse.get("error"))
                doc = opendns_docs.ASPrefixInformationDoc()
                doc.successful = False
                doc.term = asnum
                docs.append(doc)

            elif response is None:
                doc = opendns_docs.ASPrefixInformationDoc()
                doc.successful = True
                doc.term = asnum
                docs.append(doc)

            else:
                doc = opendns_docs.ASPrefixInformationDoc(response)
                doc.successful = True
                doc.term = asnum
                docs.append(doc)

        return docs

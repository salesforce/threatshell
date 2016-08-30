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

from threatshell.common.abstracts import JSONEntry
from threatshell.doctypes.generic import (
    GenericDoc,
    ThreatshellIndex,
    email_analyzer,
    hostname_analyzer
)
from elasticsearch_dsl import (
    Boolean,
    Date,
    GeoPoint,
    Integer,
    Ip,
    Nested,
    Object,
    String
)
import logging

log = logging.getLogger(__name__)
# TODO: figure out cidr mapping


class AccountEntry(JSONEntry):

    def __init__(self, jdata={}):

        self.username = ""
        self.firstName = ""
        self.lastName = ""
        self.firstActive = ""
        self.lastActive = ""
        self.organization = ""

        JSONEntry.__init__(self, jdata)


class AccountHistoryEntry(JSONEntry):

    def __init__(self, jdata={}):

        self.username = ""
        self.additional = {}
        self.focus = ""
        self.source = ""
        self.context = ""
        self.dt = ""
        self.type = ""

        JSONEntry.__init__(self, jdata)


class AccountHistoryResponse(JSONEntry):

    def __init__(self, jdata={}):

        self.history = []

        if jdata is not None:
            for history in jdata["history"]:
                self.history.append(AccountHistoryEntry(history))


class AccountNotificationEntry(JSONEntry):

    def __init__(self, jdata={}):

        self.username = ""
        self.headline = ""
        self.generated = ""
        self.content = ""
        self.type = ""

        JSONEntry.__init__(self, jdata)


class AccountNotificationResponse(JSONEntry):

    def __init__(self, jdata={}):

        self.notifications = []

        if jdata is not None:
            for n in jdata["notifications"]:
                self.notifications.append(AccountNotificationEntry(n))


class AccountOrganizationEntry(JSONEntry):

    def __init__(self, jdata={}):

        self.activeMembers = []
        self.status = ""
        self.endpoint = {}
        self.name = ""
        self.lastActive = ""
        self.firstActive = ""
        self.nextRefresh = ""
        self.acceptableDomains = []
        self.searchQuota = ""
        self.registered = ""
        self.watchQuota = ""
        self.active = False
        self.admins = []
        self.inactiveMembers = []
        self.seats = 0
        self.id = ""

        JSONEntry.__init__(self, jdata)


class AccountTeamStreamEntry(JSONEntry):

    def __init__(self, jdata={}):

        self.username = ""
        self.additional = {}
        self.focus = ""
        self.source = ""
        self.context = ""
        self.dt = ""
        self.type = ""

        JSONEntry.__init__(self, jdata)


class AccountTeamStreamResponse(JSONEntry):

    def __init__(self, jdata={}):

        self.teamstream = []

        if jdata is not None:
            for entry in jdata["teamstream"]:
                self.teamstream.append(AccountTeamStreamEntry(entry))


class AccountSource(JSONEntry):

    def __init__(self, jdata={}):

        self.active = False
        self.source = ""
        self.configuration = {}

        JSONEntry.__init__(self, jdata)


class AccountSourceResponse(JSONEntry):

    def __init__(self, jdata={}):

        self.sources = []
        if jdata is not None:
            for entry in jdata["sources"]:
                self.sources.append(AccountSource(entry))


@ThreatshellIndex.doc_type
class PassiveDNSEntry(GenericDoc):

    class Meta:
        doc_type = "passivetotal_passive_dns_entry"

    recordHash = String()
    resolve = Ip()
    value = String()
    source = String()
    lastSeen = Date()
    firstSeen = Date()
    collected = Date()


@ThreatshellIndex.doc_type
class PassiveDNSResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_passive_dns_response"

    results = Nested(
        doc_class=PassiveDNSEntry
    )

    queryValue = String()
    queryType = String()
    firstSeen = Date()
    lastSeen = Date()
    totalRecords = Integer()
    pager = Object()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class PassiveDNSUnique(GenericDoc):

    class Meta:
        doc_type = "passivetotal_passive_dns_unique"

    result_ips = Ip()
    frequency = Nested(
        properties={
            "entry": Nested(
                properties={
                    "ip": Ip(),
                    "count": Integer(index="not_analyzed")
                }
            )
        }
    )
    total = Integer()
    queryType = String()
    queryValue = String()
    pager = Object()

    def __setattr__(self, key, value):
        if key == "results":
            key = "result_ips"
        GenericDoc.__setattr__(self, key, value)

    def __init__(self, jdata={}):

        GenericDoc.__init__(self)

        for k, v in jdata.items():

            if k == "frequency":
                continue

            if v is None:
                v = {}

            setattr(self, k, v)

        if jdata.get("frequency") is not None:
            for ip, count in jdata.get("frequency"):
                self.frequency.append(
                    {
                        "entry": {
                            "ip": ip,
                            "count": count
                        }
                    }
                )


@ThreatshellIndex.doc_type
class Enrichment(GenericDoc):

    class Meta:
        doc_type = "passivetotal_enrichment"

    queryValue = String()
    tags = String()
    everCompromised = Boolean()
    queryType = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class IPEnrichment(Enrichment):

    class Meta:
        doc_type = "passivetotal_ip_enrichment"

    network = String()
    autonomousSystemName = String()
    autonomousSystemNumber = Integer()
    country = String()
    sinkhole = Boolean()
    location = GeoPoint()

    # def __setattr__(self, key, value):
    #     if key == "network":
    #         value = convert_cidr(value)
    #     super(IPEnrichment, self).__setattr__(key, value)

    def __init__(self, jdata={}):

        Enrichment.__init__(self, jdata)
        for k, v in jdata.items():

            if v is None:
                v = {}

            setattr(self, k, v)


@ThreatshellIndex.doc_type
class DomainEnrichment(Enrichment):

    class Meta:
        doc_type = "passivetotal_domain_enrichment"

    primaryDomain = String()
    dynamicDns = Boolean()
    subdomains = String()
    tld = String()

    def __init__(self, jdata={}):
        Enrichment.__init__(self, jdata)
        for k, v in jdata.items():
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class MalwareEnrichment(GenericDoc):

    class Meta:
        doc_type = "passivetotal_malware_enrichment"

    source = String()
    sourceUrl = String()
    sample = String()
    collectionDate = Date()


@ThreatshellIndex.doc_type
class MalwareEnrichmentResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_malware_enrichment_response"

    results = Nested(
        doc_class=MalwareEnrichment
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        self.results = jdata.get("results")


@ThreatshellIndex.doc_type
class OSIntEnrichment(GenericDoc):

    class Meta:
        doc_type = "passivetotal_osint_enrichment"

    source = String()
    sourceUrl = String()
    inReport = String()
    tags = String()


@ThreatshellIndex.doc_type
class OSIntEnrichmentResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_osint_enrichment_response"

    results = Nested(
        doc_class=OSIntEnrichment
    )

    def __init__(self, jdata={}):

        GenericDoc.__init__(self)
        self.results = jdata.get("results")


@ThreatshellIndex.doc_type
class SubdomainEnrichment(GenericDoc):

    queryValue = String()
    subdomains = String()

    class Meta:
        doc_type = "passivetotal_subdomain_enrichment"

    def __init__(self, jdata={}):
        GenericDoc.__init__(self, jdata)
        for k, v in jdata.items():
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class WhoisEntry(GenericDoc):

    class Meta:
        doc_type = "passivetotal_whois"

    contactEmail = String(
        analyzer=email_analyzer
    )
    domain = String()
    billing = Object()
    zone = Object()
    nameServers = String()
    registered = Date()
    lastLoadedAt = Date()
    whoisServer = String()
    registryUpdatedAt = Date()
    expiresAt = Date()
    registrar = String()
    admin = Object()
    tech = Object()
    registrant = Object()


@ThreatshellIndex.doc_type
class WhoisSearchResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_whois_response"

    results = Nested(
        doc_class=WhoisEntry
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        self.results = jdata.get("results")


@ThreatshellIndex.doc_type
class HostAttributes(GenericDoc):

    class Meta:
        doc_type = "passivetotal_host_attr_entry"

    lastSeen = Date()
    firstSeen = Date()
    category = String()
    label = String()
    hostname = String(
        analyzer=hostname_analyzer
    )


@ThreatshellIndex.doc_type
class HostAttributesResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_host_attr_response"

    results = Nested(
        doc_class=HostAttributes
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        self.results = jdata.get("results")


@ThreatshellIndex.doc_type
class HostTracker(GenericDoc):

    class Meta:
        doc_type = "passivetotal_host_tracker"

    lastSeen = Date()
    firstSeen = Date()
    attributeType = String()
    attributeValue = String()


@ThreatshellIndex.doc_type
class HostTrackerResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_host_tracker_response"

    results = Nested(
        doc_class=HostTracker
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        self.results = jdata.get("results")


@ThreatshellIndex.doc_type
class HostTrackerSearch(GenericDoc):

    class Meta:
        doc_type = "passivetotal_host_tracker_search"

    everBlacklisted = Boolean()
    alexaRank = Integer()
    hostname = String(
        analyzer=hostname_analyzer
    )


@ThreatshellIndex.doc_type
class HostTrackerSearchResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_host_tracker_search_response"

    results = Nested(
        doc_class=HostTrackerSearch
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        self.results = jdata.get("results")


@ThreatshellIndex.doc_type
class SSLCertHistory(GenericDoc):

    class Meta:
        doc_type = "passivetotal_ssl_cert_history"

    sha1 = String()
    firstSeen = Date()
    lastSeen = Date()
    ipAddresses = Ip()


@ThreatshellIndex.doc_type
class SSLCertHistoryResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_ssl_cert_history_response"

    results = Nested(
        doc_class=SSLCertHistory
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        self.results = jdata.get("results")


class SSLCertEntry(GenericDoc):

    class Meta:
        doc_type = "passivetotal_ssl_cert_entry"

    expirationDate = Date()
    fingerprint = String()
    issueDate = Date()
    issuerCommonName = String()
    issuerCountry = String()
    issuerEmailAddress = String(
        analyzer=email_analyzer
    )
    issuerGivenName = String()
    issuerLocalityName = String()
    issuerOrganizationName = String()
    issuerProvince = String()
    issuerSerialNumber = String()
    issuerStateOrProvinceName = String()
    issuerStreetAddress = String()
    issuerSurname = String()
    serialNumber = String()
    sha1 = String()
    sslVersion = Integer()
    subjectCommonName = String()
    subjectCountry = String()
    subjectEmailAddress = String(
        analyzer=email_analyzer
    )
    subjectGivenName = String()
    subjectLocalityName = String()
    subjectOrganizationName = String()
    subjectOrganizationUnitName = String()
    subjectProvince = String()
    subjectStreetAddress = String()
    subjectSurname = String()


@ThreatshellIndex.doc_type
class SSLCertSearchResponse(GenericDoc):

    class Meta:
        doc_type = "passivetotal_ssl_cert_search_response"

    results = Nested(
        doc_class=SSLCertEntry
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        self.results = jdata.get("results")


class Pager(JSONEntry):

    def __init__(self, jdata={}):

        self.next = ""
        self.previous = ""
        self.page_size = 0

        JSONEntry.__init__(self, jdata)


@ThreatshellIndex.doc_type
class ClassificationEntry(GenericDoc):

    class Meta:
        doc_type = "passivetotal_classification"

    classification = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class CompromisedEntry(GenericDoc):

    class Meta:
        doc_type = "passivetotal_compromised_history"

    everCompromised = Boolean()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class DynamicDNSEntry(GenericDoc):

    class Meta:
        doc_type = "passivetotal_dyndns_check"

    dynamicDns = Boolean()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            setattr(self, k, v)


class MonitorEntry(JSONEntry):

    def __init__(self, jdata={}):

        self.monitor = False
        JSONEntry.__init__(self, jdata)


@ThreatshellIndex.doc_type
class SinkholeEntry(GenericDoc):

    class Meta:
        doc_type = "passivetotal_sinkhole_check"

    sinkhole = Boolean()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            setattr(self, k, v)

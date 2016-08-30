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

from threatshell.doctypes.generic import (
    convert_cidr,
    BetterDate,
    email_analyzer,
    GenericDoc,
    ThreatshellIndex
)
from elasticsearch_dsl import(
    Boolean,
    Date,
    Float,
    GeoPoint,
    Index,
    Integer,
    Ip,
    Nested,
    String,
    analyzer,
    char_filter
)
import json


status_filter = char_filter(
    "opendns_status_filter",
    type="mapping",
    mappings=[
        "1 => benign",
        "0 => unknown",
        "-1 => malicious"
    ]
)

rir_filter = char_filter(
    "opendns_rir_filter",
    type="mapping",
    mappings=[
        "0 => Unknown",
        "1 => AfriNIC",
        "2 => APNIC",
        "3 => Arin",
        "4 => LACNIC",
        "5 => RIPE"
    ]
)

status_analyzer = analyzer(
    "opendns_status_analyzer",
    tokenizer="standard",
    char_filter=[status_filter]
)

rir_analyzer = analyzer(
    "opendns_rir_analyzer",
    tokenizer="standard",
    char_filter=[rir_filter],
    filter=["lowercase"]
)


@ThreatshellIndex.doc_type
class DomainCategorizationDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_domain_catigorization"

    status = String(analyzer=status_analyzer)
    security_categories = String(analyzer=status_analyzer)
    content_categories = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class DomainScoreDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_domain_score"

    domain = String()
    status = String(analyzer=status_analyzer)

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}

            setattr(self, k, v)


@ThreatshellIndex.doc_type
class PFS2Doc(GenericDoc):

    class Meta:
        doc_type = "opendns_co_occur_pfs2"

    domain = String()
    score = Float()


@ThreatshellIndex.doc_type
class CoOccurrencesDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_co_occurrences"

    pfs2 = Nested(
        doc_class=PFS2Doc
    )

    found = Boolean()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}

            setattr(self, k, v)


@ThreatshellIndex.doc_type
class TB1Doc(GenericDoc):

    class Meta:
        doc_type = "opendns_related_domains_tb1"

    domain = String()
    score = Float()


@ThreatshellIndex.doc_type
class RelatedDomainsDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_related_domains"

    tb1 = Nested(
        doc_class=TB1Doc
    )
    found = Boolean()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}

            setattr(self, k, v)


@ThreatshellIndex.doc_type
class GeoDiversityDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_security_info_geodiversity"

    country_code = String()
    score = Float()


@ThreatshellIndex.doc_type
class DomainSecurityInfoDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_security_info"

    dga_score = Float()
    perplexity = Float()
    entropy = Float()
    securerank2 = Float()
    pagerank = Float()
    asn_score = Float()
    prefix_score = Float()
    rip_score = Float()
    fastflux = Boolean()
    popularity = Float()
    geodiversity = Nested(
        doc_class=GeoDiversityDoc
    )
    geodiversity_normalized = Nested(
        doc_class=GeoDiversityDoc
    )
    tld_geodiversity = Nested(
        doc_class=GeoDiversityDoc
    )
    geoscore = Float()
    ks_test = Float()
    attack = String()
    threat_type = String()
    found = Boolean()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class ResourceRecordDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_resource_record"

    name = String()
    ttl = Integer()
    class_type = String()
    query_type = String()
    rr = Ip()


@ThreatshellIndex.doc_type
class DomainResourceRecordDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_domain_resource_record"

    first_seen = Date()
    last_seen = Date()
    rrs = Nested(
        doc_class=ResourceRecordDoc
    )


@ThreatshellIndex.doc_type
class DomainFeaturesDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_domain_features"

    age = Integer()
    ttls_min = Integer()
    ttls_max = Integer()
    ttls_mean = Float()
    ttls_median = Float()
    ttls_stddev = Float()
    country_codes = String()
    country_count = Integer()
    asns = Integer()
    asns_count = Integer()
    prefixes = String()
    prefix_count = Integer()
    rips = Integer()
    div_rips = Float()
    locations = GeoPoint()
    locations_count = Integer()
    geo_distance_sum = Float()
    geo_distance_mean = Float()
    non_routable = Boolean()
    mail_exchanger = Boolean()
    cname = Boolean()
    ff_candidate = Boolean()
    rips_stability = Float()
    base_domain = String()
    is_subdomain = Boolean()


@ThreatshellIndex.doc_type
class DomainResourceRecordHistoryDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_domain_resource_record_history"

    rrs_tf = Nested(
        doc_class=DomainResourceRecordDoc
    )
    features = Nested(
        doc_class=DomainFeaturesDoc
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class IPFeaturesDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_ip_features"

    rr_count = Integer()
    ld2_count = Integer()
    ld3_count = Integer()
    ld2_1_count = Integer()
    ld2_2_count = Integer()
    div_ld2 = Float()
    div_ld3 = Float()
    div_ld2_1 = Float()
    div_ld2_2 = Float()


@ThreatshellIndex.doc_type
class IPResourceRecordHistoryDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_ip_resource_record_history"

    rrs = Nested(
        doc_class=ResourceRecordDoc
    )
    features = Nested(
        doc_class=IPFeaturesDoc
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}

            setattr(self, k, v)


@ThreatshellIndex.doc_type
class ASInformationDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_asn_information"

    creation_date = Date()
    ir = String(analyzer=rir_analyzer)
    description = String()
    asn = Integer()
    cidr = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class ASPrefixInformationDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_asn_prefix_information"

    cidr = String()
    geo = Nested(
        properties={
            "country_name": String(),
            "country_code": Integer()
        }
    )

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class WhoisEmailToDomainDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_whois_email_to_domain"

    domain = String()
    email = String(analyzer=email_analyzer)
    current = Boolean()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class WhoisNameServerToDomainDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_whois_nameserver_to_domain"

    nameserver = String()
    domain = String()
    current = Boolean()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class WhoisDomainRecordDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_whois_record"

    addresses = String()
    administrativeContactCity = String()
    administrativeContactCountry = String()
    administrativeContactEmail = String(analyzer=email_analyzer)
    administrativeContactFax = String()
    administrativeContactFaxExt = String()
    administrativeContactName = String()
    administrativeContactOrganization = String()
    administrativeContactPostalCode = String()
    administrativeContactState = String()
    administrativeContactStreet = String()
    administrativeContactTelephone = String()
    administrativeContactTelephoneExt = String()
    auditUpdatedDate = Date()
    billingContactCity = String()
    billingContactCountry = String()
    billingContactEmail = String(analyzer=email_analyzer)
    billingContactFax = String()
    billingContactFaxExt = String()
    billingContactName = String()
    billingContactOrganization = String()
    billingContactPostalCode = String()
    billingContactState = String()
    billingContactStreet = String()
    billingContactTelephone = String()
    billingContactTelephoneExt = String()
    created = Date()
    domainName = String()
    emails = String(analyzer=email_analyzer)
    expires = Date()
    hasRawText = Boolean()
    nameServers = String()
    recordExpired = Boolean()
    registrantCity = String()
    registrantCountry = String()
    registrantEmail = String(analyzer=email_analyzer)
    registrantFax = String()
    registrantFaxExt = String()
    registrantName = String()
    registrantOrganization = String()
    registrantPostalCode = String()
    registrantState = String()
    registrantStreet = String()
    registrantTelephone = String()
    registrantTelephoneExt = String()
    registrarIANAID = Integer()
    registrarName = String()
    record_status = String()
    technicalContactCity = String()
    technicalContactCountry = String()
    technicalContactEmail = String(analyzer=email_analyzer)
    technicalContactFax = String()
    technicalContactFaxExt = String()
    technicalContactName = String()
    technicalContactOrganization = String()
    technicalContactPostalCode = String()
    technicalContactState = String()
    technicalContactStreet = String()
    technicalContactTelephone = String()
    technicalContactTelephoneExt = String()
    timeOfLatestRealtimeCheck = BetterDate(format="epoch_millis")
    timestamp = Date()
    updated = Date()
    whoisServers = String()
    zoneContactCity = String()
    zoneContactCountry = String()
    zoneContactEmail = String(analyzer=email_analyzer)
    zoneContactFax = String()
    zoneContactFaxExt = String()
    zoneContactName = String()
    zoneContactOrganization = String()
    zoneContactPostalCode = String()
    zoneContactState = String()
    zoneContactStreet = String()
    zoneContactTelephone = String()
    zoneContactTelephoneExt = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class LatestMaliciousDomsDoc(GenericDoc):

    class Meta:
        doc_type = "opendns_latest_malicious_domains"

    domain_id = Integer()
    name = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            setattr(self, k, v)

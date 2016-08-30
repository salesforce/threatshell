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

from threatshell.doctypes.generic import GenericDoc, ThreatshellIndex
from elasticsearch_dsl import (
    GeoPoint,
    String,
    Integer
)


@ThreatshellIndex.doc_type
class GeoCityDoc(GenericDoc):

    class Meta:
        doc_type = "maxmind_geo_city"

    city = String()
    region_name = String()
    region = String()
    area_code = Integer()
    time_zone = String()
    location = GeoPoint()
    metro_code = Integer()
    country_code = String()
    postal_code = Integer()
    dma_code = Integer()
    country_code3 = String()
    country_name = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class GeoASNDoc(GenericDoc):

    class Meta:
        doc_type = "maxmind_geo_asn"

    asnum = Integer()
    asname = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class GeoIpASNDoc(GeoASNDoc):

    class Meta:
        doc_type = "maxmind_geo_ip_asn"

    ip_allocation = String()

    def __init__(self, jdata={}):
        GeoASNDoc.__init__(self, jdata=jdata)


@ThreatshellIndex.doc_type
class GeoCountryCodeDoc(GenericDoc):

    class Meta:
        doc_type = "maxmind_geo_country_code"

    country_code = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class GeoCountryNameDoc(GenericDoc):

    class Meta:
        doc_type = "maxmind_geo_count_name"

    country_name = String()

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)

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
    Ip,
    Integer,
    Index,
    String
)


@ThreatshellIndex.doc_type
class ASOriginDoc(GenericDoc):

    class Meta:
        doc_type = "shadowserver_as_origin"

    domain = String()
    asnum = Integer()
    country = String()
    isp = String()
    prefix = String()
    asname = String()

    # def __setattr__(self, key, value):
    #     if key == "prefix":
    #         value = convert_cidr(value)
    #     super(ASOriginDoc, self).__setattr__(key, value)

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class ASPeersDoc(GenericDoc):

    class Meta:
        doc_type = "shadowserver_as_peers"

    peers = Integer()
    asnum = Integer()
    country = String()
    isp = String()
    domain = String()
    prefix = String()
    asname = String()

    # def __setattr__(self, key, value):
    #     if key == "prefix":
    #         value = convert_cidr(value)

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)


@ThreatshellIndex.doc_type
class ASPrefixDoc(GenericDoc):

    class Meta:
        doc_type = "shadowserver_asnum_prefix"

    prefixes = String()

    # def __setattr__(self, key, value):
    #
    #     if key == "prefixes":
    #
    #         if not isinstance(value, list):
    #             value = [value]
    #
    #         ips = []
    #         for cidr in value:
    #             ips.extend(convert_cidr(cidr))

    def __init__(self, jdata={}):
        GenericDoc.__init__(self)
        for k, v in jdata.items():
            if v is None:
                v = {}
            setattr(self, k, v)

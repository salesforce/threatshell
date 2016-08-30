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

from datetime import date, datetime
from dateutil import parser as date_parser
from elasticsearch_dsl import (
    analyzer,
    Boolean,
    Date,
    DocType,
    Index,
    Field,
    String,
    tokenizer,
    token_filter
)
from netaddr import IPNetwork
import json

# TODO: Add some analyzers to help coerce data into the correct types
# e.g. a location array where geo points are mixed between floats and longs

ThreatshellIndex = Index("threatshell")

email_filter = token_filter(
    "email_token_filter",
    type="pattern_capture",
    preserve_original=True,
    patterns=[
        "([^@]+)",
        "(\\p{L}+)",
        "(\\d+)",
        "@(.+)",
        "([^-@]+)"
    ]
)

email_analyzer = analyzer(
    "email_analyzer",
    tokenizer="uax_url_email",
    filter=[email_filter, "lowercase", "unique"],
    type="custom"
)

hostname_analyzer = analyzer(
    "hostname",
    tokenizer=tokenizer(
        "hostname_tokenizer",
        "pattern",
        pattern="([^.]+)",
        group=0
    ),
    filter=["lowercase"],
    type="custom"
)


def convert_cidr(cidr):
    network = IPNetwork(cidr)
    return [str(x) for x in list(network)]


class GenericDoc(DocType):

    session_uuid = String()
    timestamp = Date()
    successful = Boolean()
    term = String()

    class Meta:
        index = "threatshell"

    def save(self, **kwargs):
        self.timestamp = datetime.now()
        return super(GenericDoc, self).save(**kwargs)

    def to_json(self):

        def convert(x):
            return date_parser.parse(x)

        def default(x):

            try:
                dt = convert(x)
                return str(dt)
            except:
                pass

            if(
                hasattr(x, "_d_") and
                getattr(x, "_d_") is not None and
                getattr(x, "_d_") != {}
            ):
                return x._d_

            return str(x)

        return json.dumps(self, indent=4, default=default)

    def __eq__(self, other):

        self_json = self.to_json()
        other_json = other.to_json()

        return self_json == other_json


class BetterDate(Field):

    name = 'date'
    _coerce = True

    def _deserialize(self, data):

        if not data:
            return None

        if isinstance(data, date):
            return data

        try:
            return date_parser.parse(data)
        except:
            pass

        try:
            return datetime.fromtimestamp(data)
        except:
            # Might be an elasticsearch formatter for it so don't
            # error out just yet.
            return data

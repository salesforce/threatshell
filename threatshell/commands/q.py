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

import logging

log = logging.getLogger(__name__)


# TODO: Add an "all" option
class AutoQuery:

    query_table = {}
    sup_query_types = [
        "ip",
        "url",
        "domain",
        "asnum",
        "asname",
        "nameserver",
        "email",
        "hash",
        "address",
        "phone",
        "md5",
        "sha1"
    ]

    @classmethod
    def use_on(cls, query_types):
        if not isinstance(query_types, list):
            query_types = [query_types.lower()]
        else:
            query_types = [t.lower() for t in query_types]

        # log.debug("Query types requested: %s" % ", ".join(query_types))
        for t in cls.sup_query_types:
            if t not in cls.sup_query_types:
                log.warn("%s isn't a supported indicator type yet" % t)
                query_types.remove(t)

        def decorator(method):

            # log.debug(
            #     "Adding method %s to support query types of %s" % (
            #         method.__name__,
            #         ", ".join(query_types)
            #     )
            # )
            for ioc_type in query_types:
                if cls.query_table.get(ioc_type) is None:
                    cls.query_table[ioc_type] = [method]
                else:
                    cls.query_table[ioc_type].append(method)

            return method

        return decorator

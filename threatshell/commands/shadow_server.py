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
from threatshell.doctypes import shadow_server as ss_docs
from elasticsearch_dsl import String

import logging
import re
import socket

log = logging.getLogger(__name__)


class ShadowServer:

    def __init__(self):
        self.ss = "asn.shadowserver.org"
        self.port = 43
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip_expr = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    def _connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.ss, self.port))
        except Exception, e:
            log.error(
                "Failed to connect to '%s' - [%s]: %s" % (
                    self.ss,
                    str(e.__class__.__name__),
                    str(e.message)
                )
            )

    def _close(self):
        try:
            self.sock.close()
        except:
            pass

    def _send_to_sock(self, query):

        data = ""
        try:

            self._connect()
            self.sock.send(query)
            buff = self.sock.recv(4096)

            while buff != '':
                data += buff
                buff = self.sock.recv(4096)

        except Exception, e:
            log.error(
                "Error communicating on socket - [%s]: %s" % (
                    str(e.__class__.__name__),
                    str(e.message)
                )
            )
            print str(e)

        finally:
            self._close()

        return data

    def _get_ip(self, dom):
        try:
            return socket.gethostbyname(dom)
        except Exception, e:
            log.error(
                "Failed to get address of domain '%s' - [%s]: %s" % (
                    dom,
                    str(e.__class__.__name__),
                    str(e.message)
                )
            )
            return None

    def asn_origin(self, target):

        if not self.ip_expr.match(target):
            dom = target
            target = self._get_ip(target)
            if not target:
                record = (
                    "Failed to resolve IP address of %s - can't get " +
                    "ASN origin information"
                ) % dom
                log.error(record)
                doc = geo_docs.ASOriginDoc({})
                setattr(doc, "term", dom)
                setattr(doc, "successful", False)
                return doc

        data = self._send_to_sock("origin %s\r\n\r\n" % target)
        if not data:
            record = (
                "No data returned from Shadow Server for IP '%s' " +
                "for ASN origin information"
            ) % (target)
            log.error(record)
            doc = ss_docs.ASOriginDoc({})
            setattr(doc, "term", target)
            setattr(doc, "successful", False)
            return doc

        data = data.strip()

        parts = data.split("|")
        data_map = {
            'asnum': parts[0].strip(),
            'prefix': parts[1].strip(),
            'asname': parts[2].strip(),
            'country': parts[3].strip(),
            'domain': parts[4].strip(),
            'isp': parts[5].strip()
        }

        doc = ss_docs.ASOriginDoc(data_map)
        setattr(doc, "successful", True)
        setattr(doc, "term", target)
        return doc

    @AutoQuery.use_on(["ip", "domain"])
    def batch_asn_origin(self, targets):

        docs = []
        filtered_targets = []

        for i in xrange(0, len(targets)):

            if not self.ip_expr.match(targets[i]):

                dom = targets[i]
                targets[i] = self._get_ip(targets[i])

                if not targets[i]:
                    record = (
                        "Failed to resolve IP address of %s - can't get " +
                        "ASN origin information"
                    ) % dom
                    log.error(record)
                    doc = ss_docs.ASOriginDoc({})
                    setattr(doc, "term", dom)
                    setattr(doc, "successful", False)
                    docs.append(doc)

                else:
                    filtered_targets.append(targets[i])
            else:
                filtered_targets.append(targets[i])

        targets = filtered_targets

        header = "begin origin"
        footer = "end"

        targets.insert(0, header)
        targets.append(footer)
        targets = "\n".join(targets)

        data = self._send_to_sock("%s\r\n\r\n" % targets)
        if not data:
            record = (
                "No data returned from Shadow Server for batch lookup " +
                "of ASN information"
            )
            log.error(record)
            doc = ss_docs.ASOriginDoc({})
            setattr(doc, "term", "batch_origin")
            setattr(doc, "successful", False)
            return doc

        data = data.split("\n")
        data.pop()
        for line in data:
            line = line.strip()
            parts = line.split("|")
            data_map = {
                'asnum': parts[1].strip(),
                'prefix': parts[2].strip(),
                'asname': parts[3].strip(),
                'country': parts[4].strip(),
                'domain': parts[5].strip(),
                'isp': parts[6].strip()
            }
            doc = ss_docs.ASOriginDoc(data_map)
            setattr(doc, "term", parts[0])
            setattr(doc, "successful", True)
            docs.append(doc)

        return docs

    def asn_peers(self, target):

        if not self.ip_expr.match(target):
            dom = target
            target = self._get_ip(target)
            if not target:
                record = (
                    "Failed to resolve IP address of %s - can't get " +
                    "ASN peer information"
                ) % dom
                log.error(record)
                doc = ss_docs.ASPeersDoc({})
                setattr(doc, "term", dom)
                setattr(doc, "successful", False)
                return doc

        data = self._send_to_sock("peer %s\r\n\r\n" % target)
        if not data:
            record = (
                "No data returned from Shadow Server for peer lookup " +
                "of ASN information on target '%s'"
            ) % target
            log.error(record)
            doc = ss_docs.ASPeersDoc({})
            setattr(doc, "term", target)
            setattr(doc, "successful", False)
            return doc

        parts = data.split("|")
        peers = parts[0]
        peers = peers.split(" ")
        peers.pop()
        for i in xrange(0, len(peers)):
            peers[i] = peers[i].strip()

        data = data.strip()
        parts = data.split("|")
        parts.pop(0)

        data_map = {
            'peers': peers,
            'asnum': parts[0].strip(),
            'prefix': parts[1].strip(),
            'asname': parts[2].strip(),
            'country': parts[3].strip(),
            'domain': parts[4].strip(),
            'isp': parts[5].strip()
        }

        doc = ss_docs.ASPeersDoc(data_map)
        setattr(doc, "term", target)
        setattr(doc, "successful", True)
        return doc

    @AutoQuery.use_on(["ip", "domain"])
    def batch_asn_peers(self, targets):

        docs = []
        filtered_targets = []

        for i in xrange(0, len(targets)):

            if not self.ip_expr.match(targets[i]):

                dom = targets[i]
                targets[i] = self._get_ip(targets[i])

                if not targets[i]:
                    record = (
                        "Failed to resolve IP address of %s - can't get " +
                        "ASN peer information"
                    ) % dom
                    log.error(record)
                    doc = ss_docs.ASPeersDoc({})
                    setattr(doc, "term", dom)
                    setattr(doc, "successful", False)
                    docs.append(doc)
                else:
                    filtered_targets.append(targets[i])
            else:
                filtered_targets.append(targets[i])

        targets = filtered_targets

        header = "begin peer"
        footer = "end"

        targets.insert(0, header)
        targets.append(footer)
        targets = "\n".join(targets)

        data = self._send_to_sock("%s\r\n\r\n" % targets)
        if not data:
            record = (
                "No data returned from Shadow Server for batch lookup " +
                "of ASN information"
            )
            log.error(record)
            doc = ss_docs.ASPeersDoc({})
            setattr(doc, "term", "batch_peer")
            setattr(doc, "successful", False)
            return doc

        data = data.split("\n")
        data.pop()

        for line in data:

            parts = line.split("|")
            peers = parts[1].split(" ")
            peers.pop()
            peers.pop(0)
            for i in xrange(0, len(peers)):
                peers[i] = peers[i].strip()

            line = line.strip()
            line = line.split("|")
            line.pop(1)

            data_map = {
                'peers': peers,
                'asnum': line[1].strip(),
                'prefix': line[2].strip(),
                'asname': line[3].strip(),
                'country': line[4].strip(),
                'domain': line[5].strip(),
                'isp': line[6].strip()
            }
            doc = ss_docs.ASPeersDoc(data_map)
            setattr(doc, "term", line[0])
            setattr(doc, "successful", True)
            docs.append(doc)

        return docs

    @AutoQuery.use_on(["asnum"])
    def asnum_to_prefix(self, target):
        data = self._send_to_sock("prefix %s\r\n\r\n" % target)
        if not data:
            record = (
                "No data returned from Shadow Server for AS prefix lookup " +
                "on target '%s'"
            ) % target
            log.error(record)
            doc = ss_docs.ASPrefixDoc({})
            setattr(doc, "term", target)
            setattr(doc, "successful", True)
            return doc

        data = data.split("\n")
        data.pop()
        for i in xrange(0, len(data)):
            data[i] = data[i].strip()

        doc = ss_docs.ASPrefixDoc(
            {
                "prefixes": data
            }
        )
        setattr(doc, "term", target)
        setattr(doc, "successful", True)
        return doc

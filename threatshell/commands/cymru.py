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
from threatshell.doctypes import cymru as cymru_docs
from elasticsearch_dsl import String

import logging
import re
import socket

log = logging.getLogger(__name__)


class Cymru:

    def __init__(self):
        self.cymru = "whois.cymru.com"
        self.port = 43
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip_expr = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    def _connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.cymru, self.port))
        except Exception, e:
            log.error(
                "Failed to connect to '%s' - [%s]: %s" % (
                    self.cymru,
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

    def asn_info(self, target):

        data_map = {
            'asnum': None,
            "ip": None,
            'prefix': None,
            'country': None,
            'registry': None,
            'allocation_date': None,
            'asname': None
        }

        if not self.ip_expr.match(target):
            dom = target
            target = self._get_ip(target)
            if not target:
                record = (
                    "Failed to resolve IP address of %s - can't get " +
                    "ASN origin information"
                ) % dom
                log.error(record)
                doc = cymru_docs.CymruASInfoDoc(data_map)
                setattr(doc, "successful", False)
                setattr(doc, "term", target)
                return doc

        data = self._send_to_sock("-v -f %s\r\n\r\n" % target)
        if not data:
            record = (
                "No data returned from Cymru for IP '%s' " +
                "for ASN information"
            ) % (target)
            log.error(record)
            doc = cymru_docs.CymruASInfoDoc(data_map)
            setattr(doc, "successful", False)
            setattr(doc, "term", target)
            return doc

        data = data.strip()

        parts = data.split("|")
        data_map = {
            'asnum': parts[0].strip(),
            "ip": parts[1].strip(),
            'prefix': parts[2].strip(),
            'country': parts[3].strip(),
            'registry': parts[4].strip(),
            'allocation_date': parts[5].strip(),
            'asname': parts[6].strip()
        }

        doc = cymru_docs.CymruASInfoDoc(data_map)
        setattr(doc, "successful", True)
        setattr(doc, "term", target)

        return doc

    @AutoQuery.use_on(["ip"])
    def batch_asn_info(self, targets):

        data_map = {
            'asnum': None,
            "ip": None,
            'prefix': None,
            'country': None,
            'registry': None,
            'allocation_date': None,
            'asname': None
        }

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
                    doc = cymru_docs.CymruASInfoDoc(data_map)
                    setattr(doc, "successful", False)
                    setattr(doc, "term", targets[i])
                    docs.append(doc)

                else:
                    filtered_targets.append(targets[i])
            else:
                filtered_targets.append(targets[i])

        targets = filtered_targets

        header = "begin"
        options = "verbose"
        footer = "end"

        targets.insert(0, header)
        targets.insert(1, options)
        targets.append(footer)
        targets = "\n".join(targets)

        data = self._send_to_sock("%s\r\n\r\n" % targets)
        if not data:
            record = (
                "No data returned from Cymru for batch lookup " +
                "of ASN information"
            )
            log.error(record)
            doc = cymru_docs.CymruASInfoDoc(data_map)
            setattr(doc, "successful", False)
            setattr(doc, "term", "batch_asn_info")
            return doc

        data = data.split("\n")
        data.pop(0)
        data.pop()
        for line in data:
            line = line.strip()
            parts = line.split("|")
            data_map = {
                'asnum': parts[0].strip(),
                'ip': parts[1].strip(),
                'prefix': parts[2].strip(),
                'country': parts[3].strip(),
                'registry': parts[4].strip(),
                'allocation_date': parts[5].strip(),
                'asname': parts[6].strip()
            }
            doc = cymru_docs.CymruASInfoDoc(data_map)
            setattr(doc, "successful", True)
            setattr(doc, "term", parts[1].strip())
            docs.append(doc)

        return docs

    def asnum_to_name(self, target):

        data_map = {
            'asnum': None,
            'country': None,
            'registry': None,
            'allocation_date': None,
            'asname': None
        }

        data = self._send_to_sock("-v -f AS%s\r\n\r\n" % target)
        if not data:
            record = (
                "No data returned from Cymru for AS name lookup " +
                "on target '%s'"
            ) % target
            log.error(record)
            doc = cymru_docs.CymruASNumInfoDoc(data_map)
            setattr(doc, "successful", False)
            setattr(doc, "term", target)
            return doc

        data = data.strip()
        parts = data.split("|")
        data_map = {
            'asnum': parts[0].strip(),
            'country': parts[1].strip(),
            'registry': parts[2].strip(),
            'allocation_date': parts[3].strip(),
            'asname': parts[4].strip()
        }

        doc = cymru_docs.CymruASNumInfoDoc(data_map)
        setattr(doc, "successful", True)
        setattr(doc, "term", target)
        return doc

    @AutoQuery.use_on(["asnum"])
    def batch_asnum_to_name(self, targets):

        data_map = {
            'asnum': None,
            'country': None,
            'registry': None,
            'allocation_date': None,
            'asname': None
        }

        for i in xrange(0, len(targets)):
            targets[i] = "AS%s" % targets[i]

        header = "begin"
        options = "verbose"
        footer = "end"

        targets.insert(0, header)
        targets.insert(1, options)
        targets.append(footer)
        targets = "\n".join(targets)

        data = self._send_to_sock("%s\r\n\r\n" % targets)
        if not data:
            record = (
                "No data returned from Cymru for batch AS name lookup"
            )
            log.error(record)
            doc = cymru_docs.CymruASNumInfoDoc(data_map)
            setattr(doc, "successful", False)
            setattr(doc, "term", "batch_asname")
            return doc

        data = data.strip()
        lines = data.split("\n")
        lines.pop(0)

        docs = []
        for line in lines:
            parts = line.split("|")
            data_map = {
                'asnum': parts[0].strip(),
                'country': parts[1].strip(),
                'registry': parts[2].strip(),
                'allocation_date': parts[3].strip(),
                'asname': parts[4].strip()
            }
            doc = cymru_docs.CymruASNumInfoDoc(data_map)
            setattr(doc, "successful", True)
            setattr(doc, "term", parts[0].strip())
            docs.append(doc)

        return docs

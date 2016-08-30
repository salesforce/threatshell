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

from datetime import datetime, timedelta
from dateutil import parser as date_parser
from elasticsearch_dsl import connections
import copy
import json
import logging
import sys
import traceback
import unittest

try:

    from threatshell.common.log import init_console_logger
    from threatshell.common.config import Config

    config = Config()

    init_console_logger(log_level=logging.DEBUG)
    log = logging.getLogger(__name__)
    # logging.getLogger().setLevel(logging.DEBUG)

    es_tracer = logging.getLogger('elasticsearch.trace')
    es_tracer.propagate = True

    es_connections = [
        x.strip() for x in config.get("ElasticSearch", "servers").split(",")
    ]

    connections.connections.create_connection(
        hosts=es_connections
    )

except Exception, e:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(
        exc_type,
        exc_value,
        exc_traceback
    )
    lines = "\n\t".join([x.strip() for x in lines])
    log.error(
        "Caught ImportError - [%s]: %s\n\n\t%s" % (
            e.__class__.__name__,
            str(e),
            lines
        )
    )
    raise e

try:
    from threatshell.doctypes.generic import ThreatshellIndex
    from threatshell.doctypes import passivetotal as pt_docs
    from threatshell.doctypes import cymru as cymru_docs
    from threatshell.doctypes import geoip as geo_docs
    from threatshell.doctypes import shadow_server as ss_docs
    from threatshell.doctypes import opendns as opendns_docs
except ImportError, e:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(
        exc_type,
        exc_value,
        exc_traceback
    )
    lines = "\n\t".join([x.strip() for x in lines])
    log.error(
        "Caught ImportError - [%s]: %s\n\n\t%s" % (
            e.__class__.__name__,
            str(e),
            lines
        )
    )
    raise e


def setUpModule():
    try:
        log.info("Setting up threatshell index")
        ThreatshellIndex.create()
    except Exception, e:
        log.warn("[%s]: %s" % (e.__class__.__name__, str(e)))


class ESDocTest(unittest.TestCase):

    def _compare_datetimes(self, t1, t2):

        if not isinstance(t1, datetime):
            t1 = self._convert(t1)

        if not isinstance(t2, datetime):
            t2 = self._convert(t2)

        delta = timedelta()
        assert (t1 - delta) == (t2 - delta), "%s != %s" % (str(t1), str(t2))

    def _convert(self, t):
        return date_parser.parse(t)

    def _default(self, x):
        if(
            hasattr(x, "_d_") and
            getattr(x, "_d_") is not None and
            getattr(x, "_d_") != {}
        ):
            return x._d_

        return str(x)

    def _serialize(self, test_obj, entry):

        try:

            test = json.dumps(test_obj, default=self._default)
            assert test is not None, "Failed to serialize %s" % (
                type(test_obj).__name__
            )

            test = json.loads(test)
            assert isinstance(test, dict), "Failed to deserialize"

            for key in entry.keys():

                if key == "results":
                    continue

                log.debug(
                    "Testing %s key '%s'" % (
                        type(test_obj).__name__,
                        str(key)
                    )
                )

                if isinstance(entry.get(key), list):

                    s1 = entry.get(key)
                    s2 = test.get(key)

                    assert s1 == s2, "lists do not match: [%s] != [%s]" % (
                        str(s1),
                        str(s2)
                    )

                elif(
                    isinstance(entry.get(key), datetime) or
                    isinstance(test.get(key), datetime)
                ):
                    self._compare_datetimes(test.get(key), entry.get(key))

                elif test.get(key) == "{}" or test.get(key) == {}:
                    assert(
                        entry.get(key) is None or
                        entry.get(key) == u"{}"
                    )

                else:

                    t1 = test.get(key)
                    t2 = entry.get(key)

                    try:
                        t1 = self._convert(t1)
                    except:
                        pass

                    try:
                        t2 = self._convert(t2)
                    except:
                        pass

                    try:
                        self._compare_datetimes(t1, t2)
                        continue
                    except:
                        pass

                    assert(
                        test.get(key) == entry.get(key)
                    ), "test[%s]<%s>(%s) != entry[%s]<%s>(%s)" % (
                        key,
                        type(test.get(key)).__name__,
                        str(test.get(key)),
                        key,
                        type(entry.get(key)).__name__,
                        str(entry.get(key))
                    )

        except Exception, e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(
                exc_type,
                exc_value,
                exc_traceback
            )
            lines = "\n\t".join([x.strip() for x in lines])
            log.error(
                "[%s]: %s\n\n\t%s" % (
                    e.__class__.__name__,
                    str(e),
                    lines
                )
            )
            log.debug(test_obj.__dict__)
            assert False, "[%s]: %s" % (e.__class__.__name__, str(e))

    def _serialize_response(self, response_obj, test_data, root_name):

        try:

            serialize_test = json.dumps(response_obj, default=self._default)

            assert serialize_test, "Failed to serialize"

            serialize_test = json.loads(serialize_test)

            results_root = serialize_test.get(root_name)
            assert results_root is not None, "Failed to deserialize"

            for i, test_data_entry in enumerate(test_data[root_name]):
                log.debug(
                    "Testing %s entry number %d" % (
                        type(response_obj).__name__,
                        i
                    )
                )

                test = results_root[i]
                if(
                    hasattr(test, "_d_") and
                    getattr(test, "_d_") is not None
                ):
                    test = test._d_

                for key in test_data_entry.keys():

                    log.debug(
                        "Testing %s key '%s'" % (
                            type(response_obj).__name__,
                            str(key)
                        )
                    )

                    if(
                        isinstance(test.get(key), datetime) or
                        isinstance(test_data_entry.get(key), datetime)
                    ):
                        self._compare_datetimes(
                            test_data_entry.get(key),
                            test.get(key)
                        )

                    elif test_data_entry.get(key) == {}:

                        assert (
                            test.get(key) == u"{}" or
                            test.get(key) is None
                        ), "test[%s]<%s>(%s) != entry[%s]<%s>(%s)" % (
                            key,
                            type(test.get(key)).__name__,
                            str(test.get(key)),
                            key,
                            type(test_data_entry.get(key)).__name__,
                            str(test_data_entry.get(key))
                        )

                    else:

                        t1 = test.get(key)
                        t2 = test_data_entry.get(key)

                        try:
                            t1 = self._convert(t1)
                        except:
                            pass

                        try:
                            t2 = self._convert(t2)
                        except:
                            pass

                        try:
                            self._compare_datetimes(t1, t2)
                            continue
                        except:
                            pass

                        assert(
                            test.get(key) == test_data_entry.get(key)
                        ), "test[%s]<%s>(%s) != entry[%s]<%s>(%s)" % (
                            key,
                            type(test.get(key)).__name__,
                            str(test.get(key)),
                            key,
                            type(test_data_entry.get(key)).__name__,
                            str(test_data_entry.get(key))
                        )

        except Exception, e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(
                exc_type,
                exc_value,
                exc_traceback
            )
            lines = "\n\t".join([x.strip() for x in lines])
            log.error(
                "[%s]: %s\n\n\t%s" % (
                    e.__class__.__name__,
                    str(e),
                    lines
                )
            )
            assert False, "[%s]: %s" % (type(e).__name__, str(e))

    def _save_doc(self, doc):
        try:
            doc.save()
        except Exception, e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            lines = traceback.format_exception(
                exc_type,
                exc_value,
                exc_traceback
            )
            lines = "\n\t".join([x.strip() for x in lines])
            log.error(
                "[%s]: %s\n\n\t%s" % (
                    e.__class__.__name__,
                    str(e),
                    lines
                )
            )
            assert False, "[%s]: %s" % (e.__class__.__name__, str(e))

    # @classmethod
    # def tearDownClass(self):
    #     global es_connections
    #     for connection in es_connections:
    #         connection = "%s/threatshell" % connection
    #         log.debug("Cleaning index %s" % connection)
    #         requests.delete(connection)


class TestPassiveTotalDocs(ESDocTest):

    def test_account_entry_serialization(self):

        entry = {
            'username': 'jdoe@passivetotal.org',
            'firstName': 'John',
            'lastName': 'Doe',
            'lastActive': '2016-01-12 12:05:21',
            'firstActive': '2015-10-28 14:43:06',
            'organization': 'PassiveTotal'
        }

        account_entry = pt_docs.AccountEntry(entry)
        self._serialize(account_entry, entry)

    def test_account_history_serialization(self):

        entry = {
            'history': [
                {
                    'username': 'jdoe@passivetotal.org',
                    'additional': {
                        "note": "test1"
                    },
                    'focus': '37.139.30.161',
                    'source': 'web',
                    'context': 220,
                    'dt': '2016-01-12 11:45:34',
                    'type': 'search'
                },
                {
                    'username': 'jdoe@passivetotal.org',
                    'additional': {
                        "note": "test2"
                    },
                    'focus': '37.139.30.161',
                    'source': 'web',
                    'context': 221,
                    'dt': '2016-01-12 12:30:15',
                    'type': 'search'
                },

            ]
        }

        history = pt_docs.AccountHistoryResponse(entry)
        self._serialize_response(history, entry, "history")

        # TODO: add es save test

    def test_account_notification_serialization(self):

        entry = {
            'notifications': [
                {
                    'username': 'jdoe@passivetotal.org',
                    'headline': (
                        'Your monitor matched www.passivetotal.org'
                    ),
                    'generated': '2015-05-29 22:23:54',
                    'content': (
                        "www.passivetotal.org was matched on the " +
                        "'domain' field using the passivetotal " +
                        "pattern you created on 2015-05-29 22:23:49."
                    ),
                    'type': 'alert'
                },
            ]
        }

        notify_history = pt_docs.AccountNotificationResponse(entry)
        self._serialize_response(notify_history, entry, "notifications")

        # TODO: test es save

    def test_account_organization_serialization(self):

        entry = {
            'activeMembers': ['jdoe@passivetotal.org'],
            'status': 'enterprise',
            'name': 'PassiveTotal',
            'lastActive': '2016-01-12 11:45:34',
            'acceptableDomains': ['passivetotal.org'],
            'searchQuota': '500',
            'registered': '2015-01-23 13:14:38',
            'watchQuota': '40',
            'active': True,
            'admins': ['admin@passivetotal.org'],
            'inactiveMembers': ['notauser@passivetotal.org'],
            'seats': 9,
            'id': 'passivetotal'
        }

        ao = pt_docs.AccountOrganizationEntry(entry)
        self._serialize(ao, entry)

        # TODO: add es save

    def test_account_teamstream_serialization(self):

        entry = {
            'teamstream': [
                {
                    'username': 'jdoe@passivetotal.org',
                    'additional': {
                        "note": "teamstream_test1"
                    },
                    'focus': 'passivetotal.org',
                    'source': 'api',
                    'context': 'non_malicious',
                    'dt': '2016-01-13 11:18:39',
                    'type': 'classify'
                },
                {
                    'username': 'notauser@passivetotal.org',
                    'additional': {
                        "note": "teamstream_test2"
                    },
                    'focus': 'www.riskiq.net',
                    'source': 'web',
                    'context': 100,
                    'dt': '2015-11-23 15:16:51',
                    'type': 'search'
                }
            ]
        }

        teamstream = pt_docs.AccountTeamStreamResponse(entry)
        self._serialize_response(teamstream, entry, "teamstream")

    def test_account_source(self):

        entry = {
            'sources': [
                {
                    'active': False,
                    'source': '360cn',
                    'configuration': {
                        'tokenSecret': '',
                        'tokenKey': '',
                        'settings': {}
                    }
                }
            ]
        }

        account_sources = pt_docs.AccountSourceResponse(entry)
        self._serialize_response(account_sources, entry, "sources")

    def test_passive_dns_entry_serialization(self):

        entry = {
            'recordHash': (
                '6d24bc7754af023afeaaa05ac689ac36e96656aa' +
                '6519ba435b301b14916b27d3'
            ),
            'resolve': '54.153.123.93',
            'value': 'passivetotal.org',
            'source': ['opendns'],
            'lastSeen': '2016-01-10 18:00:01',
            'collected': '2016-01-19 10:04:22',
            'firstSeen': '2016-01-05 00:00:02'
        }

        # pt_docs.PassiveDNSEntry.init()
        pdns_entry = pt_docs.PassiveDNSEntry()
        for k, v in entry.items():
            setattr(pdns_entry, k, v)

        self._serialize(pdns_entry, entry)
        self._save_doc(pdns_entry)

    def test_passive_dns_response_serialization(self):

        entry = {
            'results': [
                {
                    'recordHash': (
                        '6d24bc7754af023afeaaa05ac689ac36e96656aa' +
                        '6519ba435b301b14916b27d3'
                    ),
                    'resolve': '54.153.123.93',
                    'value': 'passivetotal.org',
                    'source': ['opendns'],
                    'lastSeen': '2016-01-10 18:00:01',
                    'collected': '2016-01-19 10:04:22',
                    'firstSeen': '2016-01-05 00:00:02'
                },
                {
                    'recordHash': (
                        '3b2128b35c22e3bc8b14f9ba4d29bd1f085dad66' +
                        '488f01a9b2d69b051b917fbc'
                    ),
                    'resolve': '52.8.228.23',
                    'value': 'passivetotal.org',
                    'source': ['riskiq'],
                    'lastSeen': '2016-01-10 18:00:01',
                    'collected': '2016-01-19 10:04:22',
                    'firstSeen': '2016-01-05 00:00:02'
                }
            ],
            'queryValue': 'passivetotal.org',
            'queryType': 'domain',
            'firstSeen': '2014-04-16 02:12:09',
            'totalRecords': 9,
            'pager': None,
            'lastSeen': '2016-01-10 18:00:01'
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.PassiveDNSResponse.init()
        pdns_response = pt_docs.PassiveDNSResponse(entry_copy)
        self._serialize_response(pdns_response, entry, "results")

        entry_copy = copy.deepcopy(entry)
        pdns_response = pt_docs.PassiveDNSResponse(entry_copy)
        self._serialize(pdns_response, entry)
        self._save_doc(pdns_response)

    def test_enrichment_serialization(self):

        entry = {
            'tags': ['security'],
            'queryValue': 'passivetotal.org',
            'everCompromised': False,
            'queryType': 'domain'
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.Enrichment.init()
        enrichment_doc = pt_docs.Enrichment(entry_copy)
        self._serialize(enrichment_doc, entry)
        self._save_doc(enrichment_doc)

    def test_ip_enrichment_serialization(self):

        entry = {
            'network': '52.8.0.0/16',
            'autonomousSystemName': 'AMAZON-02 - Amazon.com',
            'tags': ['amazoncom'],
            'country': 'US',
            'value': '52.8.228.23',
            'sinkhole': False,
            'location': {
                'lat': 39.56450000000001,
                'lon': -75.597,
            },
            'everCompromised': False,
            'queryType': 'ip',
            'autonomousSystemNumber': '16509'
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.IPEnrichment.init()
        ip_enrichment = pt_docs.IPEnrichment(entry_copy)
        self._serialize(ip_enrichment, entry)
        self._save_doc(ip_enrichment)

    def test_domain_enrichment_serialization(self):

        entry = {
            'primaryDomain': 'passivetotal.org',
            'tags': ['security'],
            'dynamicDns': False,
            'queryValue': 'passivetotal.org',
            'subdomains': [],
            'tld': '.org',
            'everCompromised': False,
            'queryType': 'domain'
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.DomainEnrichment.init()
        domain_enrichment = pt_docs.DomainEnrichment(entry_copy)
        self._serialize(domain_enrichment, entry)
        self._save_doc(domain_enrichment)

    def test_malware_enrichment_response_serialization(self):

        entry = {
            'results': [
                {
                    'source': 'Threatexpert',
                    'sourceUrl': (
                        'http://www.threatexpert.com/reports.aspx?' +
                        'find=noorno.com'
                    ),
                    'sample': '7ebf1e2d0c89b1c8124275688c9e8e98',
                    'collectionDate': '2015-02-21 04:05:17'
                }
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.MalwareEnrichmentResponse.init()
        response = pt_docs.MalwareEnrichmentResponse(entry_copy)
        self._serialize_response(response, entry, "results")
        self._save_doc(response)

    def test_osint_enrichment_response_serialization(self):

        entry = {
            'results': [
                {
                    'source': 'RiskIQ',
                    'sourceUrl': (
                        'https://www.riskiq.com/blog/riskiq-labs' +
                        '/post/a-brief-encounter-with-slempo'
                    ),
                    'inReport': [
                        'man5hats.ru',
                        'rghost.ru',
                        'xxxvideotube.org',
                        'adobe-flash-player-11.com'
                    ],
                    'tags': [
                        'slempo',
                        'riskiq',
                        'mobile',
                        'crimeware',
                        'android'
                    ]
                }
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.OSIntEnrichmentResponse.init()
        osint_enrichment = pt_docs.OSIntEnrichmentResponse(entry_copy)
        self._serialize_response(osint_enrichment, entry, "results")
        self._save_doc(osint_enrichment)

    def test_subdomain_enrichment_serialization(self):

        entry = {
            'queryValue': '*.passivetotal.org',
            'subdomains': [
                'www',
                'nutmeg-beta',
                'app',
                'api',
                'certs',
                'n1',
                'n5',
                'n6'
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.SubdomainEnrichment.init()
        subdom_enrichment = pt_docs.SubdomainEnrichment(entry_copy)
        self._serialize(subdom_enrichment, entry)
        self._save_doc(subdom_enrichment)

    def test_whois_response_serialization(self):

        entry = {
            'results': [
                {
                    'contactEmail': (
                        'proxy4655031@1and1-private-registration.com'
                    ),
                    'domain': 'passivetotal.org',
                    'billing': {},
                    'zone': {},
                    'nameServers': [
                        'NS1.DIGITALOCEAN.COM',
                        'NS2.DIGITALOCEAN.COM',
                        'NS3.DIGITALOCEAN.COM'
                    ],
                    'registered': '2014-04-14',
                    'lastLoadedAt': '2015-12-08',
                    'whoisServer': 'whois.publicinterestregistry.net',
                    'registryUpdatedAt': '2015-04-14',
                    'admin': {
                        'city': 'Chesterbrook',
                        'name': 'Oneandone Private Registration',
                        'country': 'UNITED STATES',
                        'telephone': '18772064254',
                        'state': 'PA',
                        'street': (
                            '701 Lee Road Suite 300|ATTN  passivetotal.org'
                        ),
                        'postalCode': '19087',
                        'organization': '1&1 Internet Inc. - www.1and1.com',
                        'email': 'proxy4655031@1and1-private-registration.com'
                    },
                    'expiresAt': '2016-04-14',
                    'registrar': '1 & 1 Internet AG (R73-LROR)',
                    'tech': {
                        'city': 'Chesterbrook',
                        'name': 'Oneandone Private Registration',
                        'country': 'UNITED STATES',
                        'telephone': '18772064254',
                        'state': 'PA',
                        'street': (
                            '701 Lee Road Suite 300|ATTN  passivetotal.org'
                        ),
                        'postalCode': '19087',
                        'organization': '1&1 Internet Inc. - www.1and1.com',
                        'email': 'proxy4655031@1and1-private-registration.com'
                    },
                    'registrant': {
                        'city': 'Chesterbrook',
                        'name': 'Oneandone Private Registration',
                        'country': 'UNITED STATES',
                        'telephone': '18772064254',
                        'state': 'PA',
                        'street': (
                            '701 Lee Road Suite 300|ATTN  passivetotal.org'
                        ),
                        'postalCode': '19087',
                        'organization': '1&1 Internet Inc. - www.1and1.com',
                        'email': 'proxy4655031@1and1-private-registration.com'
                    }
                }
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.WhoisSearchResponse.init()
        whois_response = pt_docs.WhoisSearchResponse(entry_copy)
        self._serialize_response(whois_response, entry, "results")
        self._save_doc(whois_response)

    def test_host_attributes_response_serialization(self):

        entry = {

            'results': [
                {
                    'category': 'JavaScript Library',
                    'hostname': 'passivetotal.org',
                    'lastSeen': '2016-01-07 21:52:30',
                    'firstSeen': '2015-12-26 11:17:43',
                    'label': 'jQuery'
                },
                {
                    'category': 'Operating System',
                    'hostname': 'passivetotal.org',
                    'lastSeen': '2016-01-07 21:52:42',
                    'firstSeen': '2015-12-26 11:17:43',
                    'label': 'Ubuntu'
                },
                {
                    'category': 'Search',
                    'hostname': 'passivetotal.org',
                    'lastSeen': '2016-01-07 21:52:30',
                    'firstSeen': '2015-12-26 11:17:43',
                    'label': 'Google Search'
                },
                {
                    'category': 'Server',
                    'hostname': 'passivetotal.org',
                    'lastSeen': '2016-01-07 21:52:42',
                    'firstSeen': '2015-12-26 11:17:43',
                    'label': 'Apache'
                },
                {
                    'category': 'Tracking Pixel',
                    'hostname': 'passivetotal.org',
                    'lastSeen': '2016-01-04 15:06:11',
                    'firstSeen': '2015-12-26 11:17:43',
                    'label': '455-NHF-420.mktoresp.com'
                }
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.HostAttributesResponse.init()
        host_attrs_response = pt_docs.HostAttributesResponse(entry_copy)
        self._serialize_response(host_attrs_response, entry, "results")
        self._save_doc(host_attrs_response)

    def test_host_tracker_response_serialization(self):

        entry = {

            'results': [
                {
                    'lastSeen': '2016-01-26 13:47:45',
                    'hostname': 'passivetotal.org',
                    'attributeType': 'GoogleAnalyticsAccountNumber',
                    'firstSeen': '2015-10-09 17:05:38',
                    'attributeValue': 'UA-61048133'
                },
                {
                    'lastSeen': '2016-01-26 13:47:45',
                    'hostname': 'passivetotal.org',
                    'attributeType': 'GoogleAnalyticsTrackingId',
                    'firstSeen': '2015-10-09 17:05:38',
                    'attributeValue': 'UA-61048133-2'
                },
                {
                    'lastSeen': '2016-01-17 20:31:29',
                    'hostname': 'www.passivetotal.org',
                    'attributeType': 'GoogleAnalyticsAccountNumber',
                    'firstSeen': '2015-10-08 16:51:37',
                    'attributeValue': 'UA-61048133'
                },
                {
                    'lastSeen': '2016-01-17 20:31:29',
                    'hostname': 'www.passivetotal.org',
                    'attributeType': 'GoogleAnalyticsTrackingId',
                    'firstSeen': '2015-10-08 16:51:37',
                    'attributeValue': 'UA-61048133-2'
                },
                {
                    'lastSeen': '2016-01-26 13:48:03',
                    'hostname': 'blog.passivetotal.org',
                    'attributeType': 'GoogleAnalyticsAccountNumber',
                    'firstSeen': '2015-10-08 05:24:46',
                    'attributeValue': 'UA-61048133'
                },
                {
                    'lastSeen': '2016-01-26 13:48:03',
                    'hostname': 'blog.passivetotal.org',
                    'attributeType': 'GoogleAnalyticsTrackingId',
                    'firstSeen': '2015-10-08 05:24:46',
                    'attributeValue': 'UA-61048133-4'
                }
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.HostTrackerResponse.init()
        host_track_response = pt_docs.HostTrackerResponse(entry_copy)
        self._serialize_response(host_track_response, entry, "results")
        self._save_doc(host_track_response)

    def test_host_tracker_search_response_serialization(self):

        entry = {
            'results': [
                {
                    'everBlacklisted': False,
                    'alexaRank': 38,
                    'hostname': 'demo.paypal.com'
                },
                {
                    'everBlacklisted': False,
                    'alexaRank': 38,
                    'hostname': 'merchantweb.paypal.com'
                }
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.HostTrackerSearchResponse.init()
        host_track_search_response = pt_docs.HostTrackerSearchResponse(
            entry_copy
        )
        self._serialize_response(host_track_search_response, entry, "results")
        self._save_doc(host_track_search_response)

    def test_ssl_cert_history_response_serialization(self):

        entry = {
            'results': [
                {
                    'sha1': 'e9a6647d6aba52dc47b3838c920c9ee59bad7034',
                    'lastSeen': '2016-01-18',
                    'firstSeen': '2015-12-21',
                    'ipAddresses': ['52.8.228.23']
                },
                {
                    'sha1': '3d7dbaf257520e7d06c092948b7a7ba99199dcdf',
                    'lastSeen': '2015-11-09',
                    'firstSeen': '2015-11-09',
                    'ipAddresses': ['52.8.228.23']
                },
                {
                    'sha1': '96e64014dd4d542b33da8698094fce09098f7c97',
                    'lastSeen': '2015-10-12',
                    'firstSeen': '2015-08-31',
                    'ipAddresses': ['52.8.228.23']
                }
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.SSLCertHistoryResponse.init()
        ssl_cert_hist_response = pt_docs.SSLCertHistoryResponse(entry_copy)
        self._serialize_response(ssl_cert_hist_response, entry, "results")
        self._save_doc(ssl_cert_hist_response)

    def test_ssl_cert_entry_serialization(self):

        entry = {
            'issuerStreetAddress': None,
            'subjectSerialNumber': None,
            'subjectEmailAddress': None,
            'expirationDate': 'Apr 27 23:59:59 2017 GMT',
            'issuerSerialNumber': None,
            'issuerOrganizationName': 'thawte, inc.',
            'subjectCommonName': 'www.passivetotal.org',
            'subjectSurname': None,
            'subjectCountry': None,
            'subjectGivenName': None,
            'issuerProvince': None,
            'subjectLocalityName': None,
            'issuerStateOrProvinceName': None,
            'issuerCommonName': 'thawte dv ssl ca - g2',
            'issueDate': 'Apr 28 00:00:00 2015 GMT',
            'issuerEmailAddress': "testaddress@nodomain.com",
            'subjectOrganizationUnitName': None,
            'subjectOrganizationName': None,
            'fingerprint': (
                'e9:a6:64:7d:6a:ba:52:dc:47:b3:83:8c:92:0c:9e:e5:9b:ad:70:34'
            ),
            'issuerLocalityName': None,
            'issuerGivenName': None,
            'issuerCountry': 'us',
            'subjectStateOrProvinceName': None,
            'sha1': 'e9a6647d6aba52dc47b3838c920c9ee59bad7034',
            'sslVersion': '2',
            'issuerSurname': None,
            'serialNumber': '2317683628587350290823564500811277499',
            'subjectStreetAddress': None,
            'issuerOrganizationUnitName': 'domain validated ssl',
            'subjectProvince': None
        }

        # pt_docs.SSLCertEntry.init()
        ssl_cert_entry = pt_docs.SSLCertEntry()
        for k, v in entry.items():
            setattr(ssl_cert_entry, k, v)

        self._serialize(ssl_cert_entry, entry)
        self._save_doc(ssl_cert_entry)

    def test_ssl_cert_search_response_serialization(self):

        entry = {
            'results': [
                {
                    'issuerStreetAddress': None,
                    'subjectSerialNumber': None,
                    'subjectEmailAddress': None,
                    'expirationDate': 'Apr 27 23:59:59 2017 GMT',
                    'issuerSerialNumber': None,
                    'issuerOrganizationName': 'thawte, inc.',
                    'subjectCommonName': 'www.passivetotal.org',
                    'subjectSurname': None,
                    'subjectCountry': None,
                    'subjectGivenName': None,
                    'issuerProvince': None,
                    'subjectLocalityName': None,
                    'issuerStateOrProvinceName': None,
                    'issuerCommonName': 'thawte dv ssl ca - g2',
                    'issueDate': 'Apr 28 00:00:00 2015 GMT',
                    'issuerEmailAddress': None,
                    'subjectOrganizationUnitName': None,
                    'subjectOrganizationName': None,
                    'fingerprint': (
                        'e9:a6:64:7d:6a:ba:52:dc:47:b3:83:8c:92:0c:9e:' +
                        'e5:9b:ad:70:34'
                    ),
                    'issuerLocalityName': None,
                    'issuerGivenName': None,
                    'issuerCountry': 'us',
                    'subjectStateOrProvinceName': None,
                    'sha1': 'e9a6647d6aba52dc47b3838c920c9ee59bad7034',
                    'sslVersion': '2',
                    'issuerSurname': None,
                    'serialNumber': '2317683628587350290823564500811277499',
                    'subjectStreetAddress': None,
                    'issuerOrganizationUnitName': 'domain validated ssl',
                    'subjectProvince': None
                }
            ]
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.SSLCertSearchResponse.init()
        ssl_cert_search = pt_docs.SSLCertSearchResponse(entry_copy)
        self._serialize_response(ssl_cert_search, entry, "results")
        self._save_doc(ssl_cert_search)

    def test_classification_serialization(self):

        entry = {
            "classification": "benign"
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.ClassificationEntry.init()
        classification = pt_docs.ClassificationEntry(entry_copy)
        self._serialize(classification, entry)
        self._save_doc(classification)

    def test_compromised_serialization(self):

        entry = {
            "everCompromised": True
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.CompromisedEntry.init()
        compromised = pt_docs.CompromisedEntry(entry_copy)
        self._serialize(compromised, entry)
        self._save_doc(compromised)

    def test_dynamicdns_serialization(self):

        entry = {
            "dynamicDns": True
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.DynamicDNSEntry.init()
        dyn_dns = pt_docs.DynamicDNSEntry(entry_copy)
        self._serialize(dyn_dns, entry)
        self._save_doc(dyn_dns)

    def test_monitor_entry_serialization(self):

        entry = {
            "monitor": True
        }

        entry_copy = copy.deepcopy(entry)
        monitor_status = pt_docs.MonitorEntry(entry_copy)
        self._serialize(monitor_status, entry)

    def test_sinkhole_entry_serialization(self):

        entry = {
            "sinkhole": True
        }

        entry_copy = copy.deepcopy(entry)
        # pt_docs.SinkholeEntry.init()
        sinkhole_status = pt_docs.SinkholeEntry(entry_copy)
        self._serialize(sinkhole_status, entry)
        self._save_doc(sinkhole_status)


class TestCymruDocs(ESDocTest):

    def test_asinfo_doc_serialization(self):

        entry = {
            "allocation_date": "2004-01-29",
            "asnum": "123123",
            "ip": "1.1.1.1",
            "asname": "ACME, INC.",
            "prefix": "1.1.1.0/28",
            "registry": "arin",
            "country": "US"
        }

        entry_copy = copy.deepcopy(entry)
        asinfo_doc = cymru_docs.CymruASInfoDoc(entry_copy)
        self._serialize(asinfo_doc, entry)
        self._save_doc(asinfo_doc)

    def test_asnum_info_doc_serialization(self):

        entry = {
            "country": "US",
            "allocation_date": "2004-12-03",
            "asname": "ACME, INC.",
            "asnum": "123123",
            "registry": "arin"
        }

        entry_copy = copy.deepcopy(entry)
        asnum_info_doc = cymru_docs.CymruASNumInfoDoc(entry_copy)
        self._serialize(asnum_info_doc, entry)
        self._save_doc(asnum_info_doc)


class TestGeoLocationDocs(ESDocTest):

    def test_geo_city_doc_serialization(self):

        entry = {
            "city": "Mountain View",
            "region_name": "California",
            "region": "CA",
            "area_code": 650,
            "time_zone": "America/Los_Angeles",
            "location": {
                "lon": -122.05740356445312,
                "lat": 37.4192008972168
            },
            "metro_code": 807,
            "country_code3": "USA",
            "postal_code": "94043",
            "dma_code": 807,
            "country_code": "US",
            "country_name": "United States"
        }

        entry_copy = copy.deepcopy(entry)
        geo_doc = geo_docs.GeoCityDoc(entry_copy)
        self._serialize(geo_doc, entry)
        self._save_doc(geo_doc)

    def test_geo_asn_doc_serialization(self):

        entry = {
            "as_name": "ACME, INC.",
            "as_num": 123123
        }

        entry_copy = copy.deepcopy(entry)
        geo_doc = geo_docs.GeoASNDoc(entry_copy)
        self._serialize(geo_doc, entry)
        self._save_doc(geo_doc)

    def test_geo_country_code_doc_serialization(self):

        entry = {
            "country_code": "US"
        }

        entry_copy = copy.deepcopy(entry)
        geo_doc = geo_docs.GeoCountryCodeDoc(entry_copy)
        self._serialize(geo_doc, entry)
        self._save_doc(geo_doc)

    def test_geo_country_name_doc_serialization(self):

        entry = {
            "country_name": "United States"
        }

        entry_copy = copy.deepcopy(entry)
        geo_doc = geo_docs.GeoCountryNameDoc(entry_copy)
        self._serialize(geo_doc, entry)
        self._save_doc(geo_doc)


class TestShadowServerDocs(ESDocTest):

    def test_asorigin_doc_serialization(self):

        entry = {
            "domain": "acme.com",
            "asnum": "123123",
            "country": "US",
            "isp": "Time Warner Cable Internet LLC",
            "prefix": "1.1.1.1/28",
            "asname": "BHN-TAMPA"
        }

        entry_copy = copy.deepcopy(entry)
        ss_doc = ss_docs.ASOriginDoc(entry_copy)
        self._serialize(ss_doc, entry)
        self._save_doc(ss_doc)

    def test_aspeers_doc_serialization(self):

        entry = {
            "peers": [
                "1111",
                "2222"
            ],
            "asnum": "3333",
            "country": "US",
            "isp": "Time Warner Cable Internet LLC",
            "domain": "twcable.com",
            "prefix": "1.1.1.0/28",
            "asname": "BHN-TAMPA"
        }

        entry_copy = copy.deepcopy(entry)
        ss_doc = ss_docs.ASPeersDoc(entry_copy)
        self._serialize(ss_doc, entry)
        self._save_doc(ss_doc)

    def test_asnum_prefix_doc_serialization(self):

        entry = {
            "prefixes": [
                "1.1.1.1/28",
                "1.2.1.1/28"
            ]
        }

        entry_copy = copy.deepcopy(entry)
        ss_doc = ss_docs.ASPrefixDoc(entry_copy)
        self._serialize(ss_doc, entry)
        self._save_doc(ss_doc)


class TestOpenDNSDocs(ESDocTest):

    def test_domain_categorization_doc_serialization(self):

        entry = {
            "status": "1",
            "security_categories": ["1"],
            "content_categories": [
                "E-Commerce"
            ]
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.DomainCategorizationDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_domain_score_doc_serialization(self):

        entry = {
            "domain": "baddomain.com",
            "score": "-1"
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.DomainScoreDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_co_occurrences_doc_serialization(self):

        entry = {
            "pfs2": [
                {
                    "domain": "download.example.com",
                    "score": 0.9320288065469468
                },
                {
                    "domain": "query.example.com",
                    "score": 0.06797119345305325
                }
            ],
            "found": True
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.CoOccurrencesDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_related_domain_doc_serialization(self):

        entry = {
            "tb1": [
                {
                    "domain": "www.example1.com",
                    "score": 10
                },
                {
                    "domain": "info.example2.com.com",
                    "score": 9
                },
                {
                    "domain": "support.example.com",
                    "score": 3
                }
            ],
            "found": True
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.RelatedDomainsDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_domain_security_info_doc_serialization(self):

        entry = {
            "dga_score": 38.301771886101335,
            "perplexity": 0.4540313302593146,
            "entropy": 2.5216406363433186,
            "securerank2": -1.3135141095601992,
            "pagerank": 0.0262532,
            "asn_score": -29.75810625887133,
            "prefix_score": -64.9070502788884,
            "rip_score": -75.64720536038982,
            "popularity": 25.335450495507196,
            "fastflux": False,
            "geodiversity": [
                {
                    "country_code": "UA",
                    "score": 0.24074075
                },
                {
                    "country_code": "IN",
                    "score": 0.018518519
                }
            ],
            "geodiversity_normalized": [
                {
                    "country_code": "AP",
                    "score": 0.3761535390278368
                },
                {
                    "country_code": "US",
                    "score": 0.0005015965168831449
                }
            ],
            "tld_geodiversity": [],
            "geoscore": 0,
            "ks_test": 0,
            "attack": "",
            "threat_type": "",
            "found": True
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.DomainSecurityInfoDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_domain_resource_record_history_doc_serialization(self):

        entry = {
            "rrs_tf": [
                {
                    "first_seen": "2013-07-31",
                    "last_seen": "2013-10-17",
                    "rrs": [
                        {
                            "name": "example.com.",
                            "ttl": 86400,
                            "class_type": "IN",
                            "query_type": "A",
                            "rr": "93.184.216.119"
                        }
                    ]
                },
                {
                    "first_seen": "2013-07-30",
                    "last_seen": "2013-07-30",
                    "rrs": [
                        {
                            "name": "example.com.",
                            "ttl": 172800,
                            "class_type": "IN",
                            "query_type": "A",
                            "rr": "192.0.43.10"
                        },
                        {
                            "name": "example.com.",
                            "ttl": 86400,
                            "class_type": "IN",
                            "query_type": "A",
                            "rr": "93.184.216.119"
                        }
                    ]
                },
                {
                    "first_seen": "2013-07-18",
                    "last_seen": "2013-07-29",
                    "rrs": [
                        {
                            "name": "example.com.",
                            "ttl": 172800,
                            "class_type": "IN",
                            "query_type": "A",
                            "rr": "192.0.43.10"
                        }
                    ]
                }
            ],
            "features": {
                "age": 91,
                "ttls_min": 86400,
                "ttls_max": 172800,
                "ttls_mean": 129600,
                "ttls_median": 129600,
                "ttls_stddev": 43200,
                "country_codes": [
                    "US"
                ],
                "country_count": 1,
                "asns": [
                    15133,
                    40528
                ],
                "asns_count": 2,
                "prefixes": [
                    "93.184.208.0",
                    "192.0.43.0"
                ],
                "prefixes_count": 2,
                "rips": 2,
                "div_rips": 1,
                "locations": [
                    {
                        "lat": 38.0,
                        "lon": -97.0
                    },
                    {
                        "lat": 33.78659999999999,
                        "lon": -118.2987
                    }
                ],
                "locations_count": 2,
                "geo_distance_sum": 1970.1616237100388,
                "geo_distance_mean": 985.0808118550194,
                "non_routable": False,
                "mail_exchanger": False,
                "cname": False,
                "ff_candidate": False,
                "rips_stability": 0.5,
                "base_domain": "example.com",
                "is_subdomain": False
            }
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.DomainResourceRecordHistoryDoc(entry_copy)
        # self._serialize(doc, entry)  # TODO: Fix this
        self._save_doc(doc)

    def test_ip_resource_record_history_doc_serialization(self):

        entry = {
            "rrs": [
                {
                    "name": "93.184.216.119",
                    "type": "A",
                    "class": "IN",
                    "rr": "www.example.com.",
                    "ttl": 86400
                },
                {
                    "name": "93.184.216.119",
                    "type": "A",
                    "class": "IN",
                    "rr": "www.example.net.",
                    "ttl": 86400
                },
                {
                    "name": "93.184.216.119",
                    "type": "A",
                    "class": "IN",
                    "rr": "www.example.org.",
                    "ttl": 86400
                },
                {
                    "name": "93.184.216.119",
                    "type": "A",
                    "class": "IN",
                    "rr": "examplewww.vip.icann.org.",
                    "ttl": 30
                }
            ],
            "features": {
                "div_ld2_2": 0.5789473684210527,
                "div_ld2_1": 0.3684210526315789,
                "div_ld3": 0.7368421052631579,
                "div_ld2": 0.5263157894736842,
                "ld2_1_count": 7,
                "ld2_count": 10,
                "rr_count": 19,
                "ld3_count": 14,
                "ld2_2_count": 11
            }
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.IPResourceRecordHistoryDoc(entry_copy)
        # self._serialize(doc, entry)
        self._save_doc(doc)

    def test_as_information_doc_serialization(self):

        entry = {
            "creation_date": "2002-08-01",
            "ir": 2,
            "description": "CHINANET-BACKBONE No.31,Jin-rong Street,CN 86400",
            "asn": 4134,
            "cidr": "123.172.0.0/15"
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.ASInformationDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_as_prefix_information_doc_serialization(self):

        entry = {
            "cidr": "98.143.32.0/20",
            "geo": {
                "country_name": "United States",
                "country_code": 225
            }
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.ASPrefixInformationDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_whois_email_to_domain_doc_serialization(self):

        entry = {
            "domain": "mydomain.com",
            "email": "me@mydomain.com",
            "current": False
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.WhoisEmailToDomainDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_whois_nameserver_to_domain_doc_serialization(self):

        entry = {
            "nameserver": "ns1.mydomain.com",
            "domain": "mydomain.com",
            "current": False
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.WhoisNameServerToDomainDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_whois_domain_record_doc_serialization(self):

        entry = {
            "administrativeContactFax": None,
            "whoisServers": "whois.ripn.net",
            "addresses": [],
            "administrativeContactName": None,
            "zoneContactEmail": None,
            "billingContactFax": None,
            "administrativeContactTelephoneExt": None,
            "administrativeContactEmail": None,
            "technicalContactEmail": None,
            "technicalContactFax": None,
            "nameServers": [
                "ns4-cloud.nic.ru.",
                "195.253.65.2,",
                "2a01:5b0:5::2",
                "ns5.nic.ru.",
                "31.177.67.100,",
                "2a02:2090:e800:9000:31:177:67:100",
                "ns6.nic.ru.",
                "31.177.74.100,",
                "2a02:2090:ec00:9040:31:177:74:100",
                "ns7.nic.ru.",
                "31.177.71.100,",
                "2a02:2090:ec00:9000:31:177:71:100",
                "ns8-cloud.nic.ru.",
                "195.253.64.10,",
                "2a01:5b0:4::a",
                "ns9.nic.ru.",
                "31.177.85.186,",
                "2a02:2090:e400:7000:31:177:85:186"
            ],
            "zoneContactName": None,
            "billingContactPostalCode": None,
            "zoneContactFax": None,
            "registrantTelephoneExt": None,
            "zoneContactFaxExt": None,
            "technicalContactTelephoneExt": None,
            "billingContactCity": None,
            "zoneContactStreet": [],
            "created": "1997-11-28",
            "administrativeContactCity": None,
            "registrantName": None,
            "zoneContactCity": None,
            "domainName": "nic.ru",
            "zoneContactPostalCode": None,
            "administrativeContactFaxExt": None,
            "technicalContactCountry": None,
            "registrarIANAID": "1375",
            "updated": None,
            "administrativeContactStreet": [],
            "billingContactEmail": None,
            "record_status": [
                "REGISTERED, DELEGATED, VERIFIED"
            ],
            "registrantCity": None,
            "billingContactCountry": None,
            "expires": "2015-12-01",
            "technicalContactStreet": [],
            "registrantOrganization": "JSC 'RU-CENTER'",
            "billingContactStreet": [],
            "registrarName": "RU-CENTER-RU",
            "registrantPostalCode": None,
            "zoneContactTelephone": None,
            "registrantEmail": None,
            "technicalContactFaxExt": None,
            "technicalContactOrganization": None,
            "emails": [],
            "registrantStreet": [],
            "technicalContactTelephone": None,
            "technicalContactState": None,
            "technicalContactCity": None,
            "registrantFax": None,
            "registrantCountry": None,
            "billingContactFaxExt": None,
            "timestamp": None,
            "zoneContactOrganization": None,
            "administrativeContactCountry": None,
            "billingContactName": None,
            "registrantState": None,
            "registrantTelephone": None,
            "administrativeContactState": None,
            "registrantFaxExt": None,
            "technicalContactPostalCode": None,
            "zoneContactTelephoneExt": None,
            "administrativeContactOrganization": None,
            "billingContactTelephone": None,
            "billingContactTelephoneExt": None,
            "zoneContactState": None,
            "administrativeContactTelephone": None,
            "billingContactOrganization": None,
            "technicalContactName": None,
            "administrativeContactPostalCode": None,
            "zoneContactCountry": None,
            "billingContactState": None,
            "auditUpdatedDate": "2015-10-01 12:45:37.122 UTC",
            "recordExpired": False,
            "timeOfLatestRealtimeCheck": "1443703537167",
            "hasRawText": True
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.WhoisDomainRecordDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)

    def test_latest_malicious_domains_doc_serialization(self):

        entry = {
            "id": 22842894,
            "name": "www.cxhyly.com"
        }

        entry_copy = copy.deepcopy(entry)
        doc = opendns_docs.LatestMaliciousDomsDoc(entry_copy)
        self._serialize(doc, entry)
        self._save_doc(doc)


def tearDownModule():
    try:
        log.info("Cleaning up threatshell index")
        ThreatshellIndex.delete(ignore=404)
    except Exception, e:
        log.warn("[%s]: %s" % (e.__class__.__name__, str(e)))

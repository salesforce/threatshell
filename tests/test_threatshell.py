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

"""
test_threatshell
----------------------------------

Tests for `threatshell` module.
"""
from threatshell.common.log import init_console_logger
from threatshell.commands import cymru
from threatshell.commands import shadow_server as ss_api
from threatshell.commands import opendns as opendns_api

import json
import logging
import os
import re
import time
import unittest

GEO_SKIP = None
TQ_SKIP = None
PT_SKIP = None
IB_SKIP = None
RIQ_SKIP = None
# TODO: Novetta, OpenDNS, ShadowServer
# WD_SKIP

try:
    from threatshell.commands import geoip as geo_api
except ImportError:
    GEO_SKIP = "No geoip module"

try:
    from threatshell.commands import threat_q
except ImportError:
    TQ_SKIP = "No threat_q module"

try:
    from threatshell.commands import passivetotal as pt_api
except ImportError:
    PT_SKIP = "No passivetotal module"

try:
    from threatshell.commands import infoblox
except ImportError:
    IB_SKIP = "No infoblox module"

try:
    from threatshell.commands import riskiq
except ImportError:
    RIQ_SKIP = "No riskiq module"

try:
    from threatshell.common.config import Config
except Exception, e:
    print str(e)
    raise e

config = Config()
if "ThreatQ" not in config.config.sections():
    TQ_SKIP = "No existing configuration"

if "GeoIP" not in config.config.sections():
    GEO_SKIP = "No existing configuration"

if "PassiveTotal" not in config.config.sections():
    PT_SKIP = "No existing configuration"

if "Infoblox" not in config.config.sections():
    IB_SKIP = "No existing configuration"

if "RiskIQ" not in config.config.sections():
    RIQ_SKIP = "No existing configuration"

init_console_logger(log_level=logging.DEBUG)


class ThreatshellTestBase(unittest.TestCase):

    def _validate_response(self, docs):

        if not isinstance(docs, list):
            docs = [docs]

        for doc in docs:
            self.log.debug(doc.to_json())
            assert doc.successful is True


@unittest.skip("test outdated")
class TestConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.log = logging.getLogger(cls.__name__)
        cls.config = Config()

    def test_load_config(self):
        assert "ElasticSearch" in self.config.config.sections()
        assert self.config.get("ElasticSearch", "servers") == (
            "http://localhost:9200"
        )

    def test_save_config(self):
        try:
            self.config.target_path = "./test_config.ini"
            self.config.save_config()
        except Exception, e:
            self.log.error("Failed to save config - %s" % str(e))
            assert False

    @classmethod
    def tearDownClass(cls):
        os.unlink("./test_config.ini")


class TestCymruCommands(ThreatshellTestBase):

    @classmethod
    def setUpClass(cls):
        cls.log = logging.getLogger(cls.__name__)
        cls.cymru_api = cymru.Cymru()

    def test_asn_info(self):
        self._validate_response(
            self.cymru_api.asn_info("8.8.8.8")
        )

    def test_batch_asn_info(self):
        self._validate_response(
            self.cymru_api.batch_asn_info(
                [
                    "8.8.8.8",
                    "8.8.4.4"
                ]
            )
        )

    def test_asnum_to_name(self):
        self._validate_response(
            self.cymru_api.asnum_to_name("6461")
        )

    def test_batch_asnum_to_name(self):
        self._validate_response(
            self.cymru_api.batch_asnum_to_name(
                [
                    "6461",
                    "33363"
                ]
            )
        )


class TestShadowServer(ThreatshellTestBase):

    @classmethod
    def setUpClass(cls):
        cls.log = logging.getLogger(cls.__name__)
        cls.ss = ss_api.ShadowServer()

    def test_asn_origin(self):
        self._validate_response(
            self.ss.asn_origin("8.8.8.8")
        )

    def test_batch_asn_origin(self):
        self._validate_response(
            self.ss.batch_asn_origin(
                [
                    "8.8.8.8",
                    "8.8.4.4"
                ]
            )
        )

    def test_asn_peers(self):
        self._validate_response(
            self.ss.asn_peers("8.8.8.8")
        )

    def test_batch_asn_peers(self):
        self._validate_response(
            self.ss.batch_asn_peers(
                [
                    "8.8.8.8",
                    "8.8.4.4"
                ]
            )
        )

    def test_asnum_to_prefix(self):
        self._validate_response(
            self.ss.asnum_to_prefix("15169")
        )


class TestOpenDNS(ThreatshellTestBase):

    @classmethod
    def setUpClass(cls):
        cls.log = logging.getLogger(cls.__name__)
        cls.opendns_api = opendns_api.OpenDNS_API(config)

    def test_request_categories_batch(self):
        self._validate_response(
            self.opendns_api.request_categories_batch(
                [
                    "google.com",
                    "yahoo.com",
                    "facebook.com"
                ]
            )
        )

    def test_request_dns_info(self):
        self._validate_response(
            self.opendns_api.request_dns_info("yahoo.com")
        )

    def test_request_known_malicious_index(self):
        self._validate_response(
            self.opendns_api.request_known_malicious_index("yahoo.com")
        )

    def test_request_known_malicious_index_batch(self):
        self._validate_response(
            self.opendns_api.request_known_malicious_index_batch(
                [
                    "google.com",
                    "yahoo.com",
                    "facebook.com"
                ]
            )
        )

    def test_request_co_occurences(self):
        self._validate_response(
            self.opendns_api.request_co_occurences("yahoo.com")
        )

    def test_request_related_domains(self):
        self._validate_response(
            self.opendns_api.request_related_domains("yahoo.com")
        )

    def test_request_security_info(self):
        self._validate_response(
            self.opendns_api.request_security_info("yahoo.com")
        )

    def test_request_ip_dns_info(self):
        self._validate_response(
            self.opendns_api.request_ip_dns_info("96.43.148.26")
        )

    def test_request_whois_email(self):
        self._validate_response(
            self.opendns_api.request_whois_email(
                "registrar-updates@yahoo.com"
            )
        )

    def test_request_whois_nameserver(self):
        self._validate_response(
            self.opendns_api.request_whois_nameserver("ns1.yahoo.com")
        )

    def test_request_whois_domain(self):
        self._validate_response(
            self.opendns_api.request_whois_domain(
                "yahoo.com"
            )
        )
        self._validate_response(
            self.opendns_api.request_whois_domain(
                "yahoo.com",
                history=True
            )
        )

    def test_request_mal_domains_for_ip(self):
        self._validate_response(
            self.opendns_api.request_mal_domains_for_ip("95.211.205.228")
        )

    def test_request_ip_asn_info(self):
        self._validate_response(
            self.opendns_api.request_ip_asn_info("96.43.148.26")
        )

    def test_request_asprefix_info(self):
        self._validate_response(
            self.opendns_api.request_asprefix_info("14340")
        )


# @unittest.skipIf(TQ_SKIP is not None, TQ_SKIP)
@unittest.skip("test outdated")
class TestThreatQ(unittest.TestCase):

    def test_query(self):

        args = "1.2.3.4"
        tq = threat_q.ThreatQ()
        jdata = tq.query(args)
        assert jdata

    def test_indicator_statuses(self):

        tq = threat_q.ThreatQ()
        jdata = tq.indicator_statuses(None)
        assert jdata is not None

    def test_indicator_types(self):

        tq = threat_q.ThreatQ()
        jdata = tq.indicator_types(None)
        assert jdata is not None

    def test_update_indicator_status(self):

        tq = threat_q.ThreatQ()
        indicator = "1.2.3.4"
        jdata = tq.query(indicator)
        assert jdata is not None
        indicator_id = jdata[0].get("id")

        args = "%s --class_type network --status 'Non-malicious'" % (
            indicator_id
        )
        resp_content = tq.update_indicator_status(args)
        assert re.search(r"Non\-malicious", resp_content) is not None
        time.sleep(1)
        args = "%s --class_type network --status 'CSIRT_Review'" % (
            indicator_id
        )
        resp_content = tq.update_indicator_status(args)
        assert re.search(r"CSIRT_Review", resp_content) is not None

    # TODO - add test for adding indicator


@unittest.skipIf(GEO_SKIP is not None, GEO_SKIP)
class TestGeoIP(ThreatshellTestBase):

    @classmethod
    def setUpClass(cls):
        cls.log = logging.getLogger(cls.__name__)
        cls.geo_api = geo_api.GeoTools(config)

    def test_update(self):

        db_fnames = self.geo_api.update()
        assert len(db_fnames) > 0

    def test_city_lookup(self):
        self._validate_response(
            self.geo_api.city_lookup("www.google.com")
        )

    def test_country_lookup(self):

        self._validate_response(
            self.geo_api.country_lookup("www.google.com")
        )
        self._validate_response(
            self.geo_api.country_lookup("-cc www.google.com")
        )

    def test_as_lookup(self):

        self._validate_response(
            self.geo_api.as_lookup("www.google.com")
        )

        self._validate_response(
            self.geo_api.as_lookup("64.233.160.103")
        )


# @unittest.skipIf(IB_SKIP is not None, IB_SKIP)
@unittest.skip("test outdated")
class TestInfoblox(unittest.TestCase):

    def setUp(self):
        self.log = logging.getLogger(self.__class__.__name__)

    def test_search(self):

        ib = infoblox.Infoblox()
        try:
            es_docs = ib.search("tommy")
        except Exception, e:
            self.log.error("Infoblox query failed - %s" % str(e))
            assert False

        if not isinstance(es_docs, list):
            es_docs = [es_docs]
        for es_doc in es_docs:
            assert not hasattr(es_doc.response["tommy"], "error")


# @unittest.skip("test outdated")
@unittest.skipIf(PT_SKIP is not None, PT_SKIP)
class TestPassiveTotal(ThreatshellTestBase):

    @classmethod
    def setUpClass(cls):
        cls.log = logging.getLogger(cls.__name__)
        cls.pt = pt_api.PassiveTotal(config)

    def test_get_account_info(self):
        self._validate_response(
            self.pt.get_account_info()
        )

    def test_get_account_history(self):
        self._validate_response(
            self.pt.get_account_history()
        )

    def test_get_account_notifications(self):
        self._validate_response(
            self.pt.get_account_notifications(
                params={
                    "query": "test"
                }
            )
        )

    def test_get_organization_details(self):
        self._validate_response(
            self.pt.get_organization_details()
        )

    def test_get_organization_teamstream(self):
        self._validate_response(
            self.pt.get_organization_teamstream()
        )

    def test_get_source_details(self):
        self._validate_response(
            self.pt.get_source_details()
        )

    def test_get_passive_dns(self):
        self._validate_response(
            self.pt.get_passive_dns("passivetotal.org")
        )

    def test_get_unique_passive_dns(self):
        self._validate_response(
            self.pt.get_unique_passive_dns("passivetotal.org")
        )

    def test_get_domain_enrichment(self):
        self._validate_response(
            self.pt.get_domain_enrichment("passivetotal.org")
        )

    def test_get_ip_enrichment(self):
        self._validate_response(
            self.pt.get_ip_enrichment("8.8.8.8")
        )

    def test_get_malware_enrichment(self):
        self._validate_response(
            self.pt.get_malware_enrichment("noorno.com")
        )

    def test_get_osint_enrichment(self):
        self._validate_response(
            self.pt.get_osint_enrichment("xxxmobiletubez.com")
        )

    def test_get_subdomain_enrichment(self):
        self._validate_response(
            self.pt.get_subdomain_enrichment("passivetotal.org")
        )

    def test_get_whois(self):
        self._validate_response(
            self.pt.get_whois("passivetotal.org")
        )

    def test_search_whois(self):
        params = {
            "field": "email"
        }
        queries = ["domains@riskiq.com"]

        self._validate_response(
            self.pt.search_whois(queries, params)
        )

    def test_tag_manipulation(self):

        self.skipTest("Tags are wonky on passivetotal's side at the moment")

        params = {
            "query": "threatshell.testcase.tag.it",
            "tags": ["test_tag", "other_tag"]
        }
        post_response = self.pt.add_tags(params)
        self.log.debug(json.dumps(post_response, indent=4))
        assert post_response["POST"].get("error") is None

        put_response = self.pt.set_tags(params)
        self.log.debug(json.dumps(put_response, indent=4))
        assert put_response["PUT"]["queryValue"] == params["query"]
        assert put_response["PUT"]["tags"] == params["tags"]

        self.log.debug("Waiting for PassiveTotal 'set' changes")
        time.sleep(5)

        pt_test_tags = self.pt.get_tags(params["query"])
        self.log.debug(json.dumps(pt_test_tags, indent=4))
        assert pt_test_tags["pt_tags"] == params

        pt_tag_search = self.pt.search_tags(params["query"])
        self.log.debug(json.dumps(pt_tag_search, indent=4))
        assert pt_tag_search[params["query"]].get("tags") == params["tags"]

        pt_tag_rm = self.pt.rm_tags(params)
        self.log.debug(json.dumps(pt_tag_rm, indent=4))
        assert pt_tag_rm["DELETE"].get("error") is None

        self.log.debug("Waiting for PassiveTotal 'rm' changes")
        time.sleep(5)
        pt_test_tags = self.pt.get_tags(params["query"])
        assert pt_test_tags["pt_tags"]["tags"] == []

    def test_get_classification_status(self):
        self._validate_response(
            self.pt.get_classification_status("passivetotal.org")
        )

    def test_get_compromised_status(self):
        self._validate_response(
            self.pt.get_compromised_status("passivetotal.org")
        )

    def test_check_dynamic_dns(self):
        self._validate_response(
            self.pt.check_dynamic_dns("passivetotal.org")
        )

    def test_get_monitor_status(self):
        self._validate_response(
            self.pt.get_monitor_status("passivetotal.org")
        )

    def test_get_sinkhole_status(self):
        self._validate_response(
            self.pt.get_sinkhole_status("passivetotal.org")
        )

    def test_set_classification_status(self):
        params = {
            "query": "threatshell.test",
            "classification": "malicious"
        }
        response = self.pt.set_classification_status(params)
        self.log.debug(json.dumps(response, indent=4))
        assert response["POST"].get("error") is None

        self.log.debug("Giving PassiveTotal changes time to update")
        time.sleep(2)

        docs = self.pt.get_classification_status(params["query"])
        for response in docs:
            self.log.debug(response.to_json())
            assert response.successful is True
            assert response.classification == params["classification"]

        # TODO: check with PT friends about why this gets s/-/_/
        params["classification"] = "non-malicious"
        response = self.pt.set_classification_status(params)
        self.log.debug(json.dumps(response, indent=4))
        assert response["POST"].get("error") is None

        self.log.debug("Giving second change time to update")
        time.sleep(2)

        docs = self.pt.get_classification_status(params["query"])
        for response in docs:
            self.log.debug(response.to_json())
            assert response.successful is True
            assert (
                response.classification == params["classification"] or
                response.classification == "non_malicious"
            )

    def test_set_compromised_status(self):

        self.skipTest("Status toggle is still wonky on passivetotal's side")

        params = {
            "query": "threatshell.test",
            "status": True
        }

        response = self.pt.set_compromised_status(params)
        self.log.debug(json.dumps(response, indent=4))
        assert response["POST"].get("error") is None

        self.log.debug("Giving PassiveTotal changes time to update")
        time.sleep(4)

        docs = self.pt.get_compromised_status(params["query"])
        for doc in docs:
            self.log.debug(doc.to_json())
            assert doc.successful is True
            inner_dict = getattr(doc, params["query"])
            assert inner_dict["everCompromised"] is True

        params["status"] = False
        response = self.pt.set_compromised_status(params)
        self.log.debug(json.dumps(response, indent=4))

        self.log.debug("Giving second change time to update")
        time.sleep(4)

        docs = self.pt.get_compromised_status(params["query"])
        for doc in docs:
            self.log.debug(doc.to_json())
            assert doc.successful is True
            inner_dict = getattr(doc, params["query"])
            assert inner_dict["everCompromised"] is False

    # TODO: Finish rest of 'set_x' methods

    def test_get_host_components(self):
        self._validate_response(
            self.pt.get_host_components("passivetotal.org")
        )

    def test_get_host_trackers(self):
        self._validate_response(
            self.pt.get_host_trackers("passivetotal.org")
        )

    def test_search_host_trackers(self):
        params = {
            "type": "GoogleAnalyticsAccountNumber",
            "query": "UA-61048133"
        }
        self._validate_response(
            self.pt.search_host_trackers(params)
        )

    def test_get_ssl_cert_history(self):
        self._validate_response(
            self.pt.get_ssl_cert_history("52.8.228.23")
        )

    def test_get_ssl_cert(self):
        self._validate_response(
            self.pt.get_ssl_cert("528ee71c4ad748ece5368f68299048bffdb31c86")
        )

    # TODO: request fuzzy matching from PT
    def test_search_ssl_certs(self):
        params = {
            "field": "subjectCommonName",
            "query": "*.passivetotal.org"
        }
        self._validate_response(
            self.pt.search_ssl_certs(params)
        )


# @unittest.skipIf(RIQ_SKIP is not None, RIQ_SKIP)
@unittest.skip("test outdated")
class TestRiskIQ(unittest.TestCase):

    def setUp(self):
        self.log = logging.getLogger(self.__class__.__name__)
        self.riq = riskiq.RiskIQ()

    def _validate_data_exists(self, response, key):
        assert response is not None
        assert response != {}
        assert response.get(key) is not None

    def test_ip_passive_dns_by_name(self):
        es_doc = self.riq.passive_dns("8.8.8.8")
        response = es_doc.response["8.8.8.8"]
        self._validate_data_exists(response, "recordCount")
        assert response.get("recordCount") >= 1

    def test_ip_passive_dns_by_data(self):
        es_doc = self.riq.passive_dns("8.8.8.8 --data")
        response = es_doc.response["8.8.8.8"]
        self._validate_data_exists(response, "recordCount")
        assert response.get("recordCount") == 100

    def test_ip_passive_dns_data_limited(self):
        es_doc = self.riq.passive_dns("8.8.8.8 --limit 5 --data")
        response = es_doc.response["8.8.8.8"]
        self._validate_data_exists(response, "recordCount")
        assert response.get("recordCount") == 5

    def test_ip_passive_dns_filter(self):
        es_doc = self.riq.passive_dns("8.8.8.8 --rr_type A")
        response = es_doc.response["8.8.8.8"]
        assert response == "No results found"


if __name__ == '__main__':
    unittest.main()

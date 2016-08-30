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
from threatshell.common.colors import red, bold
from threatshell.common.constants import TS_DIR
from threatshell.doctypes import geoip as geo_docs
from hashlib import md5
import argparse
import GeoIP
import glob
import gzip
import ipaddr
import logging
import os
import re
import requests
import shlex

log = logging.getLogger(__name__)


class GeoTools:

    def __init__(self, config):
        self.config = config
        self.host_url = "http://updates.maxmind.com"
        self.fnames_url = "%s/app/update_getfilename" % self.host_url
        self.ipaddr_url = "%s/app/update_getipaddr" % self.host_url
        self.update_url = "%s/app/update_secure" % self.host_url
        self.db_path = "%s/geo_db" % TS_DIR
        self.db_hashes = {}

        self.v1_asnum = "%s/GeoLiteASNum.dat" % self.db_path
        self.v1_city = "%s/GeoLiteCity.dat" % self.db_path
        self.v1_country = "%s/GeoLiteCountry.dat" % self.db_path

        self.g1_asnum_reader = None
        self.g1_city_reader = None
        self.g1_country_reader = None

        self.have_db_files = True

        if not os.path.exists(self.db_path):
            value = raw_input(
                bold(
                    red(
                        "Geolocation databases not found. Would you like " +
                        "to download them now ([yes]/no)?: "
                    )
                )
            )

            value = value.strip().upper()
            if(
                value == "NO" or
                value == "N"
            ):
                self.have_db_files = False
            else:
                os.mkdir(self.db_path)
                self.update()

        else:

            db_files = glob.glob("%s/*" % self.db_path)

            for db_file in db_files:

                db_data = open(db_file).read()
                db_hash = md5(db_data).hexdigest()

                db_file = db_file.split(os.path.sep)[-1]

                self.db_hashes[db_file] = db_hash

            if db_files:
                self._init_readers()

    def _init_readers(self):
        self.g1_asnum_reader = GeoIP.open(self.v1_asnum, GeoIP.GEOIP_STANDARD)
        self.g1_city_reader = GeoIP.open(self.v1_city, GeoIP.GEOIP_STANDARD)
        self.g1_country_reader = GeoIP.open(
            self.v1_country,
            GeoIP.GEOIP_STANDARD
        )

    def _close_readers(self):
        self.g1_asnum_reader = None
        self.g1_city_reader = None
        self.g1_country_reader = None

    def _reset_readers(self):
        self._close_readers()
        self._init_readers()

    def update(self):

        log.debug("Requesting IP address")
        db_fnames = []
        resp = requests.get(self.ipaddr_url)
        if resp.status_code != 200:
            log.error(
                "Failed to get external IP from %s - [%d]: %s" % (
                    self.ipaddr_url,
                    resp.status_code,
                    resp.content
                )
            )
            return

        ip_addr = resp.content.strip()
        log.debug("IP Address is %s" % ip_addr)
        ip_key_md5 = md5(self.config.get("GeoIP", "LicenseKey"))
        ip_key_md5.update(ip_addr)
        ip_key_hash = ip_key_md5.hexdigest()
        log.debug("IP/Key hash is %s" % ip_key_hash)

        product_ids = self.config.get("GeoIP", "ProductIds").split(",")
        product_ids = [x.strip() for x in product_ids]

        fnames = {}
        for pid in product_ids:

            log.debug("Requesting name for product id %s..." % pid)
            resp = requests.get(self.fnames_url, params={"product_id": pid})

            if resp.status_code != 200:
                log.error(
                    "Failed to resolve %s - [%d]: %s" % (
                        self.fnames_url,
                        resp.status_code,
                        resp.content
                    )
                )
                continue

            fname = resp.content.strip()
            log.debug("Product name is %s" % fname)
            fnames[fname] = pid

        for fname in fnames.keys():

            db_hash = "0" * 32
            if self.db_hashes.get(fname) is not None:
                db_hash = self.db_hashes[fname]

            log.debug("Requesting db file %s" % fname)
            params = {
                "db_md5": db_hash,
                "challenge_md5": ip_key_hash,
                "user_id": self.config.get("GeoIP", "UserId"),
                "edition_id": fnames[fname]
            }
            resp = requests.get(self.update_url, params=params)
            if resp.status_code != 200:
                log.error(
                    "Failed to download new db file - [%d]: %s" % (
                        resp.status_code,
                        resp.content
                    )
                )
            else:
                log.debug("Downloading new db file...")
                chunk_size = 4096
                current_pattern = re.compile(
                    ".*?No new updates.*", re.IGNORECASE)
                with open("%s/%s.gz" % (self.db_path, fname), 'wb') as fd:
                    for chunk in resp.iter_content(chunk_size):
                        fd.write(chunk)

                header = open("%s/%s.gz" % (self.db_path, fname)).read(1024)
                if not current_pattern.match(header):

                    log.debug("Decompressing db file")
                    gz_istream = gzip.open(
                        "%s/%s.gz" % (self.db_path, fname), "rb")
                    ostream = open("%s/%s" % (self.db_path, fname), "wb")
                    buf = gz_istream.read(4096)
                    while buf != "":
                        ostream.write(buf)
                        buf = gz_istream.read(4096)

                    gz_istream.close()
                    ostream.close()
                    os.unlink("%s/%s.gz" % (self.db_path, fname))
                    db_fnames.append("%s/%s" % (self.db_path, fname))

                else:

                    log.debug("%s is up to date" % fname)
                    db_fnames.append("%s/%s" % (self.db_path, fname))
                    os.unlink("%s/%s.gz" % (self.db_path, fname))

        if self.g1_country_reader is None:
            self._init_readers()
        else:
            self._reset_readers()

        return db_fnames

    @AutoQuery.use_on(["ip", "domain"])
    def city_lookup(self, indicators):

        if not isinstance(indicators, list):
            indicators = [indicators]

        docs = []
        for i in indicators:
            if re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", i):
                docs.append(self.city_by_addr(i))
            else:
                docs.append(self.city_by_domain(i))

        return docs

    def city_by_domain(self, domain):

        result = self.g1_city_reader.record_by_name(domain)

        if result:
            result["location"] = {
                "lat": result["latitude"],
                "lon": result["longitude"]
            }
            del result["latitude"]
            del result["longitude"]

        doc = geo_docs.GeoCityDoc(result)
        setattr(doc, "term", domain)

        if result:
            setattr(doc, "successful", True)
        else:
            setattr(doc, "successful", False)

        return doc

    def city_by_addr(self, addr):

        result = self.g1_city_reader.record_by_addr(addr)
        doc = geo_docs.GeoCityDoc(result)

        if result:
            result["location"] = {
                "lat": result["latitude"],
                "lon": result["longitude"]
            }
            del result["latitude"]
            del result["longitude"]

        setattr(doc, "term", addr)

        if result:
            setattr(doc, "successful", True)
        else:
            setattr(doc, "successful", False)

        return doc

    def country_lookup(self, cmd_args):

        parser = argparse.ArgumentParser(usage="geo_country")

        parser.add_argument(
            "-cc",
            "--country_code",
            action="store_true",
            help="Use country code instead of name",
            default=False,
            required=False
        )

        parser.add_argument(
            "target",
            action="store",
            help="The target domain or IP to geolocate"
        )

        try:
            args = parser.parse_args(args=shlex.split(cmd_args))
        except SystemExit, e:
            if str(e) != "0":
                log.error(
                    "Invalid arguments (use -h or --help to see command " +
                    "options)"
                )
            return

        doc = None
        if re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", args.target):

            if args.country_code:

                result = self.country_code_by_addr(args.target)
                doc = geo_docs.GeoCountryCodeDoc(
                    {"country_code" : result}
                )
                setattr(doc, "term", args.target)
                if result:
                    setattr(doc, "successful", True)
                else:
                    setattr(doc, "successful", False)

            else:

                result = self.country_name_by_addr(args.target)
                doc = geo_docs.GeoCountryNameDoc(
                    {"country_name": result}
                )
                setattr(doc, "term", args.target)

                if result:
                    setattr(doc, "successful", True)
                else:
                    setattr(doc, "successful", False)

        else:

            if args.country_code:

                result = self.country_code_by_domain(args.target)
                doc = geo_docs.GeoCountryCodeDoc(
                    {"country_code": result}
                )
                setattr(doc, "term", args.target)

                if result:
                    setattr(doc, "successful", True)
                else:
                    setattr(doc, "successful", False)

            else:

                result = self.country_name_by_domain(args.target)
                doc = geo_docs.GeoCountryNameDoc(
                    {"country_name": result}
                )
                setattr(doc, "term", args.target)

                if result:
                    setattr(doc, "successful", True)
                else:
                    setattr(doc, "successful", False)

        return doc

    def _make_country_record(self, key, value):
        if value:
            return {key: value}

    def country_name_by_domain(self, domain):
        return self.g1_country_reader.country_name_by_name(domain)

    def country_name_by_addr(self, addr):
        return self.g1_country_reader.country_name_by_addr(addr)

    def country_code_by_domain(self, domain):
        return self.g1_country_reader.country_code_by_name(domain)

    def country_code_by_addr(self, addr):
        return self.g1_country_reader.country_code_by_addr(addr)

    @AutoQuery.use_on(["ip", "domain"])
    def as_lookup(self, args):

        if not isinstance(args, list):
            args = [args]

        docs = []
        for arg in args:

            as_string = None
            successful = True
            doc = None

            if re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", arg):

                as_string = self.g1_asnum_reader.org_by_addr(arg)

                start, end = self.g1_asnum_reader.range_by_ip(arg)
                start = ipaddr.IPv4Address(start)
                end = ipaddr.IPv4Address(end)
                net_range = ipaddr.summarize_address_range(start, end)
                doc = geo_docs.GeoIpASNDoc()
                setattr(doc, "ip_allocation", str(net_range[0]))

            else:
                as_string = self.g1_asnum_reader.org_by_name(arg)
                doc = geo_docs.GeoASNDoc()

            if as_string:

                as_parts = as_string.split(" ")
                setattr(doc, "as_num", as_parts[0])
                setattr(doc, "as_name", " ".join(as_parts[1:]))
                setattr(doc, "successful", True)

            else:
                setattr(doc, "as_num", 0)
                setattr(doc, "as_name", "")
                setattr(doc, "successful", False)

            docs.append(doc)

        return docs

    def can_geolocate(self):
        return self.have_db_files

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

from threatshell.common.constants import TS_DIR
from threatshell.common.colors import blue, red
from threatshell.core.config import EncryptedConfigParser

from ConfigParser import RawConfigParser
from StringIO import StringIO

import os


class ConfigManager:

    def __init__(self, config):
        self.config = config
        self.edit_path = os.path.join(TS_DIR, "threatshell.txt")
        self.target_path = os.path.join(TS_DIR, "threatshell.ini")
        self.aes_key = os.path.join(TS_DIR, "aes_key.enc")
        self.rsa_key = os.path.join(TS_DIR, "conf_key.pem")

    def set_option(self, section, option, value):
        self.config.set_option(section, option, value)

    def dump_config(self, to_screen=False):

        f = None
        if to_screen:
            f = StringIO()
        else:
            f = open(self.edit_path, "w")

        RawConfigParser.write(self.config.config, f)
        if not to_screen:
            f.close()
            print blue(
                "Wrote decrypted config to %s" % self.edit_path,
                readline=True
            )
        else:
            data = f.getvalue()
            f.close()
            return data

    def remove_section(self, section):
        if not self.config.config.has_section(section):
            print red("Section %s does not exist" % section)
            return

        self.config.remove_section(section)
        print blue("Successfully removed section %s" % section, readline=True)

    def remove_option(self, section, option):
        if not self.config.config.has_option(section, option):
            print red(
                "Section '%s' has no option '%s' to remove" % (
                    section,
                    option
                ),
                readline=True
            )
            return
        self.config.config.remove_option(section, option)
        print blue(
            "Successfully removed '%s' from '%s'" % (option, section),
            readline=True
        )

    def save(self):
        if os.path.exists(self.edit_path):
            config = EncryptedConfigParser(
                allow_no_value=True,
                private_key=self.rsa_key,
                aes_key=self.aes_key
            )
            read = config.read_raw(self.edit_path)
            if not read:
                raise IOError("Failed to read config '%s'" % self.edit_path)
            config.write(outfile=self.target_path)
        else:
            self.config.save_config()

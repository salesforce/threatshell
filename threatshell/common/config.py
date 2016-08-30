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

from threatshell.common.colors import red, magenta, bold, blue
from threatshell.common.constants import TS_ROOT, TS_DIR
from threatshell.core.config import EncryptedConfigParser
from threatshell.utils.keygen import KeyMaker

from getpass import getpass

import os


class Config:

    def __init__(self, config_file="threatshell.ini"):
        """
        @param config_file - a config file name to read or write

        throws IOException if reading the config file fails
        """

        aes_key = os.path.join(TS_DIR, "aes_key.enc")
        rsa_key = os.path.join(TS_DIR, "conf_key.pem")

        self.target_path = os.path.join(TS_DIR, config_file)
        config_path = self.target_path
        edit_path = os.path.join(TS_DIR, "threatshell.txt")

        config = None

        if not os.path.exists(config_path):

            print red(
                (
                    "\nThis appears to be the first time you've ran " +
                    "threatshell. Let's load the config defaults, then you " +
                    "can setup the appropriate values. Make sure to have " +
                    "your API keys handy ;)\n\n"
                ),
                readline=True
            )
            config_path = os.path.join(TS_ROOT, "conf", "defaults.ini")
            key_maker = KeyMaker(rsa_key, "PEM", 2048)

            print "\n"
            print bold(
                red(
                    "Building RSA key for encrypted config",
                    readline=True
                ),
                readline=True
            )
            key_maker.generate_key()

            while True:

                passphrase = getpass(
                    bold(
                        magenta("RSA key passphrase: ", readline=True),
                        readline=True
                    )
                )

                if passphrase:

                    confirm = getpass(
                        bold(
                            magenta("RSA key passphrase: ", readline=True),
                            readline=True
                        )
                    )

                    if passphrase != confirm:
                        print bold(
                            red(
                                "Passwords do not match! Please try again.\n",
                                readline=True
                            ),
                            readline=True
                        )
                    else:
                        break
                else:
                    break

            key_maker.save_key(passphrase)

            config = EncryptedConfigParser(
                allow_no_value=True,
                aes_key=aes_key,
                private_key=rsa_key
            )

            read = config.read_raw(config_path)
            if not read:
                raise IOError("Failed to read config file '%s'" % config_path)
            self._configure(config)
            config.write(outfile=self.target_path)
            print red(
                "\n\nConfiguration complete - Happy hunting!",
                readline=True
            )

        elif os.path.exists(edit_path):
            config = EncryptedConfigParser(
                allow_no_value=True,
                aes_key=aes_key,
                private_key=rsa_key
            )
            print magenta(
                "Found decrypted config file - loading and encrypting...",
                readline=True
            )
            read = config.read_raw(edit_path)
            if not read:
                raise IOError("Failed to read config file '%s'" % edit_path)
            config.write(outfile=self.target_path)
            os.unlink(edit_path)

        else:
            config = EncryptedConfigParser(
                allow_no_value=True,
                aes_key=aes_key,
                private_key=rsa_key
            )
            config.read(self.target_path)

        self.config = config

    def _configured(self, config):

        for section in config.sections():
            for key, value in config.items(section):
                if not value:
                    return False

        return True

    def _configure(self, config):

        for section in config.sections():
            print red("Configuring %s" % section, readline=True)
            for option, value in config.items(section):
                entry = raw_input(
                    bold(magenta(
                        "\t[%s] (default currently '%s'): " % (
                            option,
                            str(value)
                        ),
                        readline=True
                    ))
                )
                if entry:
                    value = entry
                if not value:
                    value = "NOT SET"
                config.set(section, option, value)

    def get_int(self, section, option):
        """
        Get the integer value of an existing option

        @param section - the config section name containing the option
        @param option - the option to be retrieved

        returns an integer value of the option
        throws NoOptionError if option is not in section
        throws ValueError if option value can't be converted to an integer
        """
        return self.config.getint(section, option)

    def get_boolean(self, section, option):
        """
        Get the boolean value of an existing option

        @param section - the config section name containing the option
        @param option - the option to be retrieved

        returns a boolean value of the option
        throws NoOptionError if option is not in section
        throws ValueError if option value can't be converted to a boolean
        """
        return self.config.getboolean(section, option)

    def get(self, section, option):
        """
        Get the raw string value of an option

        @param section - the config section name containing the option
        @param option - the option to be retrieved

        returns the raw string value of the option
        throws NoOptionError if option is not in section
        """
        return self.config.get(section, option)

    def set_option(self, section, option, value):
        """
        Creates or overwrites existing options

        @param section - the config section name that will contain the option
        @param option - the name of the option to create or modify
        @param value - the value for the given option to have
        """
        if section not in self.config.sections():
            resp = raw_input(
                bold(
                    magenta(
                        "Section %s does not exist. Create? (y/[n]): " % (
                            section
                        ),
                        readline=True
                    ),
                    readline=True
                )
            )
            if not resp or resp.lower() == "n":
                print red("Opted out of creating new section", readline=True)
                return
            else:
                self.config.add_section(section)
                self.config.set(section, option, value)
                print blue(
                    "Added '%s' -> '%s' to new section '%s'" % (
                        option,
                        value,
                        section
                    ),
                    readline=True
                )
                return

        if not self.config.has_option(section, option):
            resp = raw_input(
                bold(
                    magenta(
                        "%s does not have option %s. Create? (y/[n]): " % (
                            section,
                            option
                        ),
                        readline=True
                    ),
                    readline=True
                )
            )
            if not resp or resp.lower() == "n":
                print red("Opted out of creating new option", readline=True)
            else:
                self.config.set(section, option, value)
                print blue(
                    "Successfully added '%s' -> '%s'" % (
                        section,
                        option
                    ),
                    readline=True
                )

        else:
            self.config.set(section, option, value)

    def save_config(self):
        """
        saves current configuration to file
        """
        self.config.write(outfile=self.target_path)

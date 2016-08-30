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

from threatshell.common.colors import bold, magenta

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from ConfigParser import RawConfigParser
from getpass import getpass
from StringIO import StringIO

import os
import struct


class Error(Exception):

    def _get_message(self):
        return self.__message

    def _set_message(self, message):
        self.__message = message

    message = property(_get_message, _set_message)

    def __init__(self, msg=""):
        self.message = msg
        Exception.__init__(self, msg)

    def __repr__(self):
        return self.message

    __str__ = __repr__


class KeyNotFoundError(Error):

    def __init__(self, message="Private key not found"):
        Error.__init__(self, message)


class ConfigDecryptionError(Error):

    def __init__(self):
        Error.__init__(self, "Config decrytption failed")


class AESKeygen:

    def __init__(self, key=None, iv=None):

        if key is None:
            key = Random.new().read(32)

        if iv is None:
            iv = Random.new().read(AES.block_size)

        self.aes_key = AES.new(key, AES.MODE_CBC, IV=iv)
        self.key = key
        self.iv = iv

    def get_key(self):
        return self.key

    def get_iv(self):
        return self.iv

    def get_encryptor(self):
        return self.aes_key


class EncryptedConfigParser(RawConfigParser):

    def __init__(
        self,
        defaults=None,
        dict_type=dict,
        allow_no_value=False,
        private_key="conf_key.private.pem",
        aes_key="aes_key.enc"
    ):

        RawConfigParser.__init__(
            self,
            defaults,
            dict_type,
            allow_no_value
        )

        pkey_data = None
        try:
            pkey_h = open(private_key, "rb")
            pkey_data = pkey_h.read()
            pkey_h.close()
        except IOError:
            raise KeyNotFoundError()

        self.private_key = RSA.importKey(
            pkey_data,
            passphrase=getpass(
                bold(
                    magenta("RSA key passphrase: ", readline=True),
                    readline=True
                )
            )
        )
        self.public_key = self.private_key.publickey()
        self.aes_key_name = aes_key

    def _decrypt_config(self, key, fhandle, chunksize=1024):

        orig_size = struct.unpack('<Q', fhandle.read(struct.calcsize('Q')))[0]
#        print "Original size: %d" % orig_size
        iv = fhandle.read(AES.block_size)

        iv_string = []
        for x in iv:
            iv_string.append("%02x" % ord(x))
#        print "IV: %s" % " ".join(iv_string)

        aes_key = AES.new(key, AES.MODE_CBC, IV=iv)
        decryptor = aes_key
        file_stream = StringIO()

        while True:

            chunk = fhandle.read(chunksize)
#            print "chunk length: %d" % len(chunk)
            if len(chunk) == 0:
                break

#            print "Encrypted chunk: %s" % chunk

            d_chunk = decryptor.decrypt(chunk)
#            print "Decrypted chunk: %s" % d_chunk
            file_stream.write(d_chunk)

        file_stream.truncate(orig_size)
        file_stream.seek(0)
        return file_stream

    def _encrypt_config(
        self,
        key,
        fhandle,
        outfile="settings.ini.enc",
        chunksize=1024
    ):

        fhandle.seek(0, os.SEEK_END)
        fsize = fhandle.tell()
        fhandle.seek(0)

        out_handle = open(outfile, "wb")

        out_handle.write(struct.pack("<Q", fsize))
        out_handle.write(key.get_iv())

        encryptor = key.get_encryptor()
        while True:

            chunk = fhandle.read(chunksize)
            if len(chunk) == 0:
                break

            elif len(chunk) % AES.block_size != 0:
                chunk += " " * (16 - len(chunk) % 16)

            out_handle.write(encryptor.encrypt(chunk))

    def _encrypt_aes_key(self, aes_key):

        encrypted = self.public_key.encrypt(aes_key.get_key(), None)
        key_handle = open(self.aes_key_name, "wb")
        key_handle.write(encrypted[0])
        key_handle.close()

    def _load_aes_key(self):

        key = self.private_key.decrypt(open(self.aes_key_name, "rb").read())
        return key

    def read_raw(self, filenames):
        read_ok = []
        if not isinstance(filenames, list):
            filenames = [filenames]

        for filename in filenames:
            fp = open(filename, "r")
            RawConfigParser._read(self, fp, filename)
            read_ok.append(filename)

        return read_ok

    def read(self, filenames):

        read_ok = []
        key = None
        try:
            key = self._load_aes_key()
        except IOError:
            raise KeyNotFoundError("AES Key not found")

        if not isinstance(filenames, list):
            filenames = [filenames]

        for filename in filenames:

            fhandle = open(filename, "rb")
            decrypted_stream = self._decrypt_config(key, fhandle)
            fhandle.close()

#            print "Calling parent method"
#            print "Decrypted stream content: %s" % decrypted_stream.getvalue()
            RawConfigParser._read(self, decrypted_stream, filename)
            decrypted_stream.close()
            read_ok.append(filename)

        return read_ok

    def write(self, outfile="settings.ini.enc"):

        config_stream = StringIO()
        RawConfigParser.write(self, config_stream)
        aes_key = AESKeygen()

        self._encrypt_config(aes_key, config_stream, outfile=outfile)
        self._encrypt_aes_key(aes_key)

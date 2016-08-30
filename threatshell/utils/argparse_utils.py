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

import argparse
import time


def validate_datetime(dt):

    try:
        time.strptime(dt, "%m-%d-%Y %H:%M:%S")
    except Exception, e:
        raise argparse.ArgumentTypeError(
            (
                "%s does not match the format of MM-DD-YYYY HH:MM:SS" +
                " - Exception info: [%s] - %s"
            ) % (dt, e.__class__.__name__, e.message)
        )

    return dt


class ConvertDateTimeAction(argparse.Action):

    def __init__(
        self,
        option_strings,
        dest,
        nargs=None,
        const=None,
        default=None,
        type=None,
        choices=None,
        required=False,
        help=None,
        metavar=None
    ):

        default = self._make_time_epoch(default)
        argparse.Action.__init__(
            self,
            option_strings=option_strings,
            dest=dest,
            nargs=nargs,
            const=const,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar,
        )

    def _make_time_epoch(self, dt):
        try:
            return int(
                time.mktime(
                    time.strptime(
                        dt,
                        "%m-%d-%Y %H:%M:%S"
                    )
                )
            )
        except:
            return None

    def __call__(self, parser, namespace, values, option_string=None):

        datetime_stamp = None
        if isinstance(values, list):
            datetime_stamp = values[0]
        else:
            datetime_stamp = values

        time_epoch = self._make_time_epoch(datetime_stamp)

        setattr(namespace, self.dest, time_epoch)

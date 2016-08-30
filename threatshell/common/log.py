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

from threatshell.common.colors import red, yellow, green, cyan
from threatshell.common.constants import TS_DIR

from logging.handlers import RotatingFileHandler

import copy
import logging
import os

log = logging.getLogger()
log.setLevel(logging.DEBUG)

FORMAT = "%(asctime)s [%(levelname)s]: %(name)s - %(message)s"


class ConsoleHandler(logging.StreamHandler):

    def emit(self, record):

        colored = copy.copy(record)

        if record.levelname == "WARNING":
            colored.msg = yellow(record.msg)

        elif record.levelname in ["ERROR", "CRITICAL", "FATAL"]:
            colored.msg = red(record.msg)

        elif record.levelname == "INFO":
            colored.msg = green(record.msg)

        else:
            colored.msg = cyan(record.msg)

        logging.StreamHandler.emit(self, colored)


def init_file_logger(log_level=logging.DEBUG):

    formatter = logging.Formatter(FORMAT)

    log_path = "%s/logs/threatshell.log" % TS_DIR

    path_parts = []
    start = 0
    if log_path[0] == os.path.sep:
        path_parts.append('')
        start += 1

    for path in log_path.split(os.path.sep)[start: -1]:

        path_parts.append(path)
        if not os.path.exists(os.path.sep.join(path_parts)):
            os.mkdir(os.path.sep.join(path_parts), 0o0700)

    file_h = RotatingFileHandler(
        log_path,
        mode="a",
        maxBytes=100 * 1000 * 1000,  # 100MB
        backupCount=5
    )
    file_h.setLevel(log_level)
    file_h.setFormatter(formatter)
    log.addHandler(file_h)


def init_console_logger(log_level=logging.INFO):

    formatter = logging.Formatter(FORMAT)
    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    ch.setLevel(log_level)
    log.addHandler(ch)


def init_logging(con_level=logging.INFO, f_level=logging.DEBUG):

    init_file_logger(f_level)
    init_console_logger(con_level)

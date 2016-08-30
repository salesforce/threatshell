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

import os
import sys


def color(text, color_code, readline=True):
    """Colorize text.
    @param text: text.
    @param color_code: color.
    @return: colorized text.
    """
    # $TERM under Windows:
    # cmd.exe -> "" (what would you expect..?)
    # cygwin -> "cygwin" (should support colors, but doesn't work somehow)
    # mintty -> "xterm" (supports colors)
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text
    if readline:
        # special readline escapes to fix colored input promps
        # http://bugs.python.org/issue17337
        return "\001\033[%dm\002%s\001\033[0m\002" % (color_code, text)
    return "\x1b[%dm%s\x1b[0m" % (color_code, text)


def black(text, readline=True):
    return color(text, 30, readline)


def red(text, readline=True):
    return color(text, 31, readline)


def green(text, readline=True):
    return color(text, 32, readline)


def yellow(text, readline=True):
    return color(text, 33, readline)


def blue(text, readline=True):
    return color(text, 34, readline)


def magenta(text, readline=True):
    return color(text, 35, readline)


def cyan(text, readline=True):
    return color(text, 36, readline)


def white(text, readline=True):
    return color(text, 37, readline)


def bold(text, readline=True):
    return color(text, 1, readline)

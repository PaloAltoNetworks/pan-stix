#
# Copyright (c) 2014-2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import re
import logging

LOG = logging.getLogger(__name__)

IECACHE_RE = re.compile(
    '\\\\Temporary Internet Files\\\\',
    re.I
)

USER_RES = [
    re.compile(
        '\\\\Documents And Settings\\\\Administrator(.*)',
        re.I
    ),
    re.compile(
        '\\\\Users\\\\Administrator(.*)',
        re.I
    ),
    re.compile(
        '\\\\Documents And Settings\\\\<USER>(.*)',
        re.I
    ),
    re.compile(
        '\\\\Users\\\\<USER>(.*)',
        re.I
    ),
    re.compile(
        '\\\\DOCUME~1\\\\<USER>\\\\LOCALS~1(.*)',
        re.I
    )
]


def registry_data(props, rdata):
    if rdata == 'NULL':
        props.data = ''
        props.data_type = 'REG_NONE'
        return

    for cre in USER_RES:
        if len(rdata) > 2:
            if rdata[1] == ':' and rdata[2] == '\\':
                rdata = rdata[2:]

        mo = cre.match(rdata)
        if mo is not None:
            if len(mo.group(1)) > 0:
                props.data = mo.group(1)
                props.data.condition = 'EndsWith'
                return

            return

    props.data = rdata
    return


def file_path(props, fpath):
    for cre in USER_RES:
        mo = cre.match(fpath)
        if mo is not None:
            if len(mo.group(1)) > 0:
                if IECACHE_RE.search(mo.group(1)) is not None:
                    # IE CACHE, remove unique subdir name inside cache
                    props.file_path = '\\Temporary Internet Files\\'
                    props.file_path.condition = 'Contains'

                else:
                    props.file_path = mo.group(1)
                    props.file_path.condition = 'EndsWith'

                return

            # full match, remove from observable
            return

    props.file_path = fpath


def file_name(props, fname):
    if fname == 'sample.exe':
        return

    props.file_name = fname

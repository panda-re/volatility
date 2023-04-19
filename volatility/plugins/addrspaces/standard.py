# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

""" These are standard address spaces supported by Volatility """
import struct
import volatility.addrspace as addrspace
import volatility.debug as debug  # pylint: disable-msg=W0611
import urllib.request, urllib.parse, urllib.error
import os

# Ryan socket hacks
import socket
from struct import *

# pylint: disable-msg=C0111


def write_callback(option, _opt_str, _value, parser, *_args, **_kwargs):
    """Callback function to ensure that write support is only enabled if user repeats a long string

    This call back checks whether the user really wants write support and then either enables it
    (for all future parses) by changing the option to store_true, or disables it permanently
    by ensuring all future attempts to store the value store_false.
    """
    if not hasattr(parser.values, 'write'):
        # We don't want to use config.outfile, since this should always be seen by the user
        option.dest = "write"
        option.action = "store_false"
        parser.values.write = False
        for _ in range(3):
            testphrase = "Yes, I want to enable write support"
            response = input(
                f"Write support requested.  Please type \"{testphrase}\" below precisely (case-sensitive):\n"
            )
            if response == testphrase:
                option.action = "store_true"
                parser.values.write = True
                return
        print("Write support disabled.")


class FileAddressSpace(addrspace.BaseAddressSpace):
    """This is a direct file AS.

    For this AS to be instantiated, we need

    1) A valid config.LOCATION (starting with file://)

    2) no one else has picked the AS before us

    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """

    ## We should be the AS of last resort
    order = 100

    def __init__(self, base, config, layered=False, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.as_assert(base == None or layered, 'Must be first Address Space')
        self.as_assert(
            config.LOCATION.startswith("file://"),
            'Location is not of file scheme',
        )

        path = urllib.request.url2pathname(config.LOCATION[7:])
        self.as_assert(
            os.path.exists(path), 'Filename must be specified and exist'
        )
        self.name = os.path.abspath(path)
        self.fname = self.name
        self.mode = 'rb'
        self.socket = False
        self.last_addr = 0
        if config.WRITE:
            self.mode += '+'
        if "pmem_sock" not in self.fname:
            self.fhandle = open(self.fname, self.mode)
            self.fhandle.seek(0, 2)
            self.fsize = self.fhandle.tell()
        else:
            self.fhandle =  socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.fhandle.connect(self.fname)
            self.socket = True
            sz_bytes = int.from_bytes(self.request_generator(3, 0, 8), "little")
            self.fsize = sz_bytes
        self._long_struct = struct.Struct("=I")

    # Abstract Classes cannot register options, and since this checks config.WRITE in __init__, we define the option here
    @staticmethod
    def register_options(config):
        config.add_option(
            "WRITE",
            short_option='w',
            action="callback",
            default=False,
            help="Enable write support",
            callback=write_callback,
        )

    def request_generator(self, type, addr, length):
        req = pack("<QQQ", type, addr, length)
        #print(f"Sending req {req}")
        self.fhandle.sendall(req)
        data = self.fhandle.recv(length)
        #print(f"\t And read data: {data}")
        return data

    def fread(self, length: int) -> bytes:
        if self.socket:
            self.last_addr +=  length
            return self.request_generator(1, self.last_addr - length, int(length))
        length = int(length)
        return self.fhandle.read(length)

    def read(self, addr: int, length: int) -> bytes:
        addr, length = int(addr), int(length)
        if self.socket:
            #print(f"[STANDARD] Addr: {addr:x} | length: {length}")
            self.last_addr = addr + length
            data = self.request_generator(1, int(addr), int(length))
            if len(data) == 0:
                #print(f"[STANDARD] Returning None")
                return None
            #print(f"[STANDARD] Returning {data}")
            return data
        try:
            self.fhandle.seek(addr)
        except (IOError, OverflowError):
            return None
        data = self.fhandle.read(length)
        if len(data) == 0:
            return None
        return data

    def zread(self, addr: int, length: int) -> bytes:
        data = self.read(addr, length)
        if data is None:
            data = b'\x00' * length
        elif len(data) != length:
            data += b'\x00' * (length - len(data))
        return data

    def read_long(self, addr: int) -> int:
        string = self.read(addr, 4)
        (longval,) = self._long_struct.unpack(string)
        return longval

    def get_available_addresses(self):
        # Since the second parameter is the length of the run
        # not the end location, it must be set to fsize, not fsize - 1
        yield (0, self.fsize)

    def is_valid_address(self, addr: int) -> bool:
        if addr == None:
            return False
        return 0 <= addr < self.fsize

    def close(self):
        print("[standard] Closing time")
        self.fhandle.close()

    def write(self, addr: int, data: bytes):
        if not self._config.WRITE:
            return False
        if self.socket:
            try:
                self.request_generator(2, addr, len(data))
                self.fhandle.sendall(data)
                return True
            except:
                return False
        try:
            self.fhandle.seek(addr)
            self.fhandle.write(data)
        except IOError:
            return False
        return True

    def __eq__(self, other):
        return (
            self.__class__ == other.__class__
            and self.base == other.base
            and hasattr(other, "fname")
            and self.fname == other.fname
        )

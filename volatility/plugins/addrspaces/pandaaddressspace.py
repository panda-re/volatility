#!/usr/bin/python

import volatility.addrspace as addrspace

class PANDAAddressSpace(addrspace.BaseAddressSpace):
    def __init__(self, base, config, **kwargs):
        '''
        Initializes the address space with volatility and connects to the PMemAcess socket
        '''
        self.as_assert(base == None, 'Must be first Address Space')
        self.as_assert(hasattr(config, "panda"), "Must have PANDA address space")
        addrspace.BaseAddressSpace.__init__(self, None, config, **kwargs)
        self.panda = config.panda
        self.max_addr = 0xffffffff if self.panda.bits == 32 else 0xffffffffffffffff

    def close(self):
        pass

    def __del__(self):
        self.close()
    
    def read(self, addr, length):
        # print(f"Reading {length} bytes from {addr}")
        try:
            return self.panda.physical_memory_read(addr, length)
        except ValueError:
            return b""

    def zread(self, addr, length):
        # print(f"ZReading {length} bytes from {addr}")
        out = self.read(addr, length)
        if len(out) < length:
            out += b"\x00" * (length - len(out))
        return out

    def is_valid_address(self, addr):
        return addr >= 0 and addr <= self.max_addr

    def get_available_addresses(self):
        yield (0, self.max_addr)
    
    def write(self, addr, data):
        # print(f"Writing {len(data)} bytes to {addr}")
        return self.panda.physical_memory_write(addr, data)
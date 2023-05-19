#!/usr/bin/python

import volatility.addrspace as addrspace
import urllib
import socket
import struct
import sys
from threading import Thread, Lock

class PMemAddressSpace(addrspace.BaseAddressSpace):
    # PMemAccess request types
    REQ_OUIT = 0
    REQ_READ = 1
    REQ_WRITE = 2
    REQ_RAM_SIZE = 3

    mutex = Lock()

    def __init__(self, base, config, **kwargs):
        '''
        Initializes the address space with volatility and connects to the PMemAcess socket
        '''
        # Address space setup
        #print(f"Base: {base}")
        self.as_assert(base == None, "Must be first Address Space")
        addrspace.BaseAddressSpace.__init__(self, None, config, **kwargs)
        self.as_assert(config.LOCATION.startswith("file://"), 'Location is not of file scheme')

        # Connect to the socket
        self.sock_path = config.LOCATION[len("file://"):]
        #print("Connecting to: " + self.sock_path)
        self.sock_fd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connected = False
        tries = 0
        while tries < 10:
            try:
                self.sock_fd.connect(self.sock_path)
                self.connected = True
                break
            except socket.error as msg:
                #sys.stderr.write("PMemAddressSpace:{0}".format(str(msg)))
                #sys.stderr.flush()
                tries += 1
                sys.stderr.write("Failed, trying {0}th time\n".format(tries))
                sys.stderr.flush()
                #sys.exit(1)
        self.as_assert(self.connected, "Could not connect to socket")
        #self.send_request(self.REQ_RAM_SIZE, 0, 0)
        #x = self.sock_fd.recv(self.profile.get_obj_size("address") * 2)
        #print(f"{x}")  
        #self.max_addr = int.from_bytes(x, "big")
        #print(f"{self.max_addr:x}")
        #if self.profile.get_obj_size("address") == 4:
        #    self.max_addr = 0xffffffff
        #else:
        #    self.max_addr = 0xffffffffffffffff
        self.max_addr = 0xffffffffffffffff
        #print("SUCCESS: Connected to: " + self.sock_path)

    def close(self):
        '''
        Closes our socket and tells qemu to close its socket and thread
        XXX: Multiple connections are made, but not all of them are closed.
        '''
        try:
            self.sock_fd
            if not self.connected:
                return
        except AttributeError:
            return
        # Send quit message
        self.send_request(self.REQ_OUIT, 0, 0)
        self.sock_fd.close()

    def __del__(self):
      self.close()
   
    def send_request(self, req_type, req_addr, req_len):
      '''
      Sends a formatted request to PMemAccess
      '''
      self.sock_fd.send(struct.pack("<QQQ", req_type, req_addr, req_len))
 
    def __read_bytes(self, addr, length, pad):
        '''
        Reads data using PMemAccess
        '''
        memory = b''
        try:
            # Split the requests into smaller chunks
            block_length = 1024*4
            read_length = 0
            while read_length < length:
              # Send read request
              read_len = block_length
              if length-read_length < read_len:
                  read_len = length-read_length
              self.send_request(self.REQ_READ, addr+read_length, read_len)
              # Read the memory
              '''
              try:
                self.sock_fd.settimeout(5.0)
                memory += self.sock_fd.recv(read_len)
              
                self.sock_fd.settimeout(5.0)
                status = struct.unpack("<B", self.sock_fd.recv(1))[0]
              except:
                  memory = b''
                  status = 2
                  '''
            
              memory += self.sock_fd.recv(read_len)
              status = struct.unpack("<B", self.sock_fd.recv(1))[0]
              if status == 0:
                  raise AssertionError("PMemAddressSpace: READ of length " + 
                                       str(read_length) + '/' + str(length) +
                                       " @ " + hex(addr) + " failed.")
              if status == 2:
                  raise(AssertionError("PMemAddressSpace: TIMEOUT @ " + hex(addr)))
              read_length += read_len
        except AssertionError as e:
            memory = b''
        if pad:
            if memory is None:
                memory = b'\x00' * length
            elif len(memory) != length:
                memory += b'\x00' * (length - len(memory))
        
        return memory

    def read(self, addr, length):
        return self.__read_bytes(addr, length, pad=False)

    def zread(self, addr, length):
        return self.__read_bytes(addr, length, pad=True)

    def is_valid_address(self, addr):
        if 0 > addr or addr > self.max_addr:
            return False
        #if addr == None:
        #    return False
        return True

    def get_available_addresses(self):
        yield (0, self.max_addr)
    
    def write(self, addr, data):
        '''
        Writes data using PMemAccess
        '''
        try:
            sys.stderr.write("Writing data?\n")
            sys.stderr.flush()
            length = len(data)
            # Send write request
            self.send_request(self.REQ_WRITE, addr, length)
            self.sock_fd.send(data)
            status = struct.unpack("<B", self.sock_fd.recv(1))[0]
            # Make sure it worked
            if status == 0:
                raise AssertionError("PMemAddressSpace: WRITE of length " + str(length) +
                                     " @ " + hex(addr) + " failed.")
        except AssertionError as e:
            print(e)
            return False
        return True
#!/usr/bin/python3

'''
Marvell binary firmware tool

written by vit_sembera@trendmicro.com
'''

import sys, os, argparse, struct
from stat import *

parser = argparse.ArgumentParser(description='')
parser.add_argument('-v', '--verbose', action = 'store_true', help='verbose output')
parser.add_argument('-n', '--name', action = 'store_true', help='outputs filename')
parser.add_argument('filename', nargs = '+', help='one or more files')
args = parser.parse_args()

chunk_hdr_format = '<iiII'

  
  
for filename in args.filename:
    statinfo = os.stat(filename)
    if args.name:
      print(filename)
    if S_ISREG(statinfo[ST_MODE]):
      if args.verbose:
        print("Regular file, size = ", statinfo.st_size)
      if statinfo.st_size > 0:
        with open(filename, "rb") as file:
          ccounter = 0
          final_chunk = False;
          while not final_chunk:
            for ctype, addr, clen, crc in struct.iter_unpack(chunk_hdr_format, file.read(struct.calcsize(chunk_hdr_format))):    
              if args.verbose:
                print('Read {} bytes of chunk header. \nType : {}, Addr : {:x}, Len : {}, CRC32 : {:x}'
                  .format(struct.calcsize(chunk_hdr_format), ctype, addr, clen, crc))
              if clen != 0:
                data = file.read(clen);    
                if args.verbose:
                  print('Read {} bytes of chunk data.'.format(len(data)))
                ccounter += 1
              else:
                final_chunk = True
              
    else:
      if args.verbose:
        print('Not a regular file')
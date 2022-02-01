#!python3

'''
Marvell binary firmware tool

written by vit_sembera@trendmicro.com
'''

import sys, os, argparse, struct, crcmod
from stat import *

parser = argparse.ArgumentParser(description='')
parser.add_argument('-v', '--verbose', action = 'count', default = 0, help='verbose level')
parser.add_argument('infile', type=argparse.FileType('rb'))
parser.add_argument('outfile', nargs='?', type=argparse.FileType('wb'))
args = parser.parse_args()

chunk_hdr_format = '<iiI'
chunk_hdr_crc_format = '>I'
chunk_data_crc_format = '>I'

marvell_crc32 = crcmod.mkCrcFun(poly=0x104c11db7, initCrc=0, rev=False)
  
  
chunk_counter = 0
total_len = 0
final_chunk = False;
crc_error = False
output_data = b''
      
while not final_chunk and not crc_error:
  chunk_hdr = args.infile.read(struct.calcsize(chunk_hdr_format))
  chunk_hdr_crc = struct.unpack(chunk_hdr_crc_format, args.infile.read(struct.calcsize(chunk_hdr_crc_format)))[0]
  for ctype, addr, clen in struct.iter_unpack(chunk_hdr_format, chunk_hdr): 
    crc_hdr_calc = marvell_crc32(chunk_hdr)    
    if args.verbose > 1:
      print('Read {} bytes of chunk header.'.format(struct.calcsize(chunk_hdr_format)))
    if args.verbose > 0:
      print('Chunk Type: {}, Addr: {:x}, Len: {}'.format(ctype, addr, clen))
    if args.verbose > 1:
      print('Chunk header CRC: {:x}, calculated CRC: {:x}'.format(chunk_hdr_crc, crc_hdr_calc))
    if ctype == 1:
      data = args.infile.read(clen - 4);
      if args.verbose > 2:
        print('Raw header: {}'.format(chunk_hdr))
        print('Raw data: {}'.format(data))
      crc_data_calc = marvell_crc32(data)
      chunk_data_crc = struct.unpack(chunk_data_crc_format, args.infile.read(struct.calcsize(chunk_data_crc_format)))[0]
      if args.verbose > 1:
        print('Read {} bytes of chunk data. Chunk CRC: {:x}, calculated CRC: {:x}'.format(len(data), chunk_data_crc, crc_data_calc))               
      chunk_counter += 1
      total_len += clen - 4
      output_data += data
      crc_error = chunk_hdr_crc != crc_hdr_calc or chunk_data_crc != crc_data_calc
    elif ctype == 4:
      final_chunk = True
    else:
      print('Unknown chunk type {}'.format(ctype))
if not crc_error:
  print('Number of chunks: {}, Total length: {}'.format(chunk_counter, total_len))
  if args.outfile:
    written = args.outfile.write(output_data)
    args.outfile.close()
    print('Written {} bytes'.format(written))
else:
  print('CRC Error')    
   
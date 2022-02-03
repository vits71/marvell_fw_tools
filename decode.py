#!python3

'''
Marvell binary firmware tool
'''

import sys, os, argparse, struct, crcmod
from stat import *

class ChunkCrcError(Exception):
  pass
  
class UnknownChunkTypeError(Exception):
  pass

parser = argparse.ArgumentParser(description='')
parser.add_argument('-v', '--verbose', action = 'count', default = 0, help='verbose level')
parser.add_argument('infile', type=argparse.FileType('rb'))
parser.add_argument('outfile', type=argparse.FileType('wb'))
args = parser.parse_args()

chunk_hdr_format = '<iiI'
chunk_hdr_crc_format = '>I'
chunk_data_crc_format = '>I'
marvell_crc32 = crcmod.mkCrcFun(poly=0x104c11db7, initCrc=0, rev=False)
  
def read_chunk():
  chunk_hdr = args.infile.read(struct.calcsize(chunk_hdr_format))
  chunk_hdr_crc = struct.unpack(chunk_hdr_crc_format, args.infile.read(struct.calcsize(chunk_hdr_crc_format)))[0]
  for chunk_type, chunk_addr, chunk_len in struct.iter_unpack(chunk_hdr_format, chunk_hdr): 
    crc_hdr_calc = marvell_crc32(chunk_hdr)    
    if args.verbose > 1:
      print('Read {} bytes of chunk header.'.format(struct.calcsize(chunk_hdr_format)))
    if args.verbose > 0:
      print('Chunk Type: {}, Addr: {:#x}, Len: {}'.format(chunk_type, chunk_addr, chunk_len))
    if args.verbose > 1:
      print('Chunk header CRC: {:#x}, calculated CRC: {:#x}'.format(chunk_hdr_crc, crc_hdr_calc))
    if chunk_type == 1:
      chunk_data = args.infile.read(chunk_len - struct.calcsize(chunk_data_crc_format));
      if args.verbose > 2:
        print('Raw header: {}'.format(chunk_hdr))
        print('Raw data: {}'.format(chunk_data))
      crc_data_calc = marvell_crc32(chunk_data)
      chunk_data_crc = struct.unpack(chunk_data_crc_format, args.infile.read(struct.calcsize(chunk_data_crc_format)))[0]
      if args.verbose > 1:
        print('Read {} bytes of chunk data. Chunk CRC: {:#x}, calculated CRC: {:#x}'.format(len(chunk_data), chunk_data_crc, crc_data_calc))
      if chunk_hdr_crc != crc_hdr_calc or chunk_data_crc != crc_data_calc:
        raise ChunkCrcError(chunk_addr)  
    elif chunk_type == 4:
      chunk_data = None
    else:
      raise UnknownChunkTypeError(chunk_type)   
    return (chunk_addr, chunk_data)

def write_chunk(chunk_addr, chunk_data):
  chunk_type = 4 if chunk_data is None else 1
  chunk_len = 0 if chunk_data is None else len(chunk_data) + struct.calcsize(chunk_data_crc_format)
  chunk = struct.pack(chunk_hdr_format, chunk_type, chunk_addr, chunk_len)
  chunk += struct.pack(chunk_hdr_crc_format, marvell_crc32(chunk))
  if args.verbose > 1:
    print('Created chunk header {}, len {} bytes'.format(chunk, len(chunk)))
  if chunk_data is not None:
    chunk += chunk_data
    chunk += struct.pack(chunk_data_crc_format, marvell_crc32(chunk_data))
  if args.verbose > 2:
    print('Created chunk with data {}, len {} bytes'.format(chunk, len(chunk)))
  written = args.outfile.write(chunk)
  if written != len(chunk):
    print('Error writing chunk. chunk length {}, written {}'.format(len(chunk), written)) 
  return written
  
chunk_counter = 0
chunk_list = []
output_bytes = 0
      
while True:
  try:
    chunk_addr, chunk_data = read_chunk()
    if chunk_data is None:
      output_bytes += write_chunk(0, None)
      break
    chunk_counter += 1
    chunk_list.append((chunk_addr, chunk_data))
    output_bytes += write_chunk(chunk_addr, chunk_data)
  except ChunkCrcError as e:
    print('CRC32 Error in chunk {}, address {:#x}'.format(chunk_counter, e.args[0]))
    break
  except UnknownChunkTypeError as e:
    print('Unknown chunk type {}'.format(e.args[0]))
    break
print('Number of chunks: {}'.format(chunk_counter))
print('Bytes written: {}'.format(output_bytes))


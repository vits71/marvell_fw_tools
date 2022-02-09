#!python3

'''
Marvell binary firmware tool
'''

import sys, os, argparse, struct, crcmod, ast
from stat import *

class ChunkCrcError(Exception):
  pass
  
class UnknownChunkTypeError(Exception):
  pass

class ChunkWriteError(Exception):
  pass

def bytes_eval(b):
  return ast.literal_eval(b)

parser = argparse.ArgumentParser(description='Tool for manipulation with Marvell SoC firmware files')
parser.add_argument('-v', '--verbose', action = 'count', default = 0, help='verbose level')
subparsers = parser.add_subparsers(help='sub-command help')
  
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
      print('Created chunk data {}, len {} bytes'.format(chunk_data, len(chunk_data)))
  written = args.outfile.write(chunk)
  if written != len(chunk):
    raise ChunkWriteError(chunk_addr) 
  return written
  
def copy():
  chunk_counter = 0
  output_bytes = 0      
  while chunk_counter < args.count if args.count is not None else True:
    try:
      chunk_addr, chunk_data = read_chunk()
      if chunk_data is None:
        break
      chunk_counter += 1
      output_bytes += write_chunk(chunk_addr, chunk_data)
    except ChunkCrcError as e:
      print('CRC32 Error in chunk {}, address {:#x}'.format(chunk_counter, e.args[0]))
      break
    except UnknownChunkTypeError as e:
      print('Unknown chunk type {}'.format(e.args[0]))
      break
    except ChunkWriteError as e:
      print('Error while writing chunk address {}'.format(e.args[0]))
      break    
  output_bytes += write_chunk(0, None)
  chunk_counter += 1
  print('Number of chunks: {}'.format(chunk_counter))
  print('Bytes written: {}'.format(output_bytes))

parser_copy = subparsers.add_parser('copy', help = 'copy (and verify) firmware file')
parser_copy.add_argument('-c', '--count', type = int, help='number of chunks to copy (excluding last chunk), no count means all chunks')
parser_copy.add_argument('infile', type=argparse.FileType('rb'))
parser_copy.add_argument('outfile', type=argparse.FileType('wb'))
parser_copy.set_defaults(func=copy)

def modify():
  if len(args.address) != len(args.data):
    print('Number of address and data parameters don\'t match')
    return
  chunk_counter = 0
  output_bytes = 0
  modified_bytes = 0      
  while True:
    try:
      chunk_addr, chunk_data = read_chunk()
      if chunk_data is None:
        break
      chunk_range = range(chunk_addr, chunk_addr+len(chunk_data))
      for patch_address in args.address:
        patch_index = args.address.index(patch_address)
        patch_data = args.data[patch_index]
        if patch_address in chunk_range:
          offset1 = patch_address-chunk_addr
          patch_len = len(patch_data)
          if offset1 + patch_len > len(chunk_data):
            patch_len = len(chunk_data)-offset1
            args.data[patch_index] = patch_data[:patch_len] 
            args.address.insert(patch_index+1, chunk_addr + len(chunk_data))
            args.data.insert(patch_index+1, patch_data[patch_len:]) 
            patch_data = args.data[patch_index]
          chunk_data = chunk_data[:offset1]+ patch_data + chunk_data[offset1 + patch_len:]
          if args.verbose > 2:
            print('Patched data {}, at address {:#x}, len {} bytes'.format(patch_data, patch_address, len(patch_data)))
          modified_bytes += patch_len
      output_bytes += write_chunk(chunk_addr, chunk_data)         
    except ChunkCrcError as e:
      print('CRC32 Error in chunk {}, address {:#x}'.format(chunk_counter, e.args[0]))
      break
    except UnknownChunkTypeError as e:
      print('Unknown chunk type {}'.format(e.args[0]))
      break
    except ChunkWriteError as e:
      print('Error while writing chunk address {}'.format(e.args[0]))
      break    
  output_bytes += write_chunk(0, None)
  chunk_counter += 1
  print('Number of chunks: {}'.format(chunk_counter))
  print('Bytes modified: {}'.format(modified_bytes))
  print('Bytes written: {}'.format(output_bytes))
  
  
parser_modify = subparsers.add_parser('modify', help = 'modify and save firmware file')
parser_modify.add_argument('infile', type=argparse.FileType('rb'))
parser_modify.add_argument('outfile', type=argparse.FileType('wb'))
parser_modify.add_argument('-a', '--address', type = lambda x: int(x,0), action='append', required = True, help='modification address start (can use 0x for hex)')
parser_modify.add_argument('-d', '--data', type = lambda x: ast.literal_eval(x), action='append', required = True, help='data to modify as bytearray (use b\'\')')
parser_modify.set_defaults(func=modify)

args = parser.parse_args()
print(args)
args.func()

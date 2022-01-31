#!/usr/bin/python3

'''
Marvell binary firmware tool

written by vit_sembera@trendmicro.com
'''

import sys, os, argparse

parser = argparse.ArgumentParser(description='')
parser.add_argument('-v', '--verbose', action = 'store_true', help='verbose output')
parser.add_argument('-n', '--name', action = 'store_true', help='outputs filename')
parser.add_argument('filename', nargs = '+', help='one or more files')
args = parser.parse_args()


for filename in args.filename:
    statinfo = os.stat(filename)
    if args.name:
      print(filename)
    if S_ISREG(statinfo[ST_MODE]):
      if args.verbose:
        print("Regular file, size = ", statinfo.st_size)
      if statinfo.st_size > 0:
        with open(filename, "rb") as file:
          data = file.read()
          if args.verbose:
            print('Read {} bytes from the file'.format(len(data)))
    else:
      if args.verbose:
        print('Not a regular file')

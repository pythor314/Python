#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import os
import argparse
import hashlib


# listing all the files in the directory, starting from the deepest files
def fnames(path):
	m = []

	for root, dirs, files in os.walk(path, topdown=False):
		for name in files:
			m.append(os.path.join(root, name))
	return m

# splitting data into chunks in order to be able to encrypt/decrypt it (block chaining)
def enc(data,key,iv):
	size = 16	
	offset = 0
	end = False
	en = ''

	while not end:
		chunk = data[offset:offset+size]
		if len(chunk) - size:
			end = True
			chunk += ' ' * (size - len(chunk))

		en += AES.new(key,AES.MODE_CBC,iv).encrypt(chunk)
		offset+=size
	return en

	
def dec(data,key,iv):
	size = 16
	offset = 0
	de = ''

	while offset < len(data):
		chunk = data[offset:offset+size]
		de += AES.new(key,AES.MODE_CBC,iv).decrypt(chunk)
		offset+=size
	return ''.join(de)

# getting the hash of the given file, the files passed to this 
# function are to be excluded from the encryption/decryption process
def get_hash(file):
	op = open(file.decode('utf-8'),'rb')
	content = op.read()
	op.close()
	algo = hashlib.new('sha1')
	algo.update(content)
	hash = algo.hexdigest()
	return hash


def main():

	#getting input from the command-line
	parser = argparse.ArgumentParser()
	parser.add_argument('-m',dest='method',required=True,choices=['enc','dec'],help="method (encrypt or decrypt)")
	parser.add_argument('path')
	args = parser.parse_args()
	method = args.method

	dir = args.path
	dir = dir.lower().replace('/','\\')

	hashes = []

	# excluding this script and the key .txt file (if exists) from 
	# the process, I added this method to avoid corrupting the file
	# tha contains the key in case the script was in the same directory
	# during the process
	try:
		hashes.append(get_hash(b64encode(dir)+'.txt'))
		hashes.append(get_hash(parser.prog))
	except:
		hashes.append(get_hash(parser.prog))


	files = fnames(dir)

	if method == 'enc':
		# generating the key and IV
		k = os.urandom(32)
		i = os.urandom(16)
		
		# ignoring the the files in [hashes]
		try:
			for file in files:
				if get_hash(file) in hashes:
					continue

				# encrypting the file
				print 'encrypting %s ...'%file
				file = file.replace('/','\\')
				fname = file.split('\\')[-1]
				fdir = '\\'.join(file.split('\\')[:-1])
				f = fdir+'\\'+b64encode(fname)

				op = open(file.decode('utf-8'),'rb')
				content = op.read()
				op.close()
				
				op = open(f,'wb')
				op.write(b64encode(enc(content,k,i)))
				op.close()
				os.remove(file)
		except:
			pass

		# creating the key file to store key and IV and giving it
		# the directory path (dir) in base64 as its name
		k64 = b64encode(k)
		i64 = b64encode(i)
		op = open('%s.txt'%b64encode(dir),'w')
		op.write('%s%s'%(k64,i64))
		op.close()

	elif method == 'dec':
		# reading the key and IV from the key file
		op = open('%s.txt'%b64encode(dir),'r')
		k = op.read(44)
		i = op.read(24)
		op.close()

		for file in files:
			if get_hash(file) in hashes:
				continue

			# decrypting the file
			print 'decrypting %s ...'%file
			file = file.replace('/','\\')
			fname = file.split('\\')[-1]
			fdir = '\\'.join(file.split('\\')[:-1])
			f = fdir+'\\'+b64decode(fname)
			
			op = open(file.decode('utf-8'),'rb')
			content = op.read()
			op.close()
			
			op = open(f,'wb')
			op.write(dec(b64decode(content),b64decode(k),b64decode(i)))
			op.close()
			os.remove(file)
			

if __name__ == '__main__':
	main()

#!/usr/bin/env python

from Crypto.Cipher import AES
import random
import base64
import os
import sys


def key():
	key = []
	c = 0

	while c < 32:
		r = random.choice(asci)
		key.append(chr(r))
		c+=1
	return ''.join(key)

def iv():
	key = []
	c = 0

	while c < 16:
		r = random.choice(asci)
		key.append(chr(r))
		c+=1
	return ''.join(key)

def files_names(path):
	m = []

	for root, dirs, files in os.walk(path, topdown=False):
		for name in files:
			m.append(os.path.join(root, name))
	return m

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

		en += (AES.new(key,AES.MODE_CBC,iv)).encrypt(chunk)
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

def main():
	global asci
	asci = xrange(0,256)
	usage = 'Usage: crptr.py <method> <path>\nEx:\n\tcrptr.py -e /home/\n\tcrptr.py -d /home/'

	if len(sys.argv) < 3:
		print usage
		exit()
	try:
		files = files_names(sys.argv[2])
	except:
		print usage
		exit()

	if sys.argv[1] == '-e':
		k = key()
		i = iv()
		op = open('key.txt','w')
		save_k = base64.b64encode(k)
		save_i = base64.b64encode(i)
		op.write('key: %s\niv: %s'%(save_k,save_i))
		for file in files:
			op = open(file,'rb')
			content = op.read()
			op.close()
			print 'encrypting %s ...' %file
			op = open(file,'wb')
			op.write(base64.b64encode(enc(content,k,i)))
			op.close()
	elif sys.argv[1] == '-d':
		k = str(raw_input('key here: '))
		i = str(raw_input('IV here: '))
		for file in files:
			op = open(file,'rb')
			content = op.read()
			op.close()
			print 'decrypting %s ...' %file
			op = open(file,'wb')
			op.write(dec(base64.b64decode(content),base64.b64decode(k),base64.b64decode(i)))
			op.close()
	else:
		print usage

if __name__ == '__main__':
	main()

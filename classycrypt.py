#!/usr/bin/python

import os
from getpass import getpass

class Crypt(object):
	
	def __init__(self, crypt):
		pass
	
	def scramble(self, crypt, block, key):
		
		scrambled = str(block)
		
		for k in key[:50]:
			dist = ord(k)+1
			scrambled = scrambled[-dist*3:-dist*2]+scrambled[-dist:]+scrambled[:-dist*3]+scrambled[-dist*2:-dist]

	def xoring(self, crypt, block, key):
		
		return ''.join(chr(ord(k)^ord(old) for k, old in zip(key, block)))


class Keygen(object):
	
	def __init__(self):
		self.getpwd = getpass(prompt='Please enter your password >> ')
		self.pswd = (self.getpwd*(1024/len(self.getpwd)))[:1024]
	
	def genkey(self, pswd, iv):
		pass

class Stuff(object):
	
	def __init__(self):
		
		self.infile = open(raw_input('Which file do you want to encrypt/decrypt? >> '), 'r')

		self.size = len(self.infile.read())
		self.infile.seek(0)

		filenom = '*** I am encrypted with classycrypt ***\n'
		if self.infile.read(40) == filenom:
			self.crypt = 'decrypt'
		else:
			self.crypt = 'encrypt'
			self.infile.seek(0)

		self.outfile = open(raw_input('Where do you want to store the %sed file? >> ' % self.crypt), 'w')
		self.outfile.write(filenom)

	def pad(self, self.infile, self.outfile, self.size):
	
		padlen = self.size
		self.outfile.write(






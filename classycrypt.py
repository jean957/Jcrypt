#!/usr/bin/python

import os
from getpass import getpass

class Crypto(object):
	
	def __init__(self, key):
		
		self.key = key

	def scramble(self, block):
		
		scrambled = str(block)
		
		for k in self.key[:100]:
			dist = ord(k)+1
			scrambled = scrambled[-dist*3:-dist*2]+scrambled[-dist:]+scrambled[:-dist*3]+scrambled[-dist*2:-dist]
		
		return scrambled

	def unscramble(self, block):
		
		unscrambled = str(block)
		
		for k in reversed(self.key[:100]):
			dist = ord(k)+1
			unscrambled = unscrambled[dist*2:-dist]+unscrambled[:dist]+unscrambled[-dist:]+unscrambled[dist:dist*2]
		
		return unscrambled

	def xoring(self, block):
		
		return ''.join((chr(ord(k)^ord(old)) for k, old in zip(self.key, block)))

	def encycle(self, block):
		
		return self.scramble(self.xoring(block))

	def decycle(self, block):

		return self.xoring(self.unscramble(block))



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
		
		if self.crypt == 'encrypt':
			self.outfile.write(filenom)
		
		self.getpwd = getpass(prompt='Please enter your password >> ')
		self.pswd = (self.getpwd*(1+1024/len(self.getpwd)))[:1024]

	def padfirstblock(self):
	
		currentkey = self.inivector()
		Crypt = Crypto(currentkey)
	
		padlen =  1024-((self.size+2)%1024)
		block = (chr(padlen/256)+chr(padlen%256)+os.urandom(padlen)+self.infile.read(1024-(padlen+2)))[:1024]
		currentkey = Crypt.encycle(block)
		self.outfile.write(Crypt.encycle(currentkey))
		
		return currentkey
		
	
	def depadfirstblock(self):
		
		currentkey = self.inivector()
		Crypt = Crypto(currentkey)
		
		block = self.infile.read(1024)
		currentkey = Crypt.decycle(block)
		block = Crypt.decycle(currentkey)
		
		self.outfile.write(block[2+ord(block[0])*256+ord(block[1]):])
		
		return currentkey
	
	def inivector(self):
		
		Crypt = Crypto(self.pswd)
		
		if self.crypt == 'encrypt':
			
			iv = os.urandom(1024)
			self.outfile.write(iv)

			return Crypt.encycle(Crypt.encycle(iv))
		
		else:
		
			return Crypt.encycle(Crypt.encycle(self.infile.read(1024)))


def main():
	
	Start = Stuff()
	
	if Start.crypt == 'encrypt':
		
		currentkey = Start.padfirstblock()

		while Start.infile.read(1) != '':
			
			Start.infile.seek(Start.infile.tell()-1)
			Crypt = Crypto(currentkey)

			currentkey = Crypt.encycle(Start.infile.read(1024))
			Start.outfile.write(Crypt.encycle(currentkey))
	
	else:
		
		currentkey = Start.depadfirstblock()
		
		for i in range(Start.size/1024-1):
			
			Crypt = Crypto(currentkey)
			
			currentkey = Crypt.decycle(Start.infile.read(1024))
			Start.outfile.write(Crypt.decycle(currentkey))

main()



	






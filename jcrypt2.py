#!/usr/bin/python

''' 
Jcrypt Version 2.0

Jcrypt2 is a learning project and not intended for the secure encryption of sensitive data.

Requirements:  Linux, Python 2.7, Python hashlib

Jcrypt2 is started from the commandline. ( >> python jcrypt2.py)
first line is path to the input file. ( >> /home/user/infilename)
second line is path to the output file. ( >> /home/user/outfilename)
third line is the secret user password ( >> ***pwd***)
and that's it. Jcrypt2 will automatically recognize if a file is encrypted or plaintext.

Jcrypt2 will only work on files, to encrypt a folder, you have to archive it first,
to encrypt a message, you have to write it into a file first.

It's a symmetric cypher and supposed to be CPA secure.
The encryption will create a 15 byte random initialisation vector.
The user password will be hashed (50k times) with the iv as salt to a length of 1024 byte
and then be used as the key for the first block.
The first block will be padded with random numbers to increase the size of the file to a multiple 
of 1024 byte (with the first two byte of the padding will declare the length of the padding).
Every block is xored with the current key, then the positions of the bytes will be scrambled 
to create the key for the next block, then xored and scrambled once more before the data is 
written to the output file.
'''

# Improvements:
# Get better names for Stuff() and Crypto()
# Get a 'safe' encryption where everything happens twice with an offset of 512 byte
# Write better tests
# Using getpass() interferes with testing...
# Make GUI ( TKinter? )
# Create Windows.exe



import os
import hashlib


class Crypto(object):
	
	''' This class has the algorithms for the actual encryption and decryption process.
	A new instance, with the current key will be created for every block.'''
	
	def __init__(self, key):
		
		self.key = key

	def scramble(self, block):
		
		''' 
		(Encryption) Returns a scrambled string of the input block
		'''

		for k in self.key[:100]:
			dist = ord(k)+1
			block = block[-dist*3:-dist*2]+block[-dist:]+block[:-dist*3]+block[-dist*2:-dist]
		
		return block

	def unscramble(self, block):
		
		''' (Decryption) Returns the unscrambled input block'''

		for k in reversed(self.key[:100]):
			dist = ord(k)+1
			block = block[dist*2:-dist]+block[:dist]+block[-dist:]+block[dist:dist*2]
		
		return block

	def xoring(self, block):
		
		''' This function returns xor of the current key and the input block'''
		
		return ''.join((chr(ord(k)^ord(old)) for k, old in zip(self.key, block)))

	def encycle(self, block):
		
		''' (Encryption) Returns one encryption cycle of xoring and scrambling'''

		return self.scramble(self.xoring(block))

	def decycle(self, block):

		''' (Decryption) Returns one decryption cycle of unscrambling and xoring'''

		return self.xoring(self.unscramble(block))

class Stuff(object):

	''' Stuff() contains most functions that are not directly part of the encryption algorithm.
	When it is initialized, it asks the user for the inputfile, outputfile and password 
	and determines whether the file is intended for encryption or decryption'''

	def __init__(self):
		
		self.infile = open(raw_input('Which file do you want to encrypt/decrypt? >> '), 'r')
		self.outfile = open(raw_input('Where do you want to store the output file? >> '), 'w')
		
		self.size = len(self.infile.read())
		self.infile.seek(0)

		filenom = '*** I am encrypted with Jcrypt2 ***\n'
		
		if self.infile.read(len(filenom)) == filenom:
			self.encrypt = 0
		else:
			self.encrypt = 1
			self.infile.seek(0)
		
		if self.encrypt:
			self.outfile.write(filenom)
		
		self.pswd = raw_input('Please enter your password >> ')

	def padfirstblock(self):
	
		''' (Encryption) This function determines the length of the padding, 
		writes the first encrypted block to the outfile and returns the key for the next block.'''

		currentkey = self.inivector()
		Crypt = Crypto(currentkey)
	
		padlen =  1024-((self.size+2)%1024)
		block = (chr(padlen/256)+chr(padlen%256)+os.urandom(padlen)+self.infile.read(1024-(padlen+2)))[:1024]
		currentkey = Crypt.encycle(block)
		self.outfile.write(Crypt.encycle(currentkey))
		
		return currentkey
	
	def depadfirstblock(self):
		
		''' (Decryption) Writes the first block without padding to the outfile and returns the key for the next block.'''

		currentkey = self.inivector()
		Crypt = Crypto(currentkey)
		
		block = self.infile.read(1024)
		currentkey = Crypt.decycle(block)
		block = Crypt.decycle(currentkey)
		
		self.outfile.write(block[2+ord(block[0])*256+ord(block[1]):])
		
		return currentkey
	
	def inivector(self):
		
		''' Creates and writes, or reads the initialization vector to/from the infile/outfile and returns the first key.'''

		if self.encrypt:
			
			iv = os.urandom(15)
			self.outfile.write(iv)
		
		else:
		
			iv = self.infile.read(15)
		
		return hashlib.pbkdf2_hmac('sha512', self.pswd, iv, 50000, 1024)

def main():
	
	''' The main function.'''

	Start = Stuff()
	
	if Start.encrypt:
		
		currentkey = Start.padfirstblock()

		while Start.infile.read(1) != '':
			
			Start.infile.seek(Start.infile.tell()-1)
			Crypt = Crypto(currentkey)

			currentkey = Crypt.encycle(Start.infile.read(1024))
			Start.outfile.write(Crypt.encycle(currentkey))
	
	else:
		
		currentkey = Start.depadfirstblock()
		
		for i in range(Start.size/1024):
			
			Crypt = Crypto(currentkey)
			
			currentkey = Crypt.decycle(Start.infile.read(1024))
			Start.outfile.write(Crypt.decycle(currentkey))


# main()

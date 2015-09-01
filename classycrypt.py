#!/usr/bin/python

''' 
Jcrypt Version 2.0

Jcrypt2 is a learning project and not intended for the secure encryption of sensitive data.

Jcrypt2 is started from the commandline. ( >> python jcrypt2.py)
first line is path to the input file. ( >> /home/user/infilename)
second line is path to the output file. ( >> /home/user/outfilename)
third line is the secret user password ( >> ***pwd***)
and that's it.

Jcrypt2 will only work on files, to encrypt a folder, then you have to use a program like zip first.

It's a symmetric cypher and supposed to be CPA secure.
The encryption will create a 1024 byte random initialisation vector.
Then pad the first block with random data to increase the filesize to a multiple of 1024 bytes (the first two byte of the padding will declare the length of the padding).
Every block, is xored with the current key, then the positions of the bytes will be scrambled to create the key for the next block,
then xored and scrambled once more before the data is written to the output file.
To get the key for the (padded) first block, the initialisation vector is xored and scrambled thrice with the cycled user password.
'''

# Improvements:
# Start with a one line summary, seperated by one line for multiline docstrings
# Get better names for Stuff() and Crypto()
# Max 100 letters/line
# Switch 'encrypt', 'decrypt' to 0, 1
# Get a 'safe' encryption where everything happens twice with an offset of 512 byte



import os
from getpass import getpass


class Crypto(object):
	
	''' This class has the algorithms for the actual encryption and decryption process.
	A new instance, with the current key has to be created for every block.'''
	
	def __init__(self, key):
		
		self.key = key

	def scramble(self, block):
		
		''' (Encryption) Returns a scrambled string of the input block'''

		
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
	When it is initialized, it asks the user for the inputfile, outputfile and password and determines if the file is intended for encryption or decryption'''


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
	
		''' (Encryption) This function determines the length of the padding, writes the first encrypted block to the outfile and returns the key for the next block.'''

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

		Crypt = Crypto(self.pswd)
		
		if self.crypt == 'encrypt':
			
			iv = os.urandom(1024)
			self.outfile.write(iv)
		
		else:
		
			iv = self.infile.read(1024)
		
		return Crypt.encycle(Crypt.encycle(Crypt.encycle(iv)))

def main():
	
	''' The main function.'''

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



	






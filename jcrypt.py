#!/usr/bin/python

#		*** Version 1.7.4 ***

# This should work to encrypt and decrypt arbitrary data.
# It generates random passwords and encrypts them with a vigenere cypher.
# It uses keys of lengths 4, 11, 13, 17, 18, 19 / their lowest common multiple is 1662804
# It uses keys of lengths 7, 8, 9 Their lowest common multiple is 504
# Use: python ./jcrypt.py

# Potential improvements:
#	- numpy for speedup
#	- get GUI  -  Tkinter to show progressbar in it's own window
#	- functionize everything
#	- make jcrypt more efficient for small files by using a different mode for files with < 1 mb

# 0 <= char <= 255 ( = 256 characters) / 32 <= ASCII <= 126 ( = 95 characters)

from os import urandom
import easygui as gui
import sys


def outname(infile, crypt):		# determine the name for the outputfile
	if crypt == 'encrypt':
		return '%s.jcrypt' % infile		# for encryption, just append '.jcrypt' to the filename
	else:
		infilelist = []
		for i in infile:
			infilelist.append(i)				# make a list of letters of the name of the infile
		myextension = []
		for i in '.jcrypt':
			myextension.append(i)
		for i in range(7):
			if myextension.pop(-1) != infilelist.pop(-1):			# if it's encrypted but not 'something.jcrypt' return 'decrypted*filename'
				return 'decrypted%s' % infile
		outfile = ''.join(infilelist)
		try:
			outf = open(outfile, 'r')					# if a file with the standardname for the outfile exists
			outf.close()
			if gui.boolbox(msg='There is already a file called %s do you want to replace it?' % outfile, title='Replace File', choices=('No', 'Yes')):		# ask the user if she wants to replace it
				return gui.filesavebox(msg='', title='Save')
			else:
				return outfile
		except:
			return outfile

def encrypt(pwdlist, txt, newtxt, basekey, extrakey, count):		# ---- ENCRYPTION -----

	charlist, key3 = [], []

	for val in range(4):			# generate 3rd key
		key3.append(ord(urandom(1)))

	for i, val in enumerate(key3):					# append the key to the output / encrypted with the extra key
		charlist.append((val+basekey[(i+count*3)%len(basekey)])%256)

	for i, val in enumerate(extrakey):			# change extrakey
		extrakey[i] += key3[i%4]

	for i, val in enumerate(txt.read(1662804)):		# make a list of numbers from the text and encrypt them with the keys
		charlist.append((ord(val) + basekey[i] + extrakey[(i+count*108)%504])%256)

	newbase = []
	if count != 0 and count % 10 == 0:
		for i in range(10 + (pwdlist[(count/10)%len(pwdlist)]%15)):
			newbase.append(ord(urandom(1)))
		for i, val in enumerate(newbase):
			charlist.append((val+basekey[i+1])%256)

		newblen = len(newbase)
		for i in range(len(basekey)):
			basekey[i] += newbase[i%newblen]

	for i, val in enumerate(charlist):			# shift content for the outputfile back to chars
		charlist[i] = chr(val)

	newtxt.write(''.join(charlist))			# write everything to the outfile



def decrypt(pwdlist, txt, newtxt, basekey, extrakey, count):			#   ----- DECRYPTION ------

	charlist, key3 = [], []

	for i in range(4):			# determine key and remove it from the encrypted message
		key3.append((ord(txt.read(1))-basekey[(i+count*3)%len(basekey)])%256)

	for i, val in enumerate(extrakey):
		extrakey[i] += key3[i%4]

	for i, val in enumerate(txt.read(1662804)):				# make a list of decrypted characters (as numbers)
		charlist.append((ord(val)-(basekey[i]+extrakey[(i+count*108)%504]))%256)

	for i, val in enumerate(charlist):			# shift content for the outputfile back to chars
		charlist[i] = chr(val)

	newbase = []
	if count != 0 and count % 10 == 0:
		for i in range(10 + (pwdlist[(count/10)%len(pwdlist)]%15)):
			newbase.append((ord(txt.read(1))-basekey[i+1])%256)

		newblen = len(newbase)
		for i in range(len(basekey)):
			basekey[i] += newbase[i%newblen]

	newtxt.write(''.join(charlist))			# write everything to the outfile




def createstuff(pwdlist, newtxt):				# ---- OBSCURING START OF THE ENCRYPTED FILE AND APPEND KEYLIST ----

	pwdlength =  len(pwdlist)
	
	newtxt.write(' *** This is encrypted with jcrypt *** \n\n')		# add identifier to the beginning of the encrypted file

	keylist = []
	for i in range(125+(sum(pwdlist)-(pwdlength*32))%50):
		keylist.append(ord(urandom(1)))

	for i, val in enumerate(keylist):
		newtxt.write(chr((val+pwdlist[i%pwdlength])%256))		# write keys to the beginning of the encrypted file

	return keylist


def removestuff(pwdlist, txt):			#   ---- UNOBSCURE START OF THE ENCRYPTED FILE AND EXTRACT KEYLIST ----

	pwdlength = len(pwdlist)

	keylist = []
	for i in range(125+(sum(pwdlist)-(pwdlength*32))%50):
		keylist.append((ord(txt.read(1))-pwdlist[i%pwdlength])%256)

	return keylist


def progressbar(txt, textlength):			#   ---- CREATE A PROGRESSBAR ----
	progress = []
	for i in range(1, 11):
		if txt.tell() >= i*textlength/10:		# make progressbar and return it
			progress.append('X')
		else:
			progress.append(' ')
	
	return '{'+''.join(progress)+'}'


def analyze(infile, txt):				# ---- ANALYZE BASICS LIKE INPUTLENGTH AND WHETHER THE FILE IS ENCRYPTED ----
	txt.read()				# determine inputlength, then rewind
	textlength = txt.tell()
	txt.seek(0)

	if txt.read(39) == ' *** This is encrypted with jcrypt *** ':		# determine whether the file is encrypted or plaintext
		crypt = 'decrypt'
		txt.read(2)					# read over the newlines
	else:
		crypt = 'encrypt'
		txt.seek(0)							# reset the cursor in the infile
	
	return textlength, crypt, outname(infile, crypt)

def getpwd(crypt):			# ---- GET USERPASSWORD ----
	if crypt == 'encrypt':
		pwd = ''
		while len(pwd) < 3:
			pwd = gui.passwordbox(msg='Please enter a password with at least 3 characters.\nMixing lowercase and uppercase letters, numbers and special characters is recommended.', title='Password')
	else:
		pwd = gui.passwordbox(msg='Please enter your password', title='Password')

	pwdlist = []
	for char in pwd:					# create a list of numbers from the password
		pwdlist.append(ord(char))
	return pwdlist


def mkkeys(pwdlist, keylist):			# ---- CREATE THE BASE AND EXTRAKEY FROM THE KEYLIST ----

	key1, key2, key3, key4, key5, key6, key7, key8 = [], [], [], [], [], [], [], []
	basekey, extrakey = [], []
	count = 0
	for i in range(11):
		key1.append(keylist.pop(pwdlist[count%len(pwdlist)]%len(keylist)))
		count += 1
	for i in range(13):
		key2.append(keylist.pop(pwdlist[count%len(pwdlist)]%len(keylist)))
		count += 1
	for i in range(17):
		key3.append(keylist.pop(pwdlist[count%len(pwdlist)]%len(keylist)))
		count += 1
	for i in range(18):
		key4.append(keylist.pop(pwdlist[count%len(pwdlist)]%len(keylist)))
		count += 1
	for i in range(19):
		key5.append(keylist.pop(pwdlist[count%len(pwdlist)]%len(keylist)))
		count += 1
	for i in range(7):
		key6.append(keylist.pop(pwdlist[count%len(pwdlist)]%len(keylist)))
		count += 1
	for i in range(8):
		key7.append(keylist.pop(pwdlist[count%len(pwdlist)]%len(keylist)))
		count += 1
	for i in range(9):
		key8.append(keylist.pop(pwdlist[count%len(pwdlist)]%len(keylist)))
		count += 1

	for i in range(1662804):
		basekey.append((key1[i%11]+key2[i%13]+key3[i%17]+key4[i%18]+key5[i%19])%256)
	
	for i in range(504):
		extrakey.append((key6[i%7]+key7[i%8]+key8[i%9])%256)

	return basekey, extrakey


#			*** THIS IS THE CODE THAT IS RUN ***

infile = gui.fileopenbox(msg='Choose a File for encryption or decryption', title='Filechoice')

txt = open(infile, 'r')			# open infile and save it as txt'

textlength, crypt, outfile = analyze(infile, txt)

pwdlist = getpwd(crypt)

newtxt = open(outfile, 'w')				# create or empty outfile and save it as newtxt
newtxt.close()
newtxt = open(outfile, 'r+')

if crypt == 'encrypt':				# ENCRYPTION

	keylist = createstuff(pwdlist, newtxt)			# append stuff and keys to the beginning of the file.

	basekey, extrakey = mkkeys(pwdlist, keylist)

	count = 0

	while txt.read(1) != '':
		txt.seek(txt.tell()-1)
		encrypt(pwdlist, txt, newtxt, basekey, extrakey, count)
		count += 1
		if textlength > 6*10**6:
			print '\r', progressbar(txt, textlength), 
			print 'jcrypt is about %d%% done with the %sion (%d of %d mb)' % ((100*txt.tell())/textlength, crypt, txt.tell()/10**6, textlength/10**6),
			sys.stdout.flush()				# for some reason it won't always print without this

	newtxt.write(urandom(basekey[5]))		# obscure end of the encrypted file
	print '\n'

if crypt == 'decrypt':				# DECRYPTION

	keylist = removestuff(pwdlist, txt)		# remove stuff from the beginning and extract keys

	basekey, extrakey = mkkeys(pwdlist, keylist)

	count = 0

	while txt.read(1) != '':
		txt.seek(txt.tell()-1)
		if txt.tell() >= textlength - basekey[5]:		# if there is less stuff in the file than is appended at the end
			newtxt.write(txt.read())							# just append it and quit decryption
			break
		decrypt(pwdlist, txt, newtxt, basekey, extrakey, count)
		count += 1
		if textlength > 6*10**6:
			print '\r', progressbar(txt, textlength), 
			print 'jcrypt is about %d%% done with the %sion (%d of %d mb)' % ((100*txt.tell())/textlength, crypt, txt.tell()/10**6, textlength/10**6),
			sys.stdout.flush()				# for some reason it won't print always without this

	newtxt.seek(newtxt.tell()-basekey[5])		# delete additional stuff at the end of the file
	newtxt.truncate()
	
	print '\n'


newtxt.close()						# close outputfile
txt.close()							# close inputfile

print 'The %sion was successful, you should now see the %sed file %s' % (crypt, crypt, outfile)


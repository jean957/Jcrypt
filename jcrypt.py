#		*** Version 1.5.5 ***

# This should work to encrypt and decrypt arbitrary data.
# It generates random passwords and encrypts them with a vigenere cypher.
# It uses 3 passwords of lengths 5, 499, 501 / their lowest common multiple is 1249995
# Use: python ./jcrypt.py

# Potential improvements:
#	- numpy
#	- get GUI  -  easygui?
#	- very inefficient for small files


# 0 <= char <= 255 ( = 256 characters) / 32 <= ASCII <= 126 ( = 95 characters)

from os import urandom
from getpass import getpass
import easygui as gui
import sys




def outname(infile, crypt):			# determine the name for the outputfile
	if crypt == 'encrypt':
		return '%s.jcrypt' % infile				# for encryption, just append '.jcrypt' to the filename
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
			if gui.boolbox(msg='There is already a file called %s do you want to replace it?' % outfile, title='Replace File', choices=('No', 'Yes')):							# ask the user if she wants to replace it
				return gui.filesavebox(msg='', title='Save')
			else:
				return outfile
		except:
			return outfile

def encrypt(pwdlist, txt, newtxt, key1, key2):		# ---- ENCRYPTION -----

	charlist, key3 = [], []

	text = txt.read(1249995)				# read 1249995 chars from input

	for val in range(5):			# generate 3rd key
		key3.append(ord(urandom(1)))

	for i, val in enumerate(key3):					# append the key to the output / encrypted as vigenere with the second key
		charlist.append((val+key2[i])%256)

	for i, val in enumerate(text):		# make a list of numbers from the text and shift them by the value of the corresponding part of the key
		charlist.append((ord(val) + key1[i%501] + key2[i%499] + key3[i%5])%256)

	for i, val in enumerate(charlist):			# shift content for the outputfile back to chars
		charlist[i] = chr(val)

	newtxt.write(''.join(charlist))			# write everything to the outfile



def decrypt(pwdlist, txt, newtxt, key1, key2):			#   ----- DECRYPTION ------

	charlist, key3 = [], []

	for i in range(5):			# determine key and remove it from the encrypted message
		key3.append((ord(txt.read(1))-key2[i])%256)

	for val in txt.read(1249995):				# make a list of characters (as numbers) to decrypt
		charlist.append(ord(val))

	for i, val in enumerate(charlist):		# decrypt the message
		charlist[i] = (((charlist[i] - key1[i%501]) - key2[i%499]) - key3[i%5])%256

	for i, val in enumerate(charlist):			# shift content for the outputfile back to chars
		charlist[i] = chr(val)

	newtxt.write(''.join(charlist))			# write everything to the outfile



def createstuff(pwdlist, newtxt, key1, key2):				# ---- OBSCURING START OF THE ENCRYPTED FILE and append keys ----

	keys, pwdlength = [], len(pwdlist)
	key1count, key2count, pswrd = 0, 0, 0

	newtxt.write(' *** This is encrypted with jcrypt *** \n\n')
	newtxt.write(urandom(sum(pwdlist)-32*pwdlength))				# add identifier and stuff to the beginning of the encrypted file

	while key1count != 501 and key2count != 499:
		for i in range(pwdlist[pswrd%pwdlength]-31):
			if key1count == 501:
				break
			keys.append(key1[key1count]+pwdlist[i%pwdlength])	# mix key1, key2 and random numbers and append them to the file
			key1count += 1
		pswrd += 1
		keys.append(ord(urandom(1)))
		for i in range(pwdlist[pswrd%pwdlength]-31):
			if key2count == 499:
				break
			keys.append(key2[key2count]+pwdlist[i%pwdlength])
			key2count += 1
		pswrd += 1
		keys.append(ord(urandom(1)))
		if pwdlength % 2 == 0 and pswrd % pwdlength == 0:			# keylength is even: avoid simple repetition
			pswrd -= 3

	for i, val in enumerate(keys):
		keys[i] = chr((val+pwdlist[-i%pwdlength])%256)				# shift the numbers back to characters

	newtxt.write(''.join(keys))		# write keys to the beginning of the encrypted file
	newtxt.write(urandom(pwdlist[-1]-32))


def findkeypwd(txt, pwdlist):
	return pwdlist[-((txt.tell()-(42+sum(pwdlist)-32*len(pwdlist)))%len(pwdlist))]			# 


def removestuff(pwdlist, txt):			#   ---- UNOBSCURE START OF THE ENCRYPTED FILE and extract keys ----

	key1, key2, pwdlength = [], [], len(pwdlist)
	key1count, key2count, pswrd = 0, 0, 0

	txt.read(sum(pwdlist)-32*pwdlength)			# remove first stuff

	while key1count != 501 and key2count != 499:
		for i in range(pwdlist[pswrd%pwdlength]-31):		# extract keys and read over stuff in the encrypted file
			if key1count == 501:
				break
			key1.append(((ord(txt.read(1))-pwdlist[i%pwdlength])-findkeypwd(txt, pwdlist))%256)
			key1count += 1
		pswrd += 1
		txt.read(1)
		for i in range(pwdlist[pswrd%pwdlength]-31):
			if key2count == 499:
				break
			key2.append(((ord(txt.read(1))-pwdlist[i%pwdlength])-findkeypwd(txt, pwdlist))%256)
			key2count += 1
		pswrd += 1
		txt.read(1)
		if pwdlength % 2 == 0 and pswrd % pwdlength == 0:
			pswrd -= 3

	txt.read(pwdlist[-1]-32)

	return key1, key2					# return keys


def generatekeys():
	key1, key2 = [], []

	for val in range(501):		# generate keys
		key1.append(ord(urandom(1)))
		key2.append(ord(urandom(1)))
	key2.pop()
	key2.pop()
	
	return key1, key2


def progressbar(txt, textlength):
	progress = []
	for i in range(1, 11):
		if txt.tell() >= i*textlength/10:		# make progressbar and return it
			progress.append('X')
		else:
			progress.append(' ')
	
	return '{'+''.join(progress)+'}'



#			*** THIS IS THE CODE THAT IS RUN ***

infile = gui.fileopenbox(msg='Choose a File for encryption or decryption', title='Filechoice')

txt = open(infile, 'r')			# open infile and save it as txt'

txt.read()				# determine inputlength, then rewind
textlength = txt.tell()
txt.seek(0)

if txt.read(39) == ' *** This is encrypted with jcrypt *** ':		# determine whether the file is encrypted or plaintext
	crypt = 'decrypt'
	txt.read(2)					# read over the newlines
else:
	crypt = 'encrypt'
	txt.seek(0)							# reset the cursor in the infile

if crypt == 'encrypt':
	pwd = ''
	while len(pwd) < 3:
		pwd = gui.passwordbox(msg='Please enter a password with at least 3 characters.\nMixing lowercase and uppercase letters, numbers and special characters is recommended.', title='Password')
else:
	pwd = gui.passwordbox(msg='Please enter your password', title='Password')

pwdlist = []
for char in pwd:					# create a list of numbers from the password
	pwdlist.append(ord(char))

outfile = outname(infile, crypt)
newtxt = open(outfile, 'w')				# create or empty outfile and save it as newtxt
newtxt.close()
newtxt = open(outfile, 'r+')

if crypt == 'encrypt':				# ENCRYPTION

	key1, key2 = generatekeys()

	createstuff(pwdlist, newtxt, key1, key2)			# append stuff and keys to the beginning of the file.

	while txt.read(1) != '':
		txt.seek(txt.tell()-1)
		encrypt(pwdlist, txt, newtxt, key1, key2)
		if textlength > 6*10**6:
			print '\r', progressbar(txt, textlength), 
			print 'jcrypt is about %d%% done with the %sion (%d of %d mb)' % ((100*txt.tell())/textlength, crypt, txt.tell()/10**6, textlength/10**6),
			sys.stdout.flush()				# for some reason it won't print always without this

	newtxt.write(urandom(key1[0]+key2[0]))		# obscure end of the encrypted file
	print '\n'

elif crypt == 'decrypt':				# DECRYPTION

	key1, key2 = removestuff(pwdlist, txt)		# remove stuff from the beginning and extract keys

	while txt.read(1) != '':
		txt.seek(txt.tell()-1)
		if txt.tell() >= textlength - (key1[0]+key2[0]):		# if there is less stuff in the file than is appended at the end
			newtxt.write(txt.read())							# just append it and quit decryption
			break
		decrypt(pwdlist, txt, newtxt, key1, key2)
		if textlength > 6*10**6:
			print '\r', progressbar(txt, textlength), 
			print 'jcrypt is about %d%% done with the %sion (%d of %d mb)' % ((100*txt.tell())/textlength, crypt, txt.tell()/10**6, textlength/10**6),
			sys.stdout.flush()				# for some reason it won't print always without this

	newtxt.seek(newtxt.tell()-(key1[0]+key2[0]))		# delete additional stuff at the end of the file
	newtxt.truncate()
	
	print '\n'
		

newtxt.close()						# close outputfile
txt.close()							# close inputfile

print 'The %sion was successful, you should now see the %sed file %s' % (crypt, crypt, outfile)



#!/usr/bin/python

''' 
Testing jcrypt2

Use: 
>> comment out main() in last line of jcrypt2.py
>> ./tests2.py < tests2.inp
'''

from jcrypt2 import *
import os


key = ''.join(x for x in os.urandom(1024))
text = ''.join(chr(x%256) for x in range(10000))
block = text[:1024]

'''
print key
print text
'''

C = Crypto(key)
print 'scrambling:',
print block == C.unscramble(C.scramble(block))
#print 'scrambled:', C.scramble(block)
print 'xoring: key with itself:', C.xoring(key),
#print 'text:', C.xoring(block)
print C.xoring(C.xoring(block)) == block
print '\nx == Encycle(Decycle(x)):', C.encycle(C.decycle(block)) == block
print 'x == Decycle(Encycle(x)):', C.decycle(C.encycle(block)) == block

print '\ncreating testfile'
plain = open('plaintemp', 'w')
plain.write(os.urandom(10000))
plain.close()
main()
print '\ntestfile encrypted'
main()
print '\ntestfile decrypted'
print 'Plaintext is equal to Decrypted(Encrypted()):', 
print open('plaintemp', 'r').read() == open('dectemp', 'r').read()
os.system('rm plaintemp enctemp dectemp')

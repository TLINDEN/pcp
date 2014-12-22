#!/usr/local/bin/python

from pypcp import *
from pprint import pprint

# import secret key
zbobsec = open("../../tests/key-bobby-sec", "r").read()
bobsec = Key(encoded=zbobsec, passphrase="b")
#bobsec.dump()

# import public key
zalipub = open("../../tests/key-alicia-pub", "r").read()
alipub = PublicKey(encoded=zalipub)
#alipub.dump()

# always required
ctx = Context()

# symmetric encryption (self mode)
sencrypted = ctx.encrypt(string="hello world", passphrase="x", armor=True)
print sencrypted

# asymmetric encryption bob => alice
ctx.addkey(bobsec)
ctx.recipients(alipub)
aencrypted = ctx.encrypt(string="hello world", armor=True, sign=False)
#print aencrypted

sclear = ctx.decrypt(string=sencrypted, passphrase="x")
print sclear

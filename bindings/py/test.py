#!/usr/local/bin/python

from pypcp import *
from pprint import pprint

zbobsec = open("../../tests/key-bobby-sec", "r").read()

bobsec = Key(encoded=zbobsec, passphrase="b")
#bobsec.dump()

zalipub = open("../../tests/key-alicia-pub", "r").read()
alipub = PublicKey(encoded=zalipub)
#alipub.dump()

ctx = Context()

encrypted = ctx.encrypt(string="hello world", passphrase="x")

ctx.addkey(bobsec)
ctx.recipients(alipub)
encrypted = ctx.encrypt(string="hello world")


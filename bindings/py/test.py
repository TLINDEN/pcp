#!/usr/local/bin/python

from sys import argv, stdout
from pypcp import *
from pprint import pprint

orig = "hello world"


def importkey(filename, passwd=None, secret=True, public=False):
    raw = open(filename, "r").read()
    if secret and not public:
        key = Key(encoded=raw, passphrase=passwd)
        return key
    else:
        key = PublicKey(encoded=raw)
        return key

def asym():
    # import keys
    bobSec = importkey("../../tests/key-bobby-sec", "b")
    bobPub = importkey("../../tests/key-bobby-pub", public=True)
    aliSec = importkey("../../tests/key-alicia-sec", "a")
    aliPub = importkey("../../tests/key-alicia-pub", public=True)

    # one context for each
    ctxA = Context()
    ctxB = Context()

    # prepare ctx' for crypto
    ctxA.addkey(aliSec)
    ctxA.recipients(bobPub)

    ctxB.addkey(bobSec)
    ctxB.recipients(aliPub)

    # Alice encrypt => Bob
    # FIXME: if passed as is, then it's empty later on
    encrypted = ctxA.encrypt(source="%s" % orig, armor=True)
    #print "encrypted:\n%s" % encrypted

    # Bob decrypt from Alice
    clear = ctxB.decrypt(source=encrypted)
    #print "clear: %s" % clear

    if clear == orig:
        return True
    else:
        return False


def sym():
    # always required
    ctx = Context()

    # symmetric encryption (self mode)
    encrypted = ctx.encrypt(source="%s" % orig, passphrase="x", armor=True)
    
    # decrypt
    clear = ctx.decrypt(source=encrypted, passphrase="x")
    
    if clear == orig:
        return True
    else:
        return False



def defun(name):
    if not globals()[name]():
        print "%s: failed" % name
        exit(1)
    else:
        print "%s: ok" % name
        return True


if len(argv) == 2:
    if defun(argv[1]):
        exit(0)
else:
    # execute all
    for func in ["asym", "sym"]:
        defun(func)
    exit(0)





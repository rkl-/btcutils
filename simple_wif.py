#!/usr/bin/env python

import sys
import hashlib
import base58

if len(sys.argv) < 2:
	raise Exception("invalid parameter")

passphrase = sys.argv[1]

# step 1
h1 = hashlib.sha256()
h1.update(passphrase)

# step 2
h1 = "\x80" + h1.digest()

# step 3
h2 = hashlib.sha256()
h2.update(h1)
h2 = h2.digest()

# step 4
h3 = hashlib.sha256()
h3.update(h2)
h3 = h3.digest()

# step 5
chksum = h3[:4]

# step 6
h4 = h1 + chksum

# step 7
prvKey = base58.b58encode(h4)
print prvKey

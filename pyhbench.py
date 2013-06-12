#!/usr/bin/python

# Author: Christophe Monniez <christophe.monniez@fccu.be>
# License: GPL-3 (see COPYING)

import os
import multiprocessing
import Crypto.Hash.RIPEMD
import Crypto.Hash.MD5
import hashlib
import time
import sys

POISONPILL = "!! A poison pill !!"
MAXPROC = multiprocessing.cpu_count() - 1

class HDuration(object):
    def __init__(self,hname,filename,hexdump,duration):
        self.hname = hname
        self.filename = filename
        self.hexdump = hexdump
        self.duration = duration

    def __repr__(self):
        x = "%s - %s -%s -%f" % (self.hname, self.filename, self.hexdump, self.duration)
        return x

class GenericH(object):
    def __init__(self):
        self.duration = 0

    def update(self,data):
        t = time.time()
        self.h.update(data)
        self.duration += (time.time() - t)

    def hexdump(self):
        return self.h.hexdigest()

class CryptoRipe(GenericH):
    def __init__(self):
        self.duration = 0
        self.startTime = time.time()
        self.h = Crypto.Hash.RIPEMD.new()

class CryptoMd5(GenericH):
    def __init__(self):
        self.duration = 0
        self.startTime = time.time()
        self.h = Crypto.Hash.MD5.new()

class HlibMd5(GenericH):
    def __init__(self):
        self.duration = 0
        self.startTime = time.time()
        self.h = hashlib.md5()

class HlibSha1(GenericH):
    def __init__(self):
        self.duration = 0
        self.startTime = time.time()
        self.h = hashlib.sha1()

class HlibSha224(GenericH):
    def __init__(self):
        self.duration = 0
        self.startTime = time.time()
        self.h = hashlib.sha224()

class HlibSha384(GenericH):
    def __init__(self):
        self.duration = 0
        self.startTime = time.time()
        self.h = hashlib.sha384()

class HlibSha256(GenericH):
    def __init__(self):
        self.duration = 0
        self.startTime = time.time()
        self.h = hashlib.sha256()

class HlibSha512(GenericH):
    def __init__(self):
        self.duration = 0
        self.startTime = time.time()
        self.h = hashlib.sha512()

def mdhash(f):
    hobjects = {
        "Crypto RipeMD" : CryptoRipe(),\
        "Crypto MD5" : CryptoMd5(),\
        "Hashlib Md5" : HlibMd5(),\
        "Hashlib sha1" : HlibSha1(),\
        "Hashlib sha256" : HlibSha256(),\
        "Hashlib sha512" : HlibSha512(),\
        "Hashlib sha224" : HlibSha224(),\
        "Hashlib sha384" : HlibSha384(),\
    }

    try:
        fichier = open(f,'r')
    except:
        print "Error, cannot read file '%s'" % f
    finally:
        while 1:
            try:
                data = fichier.read(4096)
            except:
                break
            if len(data) == 0:
                break
            for h in hobjects.values():
                h.update(data)
    return(hobjects)

def walking(basedir,fileQueue):
    for rootdir,dirs,files in os.walk(basedir):
        for f in files:
            fullpath = os.path.join(rootdir,f)
            fileQueue.put(fullpath)
    for i in range(MAXPROC):
        fileQueue.put(POISONPILL)

def hashing(fileQueue,resultQueue):
    while 1:
        fullpath = fileQueue.get()
        if fullpath == POISONPILL:
            break
        hobjects = mdhash(fullpath)
        for hname,h in hobjects.iteritems():
            hduration = HDuration(hname,fullpath,h.hexdump(),h.duration)
            resultQueue.put(hduration)

def resulting(resultQueue):
    durations = {}
    while 1:
        r = resultQueue.get()
        if r == POISONPILL:
            break
        if r.hname not in durations:
            durations[r.hname] = r.duration
        else:
            durations[r.hname] += r.duration
    print "\n----\nFinal results:"
    for hname,duration in durations.iteritems():
        print "%s : %0.3f" % (hname,duration)

def status(fq,rq):
    print ""
    while 1:
        print "\rFile Queue: %d -- Result Queue: %d" % (fq.qsize(),rq.qsize())
        time.sleep(5)

if __name__ == '__main__':
    dirtohash = '/usr/share/doc'
    if len(sys.argv) > 1:
        dirtoshash = sys.argv[1]

    # a queue for the files to hash
    fq = multiprocessing.Queue()
    # a queue for the results 
    rq = multiprocessing.Queue()


    walker = multiprocessing.Process(target=walking, args=(dirtohash,fq))
    walker.start()
    hProcesses = []
    for n in range(MAXPROC):
        p = multiprocessing.Process(target=hashing, args=(fq,rq))
        p.start()
        hProcesses.append(p)

    resulter = multiprocessing.Process(target=resulting, args=(rq,))
    resulter.start()

    statusPrint =multiprocessing.Process(target=status, args=(fq,rq))
    statusPrint.start()

    walker.join()
    for p in hProcesses:
        p.join()
    # once the hash are finished, we inject the POISONPILL in the result Queue
    statusPrint.terminate()
    rq.put(POISONPILL)
    resulter.join()


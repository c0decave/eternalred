#!/usr/bin/env python2
# easy public share scanner for samba

import os
import sys
import time
import Queue
import socket
import struct
import random
import argparse
import threading

from random import randrange
from smb.SMBConnection import SMBConnection

version = '0.1'

global rQ
rQ = Queue.Queue()

global q
q = Queue.Queue()

global payload

def printd(data):
	pass

def printe(data):
	pass

def clean_line(line):
	line = line.rstrip('\r')
	line = line.rstrip('\n')
	return line

def randomizeIP(iplist):
	''' function to randomize ips to scan'''
	orig_list = iplist

	# check if we have double ips
	for ip in orig_list:
		if iplist.count(ip)>1:
			print '[*] Warning, %s is %d times in list' % (ip,iplist.count(ip))
			while iplist.count(ip)>1:
				iplist.remove(ip)

	spos = 0
	epos = len(iplist)-1
	cnt = 0
	while [ 1 ]:
		a = random.randint(0,epos)
		b = random.randint(0,epos)
		amove = iplist[a]
		bmove = iplist[b]
		iplist[a]=bmove
		iplist[b]=amove
		cnt+=1
		rnd=2
		if cnt > epos*rnd:
			print '[+] Did %d random iterations, break' % (rnd)
			break

	# check if all ips still there (you never know ;))
	for ip in orig_list:
		if iplist.count(ip)==0:
			print 'Warning missing %s' % (ip)

	return iplist

def _share_check(conn):
	logshares = []
	shares = conn.listShares()

	for share in shares:
		if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL','print$']:
			#print 'Share: [%s]' % share.name
			try:
				sharedfiles = conn.listPath(share.name, '/')
			except:
				return False

			files = []
			for sharedfile in sharedfiles:
				files.append(sharedfile.filename)
#					print(sharedfile.filename)
			data = ('READ',share.name,files)
			logshares.append(data)
	return logshares

def _share_check_write(conn,payload):
	fr = open(payload,'r+')
	logshares = []
	testpath='/.ZGF0YS5iaW4ZGF0YS5iaW4'
	shares = conn.listShares()
	for share in shares:
#		print 'SHARE:',share.name
		if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL','print$']:
			try:
				# write file
				ret = conn.storeFile(share.name, testpath, fr, timeout=30)

				# remove file :)
				conn.deleteFiles(share.name, testpath, timeout=30)
			except:
				return False
			if ret > 0:
				data = ('WRITE',share.name,'')
				logshares.append(data)
	return logshares

def make_request(host,port,timeout,payload):
	human=[]
	try:
		# place here what the code has to do!!
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect((host,port))
		s.close()
	except socket.timeout:
		printe('%s timeout' % host)
		return False
	except socket.error:
		printe( '%s refused' % host)
		return False

	clmachine='localhost'
	sname='server'
	domain='WORKGROUP'
	user = ''
	password = ''
	conn = SMBConnection(user,password,clmachine,sname,domain,use_ntlm_v2=True,is_direct_tcp=True)	
	conn.connect(host,port)
	logshares = _share_check(conn)

	# public read shares
	if logshares != False:
		hdata = '%s:%d' % (host,port)
		hdump = logshares
		read = [hdata,hdump]
		rQ.put(read)

	# public write shares
	logshares = _share_check_write(conn, payload)
	if logshares != False:
		hdata = '%s:%d' % (host,port)
		hdump = logshares
		read = [hdata,hdump]
		#print 'write',read
		rQ.put(read)

def run(args):


	payload = args.payl
	if args.outfile:
		fw = open(args.outfile,'w')

	if args.host:
		host = args.host
		print 'Hostmode: %s' % host
		line = clean_line(host)
		q.put(line)

	elif args.hostlist:
		ipL=[]
		hostlist = args.hostlist
		print 'Hostlistmode'
		fr = open(hostlist,'r')
		rBuf = fr.readlines()
		for l in rBuf:
			l = clean_line(l)
			ipL.append(l)
		if not args.unrandom:
			iplist = randomizeIP(ipL)
		else:
			iplist = ipL

		list = [q.put(query) for query in iplist]

	else:
		print 'Unknown or no mode choosen. cya'
		sys.exit()

	print 'Targets: %d' % (q.qsize())

	port = int(args.port)

	thrCnt = args.thrCnt

	thrList = []

	printd('Starting loop')
	while True:
		if len(thrList) < thrCnt and q.qsize()>0:
			#pkt is send to thread and used
			newthread = threading.Thread(target = make_request,args = (q.get(),port,int(args.timeout),payload))
			newthread.daemon = True
			newthread.start()
			thrList.append(newthread)

		for entry in thrList:
			if entry.isAlive()==False:
				entry.join()
				thrList.remove(entry)

		if rQ.qsize()>0:

			pout = rQ.get()
			hostdata = '%s' % (pout[0])
			sharedata = pout[1][0]
#			print 'sharen:',sharen
			sharef = sharedata[2]
			sharem = sharedata[0]
			sharen = sharedata[1]
			
			for item in sharef:
				tp = '%s %s %s %s' % (hostdata,sharem,sharen,item)
				print tp 
				if args.outfile:
					tp = tp + '\n'
					fw.write(tp)
					fw.flush()
			if sharedata[0] == 'WRITE':
				tp = '%s %s %s' % (hostdata,sharedata[0],sharedata[1])
				print tp 
				if args.outfile:
					tp = tp + '\n'
					fw.write(tp)
					fw.flush()
				
		if q.qsize()==0 and len(thrList) == 0:
			break

	if args.outfile:
		fw.close()



def main():
	parser_desc = 'smb share enumerator %s' % version
	prog_desc = 'smb_enum.py'
	parser = argparse.ArgumentParser(prog = prog_desc, description=parser_desc)
	parser.add_argument("-l","--host",action="store",required=False,help='host to check version',dest='host')
	parser.add_argument("-L","--hostlist",action="store",required=False,help='hostlist to check version',dest='hostlist')
	parser.add_argument("-p","--port",action="store",required=False,default=139,help='ipmi port',dest='port')
	parser.add_argument("-t","--threads",action="store",required=False,default=50,help='how many threads',dest='thrCnt')
	parser.add_argument("-T","--timeout",action="store",required=False,default=5,help='timeout of socket recv',dest='timeout')
	parser.add_argument("-o","--outfile",action="store",required=False,help='outfile in txt format',dest='outfile',default=None)
	parser.add_argument("-r","--unrandom",action="store",required=False,help='disable random targetlist',dest='unrandom')
	parser.add_argument("-P","--payload",action="store",required=False,help='payload to upload',dest='payl',default='payload')
	args = parser.parse_args()
	run(args)

if __name__ == "__main__":
	main()

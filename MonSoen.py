#!/usr/bin/python
# Imports
import Queue
import socket
import time
import base64
from threading import Thread
from threading import Lock
from optparse import OptionParser
from optparse import OptionGroup
from netaddr import *

# Global lock to prevent threads from messing things up
LOCK = Lock()

# Global Print function for verbose options and thread-safe (we hope)..  Its not - refer next thread class thing to fix.
def PrintMsg(message, verbose):
	if verbose:
		LOCK.acquire()
		print message
		LOCK.release()

# This class will print messages...
class PrintStuff(Thread):

	# Class init and define class vars...
	def __init__(self, qu):
		Thread.__init__(self)
		self.queue = qu
		self.thrun = 1

	# Called to shut down the thread...
	def KillIt(self):
		self.thrun = 0

	# Main workhorse...
	def run(self):
		while self.thrun:
			req = self.queue.get()
			if req is None:
				self.thrun = 0
				break
			PrintMsg(str(req), True)
			
# This class will be used for scanning networks via proxy...
class Scanner(Thread):

	# Class init and define class vars
	def __init__(self, ph, pp, pu, pw, md, qu, pq):
		Thread.__init__(self)
		self.phost = ph
		self.pport = pp
		self.puser = pu
		self.ppass = pw
		self.smode = md
		self.queue = qu
		self.prnqu = pq
		self.const = ""
		if self.smode == "get":
			self.const = "GET http://%s HTTP/1.0\r\nUser-Agent: python\r\n"
		else:
			self.const = "CONNECT %s HTTP/1.0\r\nUser-Agent: python\r\n"
		if len(self.puser) > 0:
			tmpstr = str(self.puser) + ":" + str(self.ppass)
			tmpstr = base64.encodestring(tmpstr)
			tmpstr = str(tmpstr).replace("\r", "").replace("\n", "")
			self.const = self.const + "Proxy-Authorization: Basic " + str(tmpstr) + "\r\n"
		self.const = self.const + "\r\n"
			
		self.thrun = 1
		self.csock = None

	# Get fixed length string
	def StringLen(self, val):
		retstr = str(val)
		# We're working with IP addresses, so lets assume it is
		# maximum length 15, plus colon, plus 5.  ie: 21 chars...
		while len(retstr) < 21:
			retstr = retstr + ' '
		return retstr

	# Called to shutdown the threads...
	def KillIt(self):
		self.thrun = 0

	# Main workhorse is here...
	def run(self):
		time.sleep(1)
		while self.thrun:
			req	= self.queue.get()
			if req is None:
				if self.queue.empty():
					self.prnqu.put(None)
				self.thrun = 0
				break
			try:
				self.csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.csock.connect((self.phost, self.pport))
				self.csock.settimeout(10)
				sendstr = self.const % (str(req))
				self.csock.send(sendstr)
				resp = ""
				resp = self.csock.recv(1024)
	                        if resp == '':
					self.prnqu.put(self.StringLen(str(req)) + " : Proxy Connection Closed with no response...")
                	               	self.csock.close()
	                        else:
					arstr = str(resp).replace("\r", "").split("\n")[0]
					self.prnqu.put(self.StringLen(str(req)) + " : " + arstr)
				self.csock.close()
				self.csock = None
			except socket.timeout:
				self.prnqu.put(self.StringLen(str(req)) + " : Timeout speaking with Proxy")
			
			except:
				self.prnqu.put(self.StringLen(str(req)) + " : Unspecified error")

# This class will be used for tunneling data through proxy servers in tunnel mode...
# Tunnelling code primarily done by Willem Mouton - willem@sensepost.com
class Session(Thread):

	# Class init and define class vars
	def __init__(self, cs, ph, pp, pu, pw, rh, rp, vr):
		Thread.__init__(self)
		self.csock = cs
		self.phost = ph
		self.pport = pp
		self.puser = pu
		self.ppass = pw
		self.rhost = rh
		self.rport = rp
		self.verbo = vr

		self.iscon = False
		self.psock = None
		self.const = ""
		self.const = "CONNECT %s:%d HTTP/1.0\r\nUser-Agent: python\r\n" % (self.rhost, self.rport)
		if len(self.puser) > 0:
			tmpstr = str(self.puser) + ":" + str(self.ppass)
			tmpstr = base64.encodestring(tmpstr)
			tmpstr = str(tmpstr).replace("\r", "").replace("\n", "")
			self.const = self.const + "Proxy-Authorization: Basic " + str(tmpstr) + "\r\n"
		self.const = self.const + "\r\n"
		self.thrun = 0

	# Called to shutdown the class
	def KillIt(self):
		self.thrun = 0

	# The actual work-horse...
	def run(self):
		# We are only going to start the thread once the proxy has successfully negotiated the connection
		self.thrun = 0
		PrintMsg("    + Starting proxy connection to " + self.phost + ":" + str(self.pport) + "...", self.verbo)
		# Try and connect to the proxy
		try:
			self.psock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.psock.connect((self.phost, self.pport))
		except:

			print "ERROR: Could not connect to the proxy..."
			print "ERROR: This is pretty much unrecoverable..."
			print "ERROR: Sorry it didn't work out..."
			self.csock.close()
			exit(1)
		PrintMsg("    + Connected to proxy.", self.verbo)
		PrintMsg("    + Negotiating proxy connection && setting socket options...", self.verbo)
		self.psock.send(self.const)
		# We start by trying to negotiate our proxy connection...
		try:
			resp = self.psock.recv(1024)
			if resp == '':
				PrintMsg("    + Proxy connection closed.", self.verbo)
				self.csock.close()
				self.thrun = 0
			else:
				if str(resp).split("\n")[0].find("200") > -1:
					self.iscon = True
					self.thrun = 1
					PrintMsg("    + Proxy connection negotiated.", self.verbo)
				else:
					print "ERROR: The proxy hates you with:"
					print "ERROR: %s" %(str(resp).split("\n")[0].replace("\r", ""))
					self.iscon = False
					self.psock.close()
					self.csock.close()
					self.thrun = 0
		except:
			print "ERROR: Unspecified error whilst negotiating proxy connect..."
			self.csock.close()
			self.iscon = False
			self.thrun = 0

		# At this point, we can assume that our stuff has worked...
		# So, we set our socket options...
		if self.iscon:
		
			self.psock.setblocking(0)
			self.csock.setblocking(0)
			# And we run as long as neccessary...
		   	while self.thrun:
				# Check for proxy data and forward to local listener
				try:
					resp = self.psock.recv(1024)
					if resp == '':
						PrintMsg("    + Proxy connection closed.", self.verbo)
						self.csock.close()
						self.thrun = 0
						break
					i = self.csock.send(resp)
					if i == 0:
						PrintMsg("    + Local connection closed.", self.verbo)
						self.psock.close()
						self.thrun = 0
						break
					PrintMsg("    + PROXY -> LOCAL: " + str(i) + " bytes", self.verbo)
				except:
					pass
				# Check for local listener data and forward to proxy
				try:
					resp = self.csock.recv(1024)
					if resp == '':
						PrintMsg("    + Local connection closed.", self.verbo)
						self.psock.close()
						self.thrun = 0
						break
					i = self.psock.send(resp)
					if i == 0:
						PrintMsg("    + Proxy connection closed.", self.verbo)
						self.csock.close()
						self.thrun = 0
						break
					PrintMsg("    + LOCAL -> PROXY: " + str(i) + " bytes", self.verbo)
				except:
					pass

# Used to start the local listener when app is run in tunnel mode
def StartTunnel(ph, pp, pu, pw, lh, lp, rh, rp, vr):
	# Local variables
	phost = ph
	pport = pp
	puser = pu
	ppass = pw
	lhost = lh
	lport = lp
	rhost = rh
	rport = rp
	verbo = vr
	thrds = list()
	thrun = 0
	PrintMsg("  * Tunnel Settings", verbo)
	PrintMsg("    + Local Listener IP    : " + lhost, verbo)
	PrintMsg("    + Local Listener Port  : " + str(lport), verbo)
	PrintMsg("    + Remote Host IP       : " + rhost, verbo)
	PrintMsg("    + Remote Host Port     : " + str(rhost), verbo)
	PrintMsg("", verbo)
	# Establish the local listener...
	try:
		lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		lsock.bind((lhost, lport))
		lsock.listen(1)
		print "  * Local listener listening on", lhost + ":" + str(lport)
		thrun = 1
		try:
			while thrun:
				(csock, addresss) = lsock.accept()
				PrintMsg("    + Connect from : " + str(addresss), verbo)
				session = Session(csock, phost, pport, puser, ppass, rhost, rport, verbo)
				session.start()
				thrds.append(session)
		except KeyboardInterrupt:
		        print "ERROR: Keyboard interrupt detected.  Shutting down..."
		except:
		        print "ERROR: Unspecified error in while loop."
		finally:
			# We want to kill all our threads...
		        for i in thrds:
				i.KillIt()
			lsock.close()
			thrun = 0
		print "Shutting down...  Sleeping for 5 seconds..."
		time.sleep(5)
	except:
		# Oops...  It didn't work... :(
		print "ERROR: Error starting local listener.  Sorry it didn't work out..."
		print "ERROR: If you're running this in  *nix and the port is < 1024, "
		print "ERROR: are you sure you're running this as root ?"
	return 1

# Used to parse IP's...
# Format is host,network/mask etc.  More than one can be specified on the cli, as long as they are seperated with ","
def ParseIpRange(ip):
	ReturnLst = list()
	ReturnVal = 0
	wrklist = list()
	wrklist = str(ip).split(",")
	for w in wrklist:
		try:
			the_range = IP(w).cidr()
			for i in the_range:
				if not ReturnLst.count(str(i)) > 0:
					ReturnLst.append(str(i))
		except:
			ReturnVal = 1
	return ReturnLst, ReturnVal

# Used to parse Port Ranges...
def ParsePortRange(pr):
	ReturnLst = list()
	ReturnVal = 0
	wrklist = list()
	wrklist = str(pr).split(",")
	for w in wrklist:
		try:
			if str(w).find("-") > -1:
				(n1, n2) = str(w).split("-")
				stuff = range(int(n1), int(n2))
				for j in stuff:
					if not ReturnLst.count(int(j)) > 0:
						ReturnLst.append(int(j))
			else:
				if not ReturnLst.count(int(w)) > 0:
					ReturnLst.append(int(w))
		except:
			ReturnVal = 1		
	return ReturnLst, ReturnVal


# Used to start a scan...
def StartScan(ph, pp, pu, pw, sm, tr, pr, tn, vr):
	# Set the local variables
	phost = ph
	pport = pp
	puser = pu
	ppass = pw
	smode = sm
	targs = tr
	ports = pr
	numth = tn
	verbo = vr
	thrds = list()
	thrun = 0
	queue = Queue.Queue()
	prnqu = Queue.Queue()

	try:

		PrintMsg("  * Parsing Options...", verbo)
		(TList, TCode) = ParseIpRange(targs)
		if TCode > 0 and len(TList) == 0:
			print "ERROR: Could not parse targets.  Please ensure the format is correct"
			return
		elif TCode > 0 and len(TList) > 0:
			PrintMsg("   + Could not parse some targets.  Continuing with what I have...", verbo)
		else:
			PrintMsg("   + Parsed Targets...", verbo)
		(PList, PCode) = ParsePortRange(ports)
		if PCode > 0 and len(PList) == 0:
			print "ERROR: Could not parse ports.  Please ensure the format is correct"
			return
		elif PCode > 0 and len(PList) > 0:
			PrintMsg("   + Could not parse some ports.  Continuing with what I have...", verbo)
		else:
			PrintMsg("   + Parsed Ports...", verbo)
		PrintMsg("   + Done", verbo)
		PrintMsg("", verbo)
		PrintMsg("  * Scan Settings", verbo)
	        PrintMsg("   + Scan Mode            : " + smode, verbo)
	        PrintMsg("   + Number of targets    : " + str(len(TList)), verbo)
	        PrintMsg("   + Number of ports      : " + str(len(PList)), verbo)
	        PrintMsg("   + Number of threads    : " + str(numth), verbo)
		PrintMsg("", verbo)
		# Start the threads...
		PrintMsg("  * Initialising Threads...", verbo)
		for i in range(numth):
			#thrds.append(itm)
			itm = Scanner(phost, pport, puser, ppass, smode, queue, prnqu).start()
			thrds.append(itm)
			#(self, ph, pp, pu, pw, md, qu)
			# PrintMsg("   + Starting thread " + str(i), verbo)
		PrintMsg("   + Starting Print Manager", verbo)
		PrintMgr = PrintStuff(prnqu).start()
		PrintMsg("   + Done", verbo)
		PrintMsg("", verbo)
		# Create the queues...
		PrintMsg("  * Initialising Queues...", verbo)
		for i in TList:
			for j in PList:
				queue.put(str(i) + ":" + str(j))
		PrintMsg("   + Done", verbo)
		PrintMsg("", verbo)
		# Put None at the end of the queue for each thread so that we can stop prettily...
		for i in range(numth):
			queue.put(None)
	except KeyboardInterrupt:
		print "ERROR: Keyboard interrupt detected.  Shutting down..."
		queue = Queue.Queue()
		prnqu = Queue.Queue()
		for t in thrds:
			t.KillIt()
		for i in range(numth):
			queue.put(None)
		prnqu.put(None)
	return 0

def GMode():
	print """         ________                                        __
        / ____  /  ____     __      ______      __      / /
       / /   /_/  /___ \   / /__   / __  /  ___/ /__   / /___
      / / _____  ____/ /  / ___/  / /_/ /  /__  ___/  / __  /
     / / /_  _/ / __  /  / /     / ____/     / /     / / / /
    / /___/ /  / /_/ /  / /     / /___      / /     / / / / __
   /_______/  /_____/  /_/     /_____/     /_/     /_/ /_/ / /
-----------------------------------------------------------|/---

The man...  The legend... :P
"""
	return 0
	

def main():
	# Proxy Variables
	phost = ""
	pport = -1
	puser = ""
	ppass = ""
	pauth = False

	# Tunnel Variables
	lhost = ""
	lport = -1
	rhost = ""
	rport = -1

	# Scan Variables
	smode = ""
	targs = ""
	ports = ""
	thrds = 0
	

	# Main Script Variables
	verbo = False
	omode = ""

	# Print nice welcome message
	print "SensePost MonSoen"
	print ""
	print "ian@sensepost.com || willem@sensepost.com"
	print ""
	opusg = "  %prog [options] arg1 arg2"
	opvrs = "%prog v0.1"
	parse = OptionParser(usage=opusg, version=opvrs)

	# First, we set the main app options...
	syst_group = OptionGroup(parse, "Main Script Settings")
	syst_group.add_option("-m", "--mode",      dest="omode",      help="Script mode ( tunnel | scan )")
	syst_group.add_option("-v", "--verbose",   dest="verbose",    help="Verbose Mode", action="store_true", default=False)
	parse.add_option_group(syst_group)

	# Set the proxy server options group...
	prox_group = OptionGroup(parse, "Proxy Server Options")
	prox_group.add_option("-p", "--proxy",     dest="proxy",      help="Proxy Host:Port")
	prox_group.add_option("-u", "--username",  dest="username",   help="Proxy Username")
	prox_group.add_option("-w", "--password",  dest="password",   help="Proxy Password")
	parse.add_option_group(prox_group)

	# Set the tunnel options group...
	tunn_group = OptionGroup(parse, "Tunnel Options")
	tunn_group.add_option("-r", "--remote",    dest="remote",     help="Remote Host:Port")
	tunn_group.add_option("-l", "--local",     dest="local",      help="Local Host:Port")
	parse.add_option_group(tunn_group)

	# Set the scan options group...
	scan_group = OptionGroup(parse, "Scan Options")
	scan_group.add_option("-s", "--scan-mode", dest="scanmode",   help="Scan mode ( connect | get )")
	scan_group.add_option("-t", "--targets",   dest="targets",    help="Address to scan")
	scan_group.add_option("-o", "--ports",     dest="portrange",  help="Port Range")
	scan_group.add_option("-n", "--threads",   dest="threads",    help="Number of Threads")
	parse.add_option_group(scan_group)

	# Set the evilness group...
	evil_group = OptionGroup(parse, "Other Options")
	evil_group.add_option("-g", "--gp",    dest="gmode",      help="The obligatory evilness", action="store_true", default=False)
	parse.add_option_group(evil_group)

	# Now, we parse the variables...
	(opt, arg) = parse.parse_args()

	# We check the G flag first...
	if opt.gmode == True:
		GMode()
		return
	# Set the verbosity
	verbo = opt.verbose
	# We have to check to ensure that a operating mode has been specified.  That we will do first.
	if opt.omode != "tunnel" and opt.omode != "scan":
		parse.error("Invalid operating mode specified.  This should be one of: tunnel | scan")
	omode = opt.omode
	try:
		(phost, pport) = str(opt.proxy).split(":")
		pport = int(pport)
	except:
		parse.print_help()
		parse.error("Invalid proxy:port specified.")
	# And, since proxy auth is also global, lets test the user and password and set if neccessary...
	puser = opt.username
	ppass = opt.password
	if puser == None:
		puser = ""
		pauth = False
	else:
		pauth = True
	if pauth == True and ppass == None:
		ppass = ""

	# Print Startup Information
	PrintMsg("Starting MonSoen with the following global options...", verbo)
	PrintMsg("", verbo)
	PrintMsg("  * MonSoen Settings", verbo)
	PrintMsg("    + Operating Mode       : " + omode, verbo)
	PrintMsg("", verbo)
	PrintMsg("  * Proxy Settings", verbo)
	PrintMsg("    + Proxy Server         : " + phost, verbo)
	PrintMsg("    + Proxy Port           : " + str(pport), verbo)
	PrintMsg("    + Proxy Authentication : " + str(pauth), verbo)
	if pauth:
		PrintMsg("    + Proxy Username       : " + puser, verbo)
		PrintMsg("    + Proxy Password       : " + ppass, verbo)
	PrintMsg("", verbo)
	

	# Now, things get a little more interesting...
	# TUNNEL MODE: Lets check the variables we need...
	if omode == "tunnel":
		try:
			(lhost, lport) = str(opt.local).split(":")
			lport = int(lport)
		except:
			parse.error("Invalid listener-host:listener-port")
		try:
			(rhost, rport) = str(opt.remote).split(":")
			rport = int(rport)
		except:
			parse.error("Invalid remote-host:remote-port")
		rcode = StartTunnel(phost, pport, puser, ppass, lhost, lport, rhost, rport, verbo)

	
	# SCAN MODE: Lets check the variables we need...
	if omode == "scan":

		smode = opt.scanmode
		if smode == None:
			parse.error("No scan mode specified")
		if smode != "get" and smode != "connect":
			parse.error("Invalid scan mode specified.  Please use get | post")
		targs = opt.targets
		if targs == None:
			parse.error("No targets specified.  Please specify them as host,network/netmask,host etc")
		ports = opt.portrange
		if ports == None:
			parse.error("No port range specified.  Please specify port range as port,port-port etc")
		try:
			thrds = int(opt.threads)
		except:
			parse.error("Number of threads to use was incorrectly specified")
		rcode = StartScan(phost, pport, puser, ppass, smode, targs, ports, thrds, verbo)
	
if __name__ == "__main__":
	main()

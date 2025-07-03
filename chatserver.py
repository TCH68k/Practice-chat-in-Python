#!/usr/bin/env python3
"""
	          Name: Practice chat server in Python
	       Version: 2.0.0
	    Written by: TCH (tch@protonmail.com, http://oscomp.hu)
	  Contributors: amrhassan, mluebke, SilentGhost, hoangphuctv, zamir, Wolf
	 Last modified: 2025.07.03.
	Released under: Public Domain

$VER: Practice chat server in Python 2.0.0 (03.07.2025)
"""

from hashlib import sha256
from typing import Union
import datetime
import os
import select
import signal
import socket
import sys
import threading
import time
import typing

def fopen(path: str, mode: str) -> Union[typing.TextIO, None]:
	try:
		f = open(path, mode)
	except IOError:
		return None
	except OSError:
		return None
	return f

def log_line(line: str):
	global logfile
	
	logfileh = fopen(logfile, "a")
	if (logfileh == None):
		return
	
	fstr = "[" + datetime.datetime.now().isoformat() + "]: " + line + "\n"
	logfileh.write(fstr)
	logfileh.close()

""" Thx to zamir and Wolf """
def pwhash(msg: str) -> str:
	return sha256(msg.encode()).hexdigest()

def parse_line(l):
	global port
	
	l = l[:l.find("#")]
	eq = l.find("=")
	n = l[:eq].strip()
	v = l[eq + 1:].strip()
	
	if (n == "port"):
		port = int(v)

def load_config() -> int:
	global conffile, tmpfile
	
	log_line("Loading configuration...")
	if (not os.path.exists(conffile)):
		return 0
	f = fopen(conffile, "r")
	if (f == None):
		log_line("ERROR: open() of configuration file (\"" + conffile + "\") has failed.")
		return 1
	ls = f.readlines()
	f.close()
	for l in ls:
		parse_line(l)
	if (os.path.exists(tmpfile)):
		try:
			os.unlink(tmpfile)
		except OSError:
			log_line("ERROR: Removing reload mark file (\"" + tmpfile + "\") has failed.")
			return 2
	log_line("Configuration loaded.")
	return 0

def chk_datadir():
	global datadir
	
	if (not os.path.exists(datadir)):
		os.makedirs(datadir, 0o644, True)

def load_users() -> int:
	global userfile, users
	
	log_line("Loading users...")
	chk_datadir()
	if (not os.path.exists(userfile)):
		return 0
	f = fopen(userfile, "r")
	if (f == None):
		log_line("ERROR: open() of user database file (\"" + userfile + "\") has failed.")
		return 1
	ls = f.read().splitlines()
	f.close()
	is_username = True
	for l in ls:
		if (is_username):
			username = l
		else:
			users[username] = l
		is_username = not is_username
	log_line("Users loaded.")
	return 0

def reg_user(username: str, password: str) -> int:
	global userfile, users
	
	if (username in users):
		return 1
	f = fopen(userfile, "a")
	if (f == None):
		return 2
	pwh = pwhash(password)
	users[username] = pwh
	f.write(username + "\n")
	f.write(pwh + "\n")
	f.close()
	return 0

def auth_user(username: str, password: str) -> bool:
	global users
	
	return (username in users) and (users[username] == pwhash(password))

def del_connection(i: int, do_close: bool):
	global connections, addresses, buffers, bufflens, shifts, userids, connids, sockmap
	
	poller.unregister(connections[i].fileno())
	if (do_close):
		connections[i].shutdown(socket.SHUT_RDWR)
		connections[i].close()
	del connections[i]
	del addresses[i]
	del buffers[i]
	del bufflens[i]
	del shifts[i]
	del sockmap[sockets[i]]
	for fd in sockmap:
		if (sockmap[fd] > i):
			sockmap[fd] -= 1
	del sockets[i]
	if (userids[i] in connids):
		del connids[userids[i]]
	del userids[i]
	for un in connids:
		if (connids[un] > i):
			connids[un] -= 1
	send_userlist_to_all(-1)

def buffer_readstr(i: int, o: int, a: int) -> (int, int, int, str):
	global buffers, bufflens
	
	"""
		Error codes:
		1 = Broken string
		2 = Invalid string
	"""
	l = buffers[i][o]
	p = o + 1
	if (l == 0):
		return (0, p, l, "")
	if (l > bufflens[i] - a):
		return (1, p, l, "")
	s = bytearray()
	while (l > len(s)):
		b = buffers[i][p]
		if (((b < 32) and (b != 9) and (b != 10) and (b != 13)) or (b == 127)):
			return (2, p, l, "")
		s.append(b)
		p += 1
	return (0, p, l, s.decode())

def chk_str(e, s, i, v):
	if (e == 1):
		return 254
	if (e == 2):
		return i
	if (s == ""):
		return v
	return 0

def qwordtobinarystr(i: int) -> bytearray:
	r = bytearray()
	r.append(i >> 56)
	r.append((i >> 48) & 255)
	r.append((i >> 40) & 255)
	r.append((i >> 32) & 255)
	r.append((i >> 24) & 255)
	r.append((i >> 16) & 255)
	r.append((i >> 8) & 255)
	r.append(i & 255)
	return r

def sendtosocket(i: int, d: bytearray):
	global connections
	
	data = bytes(qwordtobinarystr(len(d)) + d)
	tsb = 0
	while (tsb < len(data)):
		sb = connections[i].send(data)
		if (sb == 0):
			return False
		tsb += sb
	return True

def send_userlist_to_conn(i: int) -> bool:
	global userlist
	
	if (not sendtosocket(i, userlist)):
		del_connection(i, False)
		return False
	
	return True

def send_userlist_to_all(exc: int):
	global userlist, userids
	
	userlist = bytearray([3])
	userlist.extend(qwordtobinarystr(len(userids)))
	for u in range(0, len(userids)):
		userlist.append(len(userids[u]))
		userlist.extend(userids[u].encode())
	for i in range(0, len(connections)):
		if (exc != i):
			send_userlist_to_conn(i)

def handle_buffer(i: int) -> int:
	global connections, addresses, buffers, bufflens, userids, connids
	
	"""
		Global handle_buffer() error codes:
		254 = Broken buffer
		255 = Unknown buffer type
	"""
	buftype = buffers[i][0]
	if (buftype < 3):
		"""
			Common transmitting registration/authentication/transmission error codes:
			1 = Invalid username
			2 = Empty username
			3 = Invalid password/message
			4 = Empty password/message
		"""
		if (buftype == 0):
			mt = "register"
		if (buftype == 1):
			mt = "log in"
		else:
			mt = "send a message"
		e, p, l, username = buffer_readstr(i, 1, 4)
		r = chk_str(e, username, 1, 2)
		if (r != 0):
			log_line("WARNING: Client " + addresses[i][0] + " tried to " + mt + " with an invalid username (\"" + username + "\").")
			return r
		
		e, p, l, pom = buffer_readstr(i, p, 3 + l)
		r = chk_str(e, pom, 3, 4)
		if (r != 0):
			log_line("WARNING: Client " + addresses[i][0] + " tried to " + mt + " with an invalid password.")
			return r
		
		if (buftype == 0):
			"""
				Extra registration error codes:
				5 = User already exists
				6 = Server error: unable to open user database file
			"""
			r = reg_user(username, pom)
			if (r != 0):
				if (r == 1):
					log_line("WARNING: Client " + addresses[i][0] + " tried register username (\"" + username + "\"), what already exists.")
				elif (r == 2):
					log_line("WARNING: Unable to open user database file.")
				return r + 4
			else:
				log_line("NOTE: Client " + addresses[i][0] + " has been registered the user \"" + username + "\".")
		elif (buftype == 1):
			"""
				Extra authentication error codes:
				5 = User does not exist, or password does not match
				6 = User is already logged in
			"""
			if (not auth_user(username, pom)):
				log_line("WARNING: Client " + addresses[i][0] + " tried to log in with either a nonexistent username (\"" + username + "\"), or with a non-matching password.")
				return 5
			
			if (username in connids):
				log_line("WARNING: Client " + addresses[i][0] + " tried to log in with username (\"" + username + "\"), what is already logged in.")
				return 6
			userids[i] = username
			connids[username] = i
			log_line("NOTE: Client " + addresses[i][0] + " has logged in with username (\"" + username + "\").")
			send_userlist_to_all(i)
		elif (buftype == 2):
			"""
				Extra transmission error codes:
				5 = Recipient has a broken connection
			"""
			log_line("NOTE: Client " + addresses[i][0] + " (\"" + userids[i] + "\") has sent a message (\"" + pom + "\") to (\"" + username + "\").")
			o = connids[username]
			tuser = userids[i].encode()
			tpom = pom.encode()
			if (not sendtosocket(o, bytearray([2, len(tuser)]) + tuser + bytearray([len(tpom)]) + tpom)):
				del_connection(o, False)
				return 5
			
		return 0
	elif (buftype == 3):
		"""
			Listing error codes:
			-1 = Broken connection, will not be transmitted back, as the requester broke
			-2 = No error, but the list request will either result in the list, or nothing: no error code needed.
		"""
		if (not send_userlist_to_conn(i)):
			return -1
		
		return -2
	elif (buftype == 4):
		"""
			Should not happen. Ever.
		"""
		log_line("WARNING: Client " + addresses[i][0] + " sent a server error code: " + str(data[1]))
	else:
		return 255

def recv_thread():
	global poller, tf, run, connections, addresses, buffers, bufflens, shifts, sockmap, pause
	
	tf = False
	while run:
		if (pause):
			time.sleep(0.05)
		else:
			events = poller.poll(0.05)
			if (pause):
				continue
			for j in range(0, len(events)):
				i = sockmap[events[j][0]]
				try:
					data = connections[i].recv(256)
				except BlockingIOError:
					pass
				except ConnectionResetError:
					log_line("ERROR: Client " + addresses[i][0] + " interrupted connection.")
					del_connection(i, False)
				except Exception as e:
					log_line("WARNING: Unexpected exception (\"" + str(e) + "\") on reading socket from client " + addresses[i][0] + ".")
				else:
					if (len(data) == 0):
						log_line("NOTE: Client #" + str(i) + " (" + addresses[i][0] + ") exited.")
						del_connection(i, False)
					else:
						if (len(buffers[i]) == 0):
							ptr = 0
							while ((shifts[i] < 8) and (ptr < len(data))):
								bufflens[i] = (bufflens[i] << 8) | data[ptr]
								ptr += 1
								shifts[i] += 1
							if ((shifts[i] == 8) and (ptr < len(data))):
								while (ptr < len(data)):
									buffers[i].append(data[ptr])
									ptr += 1
						else:
							buffers[i] += data
						if (len(buffers[i]) == bufflens[i]):
							ret = handle_buffer(i)
							buffers[i] = bytearray()
							bufflens[i] = 0
							shifts[i] = 0
							if (ret >= 0):
								if (not sendtosocket(i, bytearray([4, ret]))):
									del_connection(i, False)
	tf = True

def sighnd(signum: int, frame):
	global load, run
	
	if (signum == signal.SIGHUP):
		load = True
	elif ((signum == signal.SIGTERM) or (signum == signal.SIGINT)):
		run = False

""" Thx to hoangphuctv. """
def file_put_contents(filename: str, text: str):
	f = fopen(filename, "w")
	if (f == None):
		return
	f.write(text)
	f.close()


""" Thx to amrhassan. """
def file_get_contents(filename: str) -> str:
	if (os.path.exists(filename)):
		f = fopen(filename, "r")
		if (f == None):
			return ""
		content = f.read()
		f.close()
		return content
	return ""

""" Thx to mluebke. """
def check_pid(pid: int) -> bool:
	""" Check For the existence of a unix pid. """
	try:
		os.kill(pid, 0)
	except OSError:
		return False
	else:
		return True

def open_listening_socket():
	global sock, port
	
	log_line("Opening listening socket...")
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(("127.0.0.1", port))
	sock.listen(10)

def close_connections():
	global sock
	
	log_line("Closing open connections...")
	for i in range(0, len(connections)):
		del_connection(i, True)
	log_line("Closing listening socket...")
	sock.close()

progname = "chatserver.py"
conffile = "/etc/" + progname + ".conf"
tmpfile = "/tmp/" + progname + ".tmp"
pidfile = "/var/run/" + progname + ".pid"
logfile = "/var/log/" + progname + ".log"
errlogfile = "/var/log/" + progname + ".err.log"
datadir = "/var/lib/" + progname + "/"
userfile = datadir + "users"

usage = "Usage: " + progname + " <start/stop/reload>"
if (len(sys.argv) == 1):
	print(usage)
	os._exit(0)

do_reload = sys.argv[1] == "reload"
do_stop = (not do_reload) and (sys.argv[1] == "stop")
do_start = (not do_reload) and (not do_stop) and (sys.argv[1] == "start")
if ((not do_reload) and (not do_stop) and (not do_start)):
	print("Unknown command: \"" + sys.argv[1] + "\"", file=sys.stderr)
	print(usage, file=sys.stderr)
	os._exit(1)

try:
	pid = int(file_get_contents(pidfile))
except ValueError:
	pid = -1
is_running = (pid != -1) and check_pid(pid)

if (do_start and is_running):
	print("Server is already running.", file=sys.stderr)
	os._exit(2)

if ((do_reload or do_stop) and (not is_running)):
	print("Server is not running.", file=sys.stderr)
	os._exit(3)

if (do_reload):
	f = fopen(tmpfile, 'a')
	if (f == None):
		print("Creating reload mark file (\"" + tmpfile + "\") has failed.", file=sys.stderr)
		os._exit(4)
	f.close()
	os.kill(pid, signal.SIGHUP)
	is_reloading = True
	timeout = 100
	while (is_reloading and (timeout > 0)):
		time.sleep(0.05)
		timeout -= 1
		is_reloading = os.path.exists(tmpfile)
	if (is_reloading):
		print("Reloading configuration has failed.", file=sys.stderr)
		os._exit(5)
	os._exit(0)

if (do_stop):
	os.kill(pid, signal.SIGTERM)
	timeout = 100
	while (is_running and (timeout > 0)):
		time.sleep(0.05)
		timeout -= 1
		is_running = check_pid(pid)
	if (is_running):
		print("Server could not have been stopped gracefully. Killing...", file=sys.stderr)
		os.kill(pid, signal.SIGKILL)
		os._exit(6)
	else:
		print("Server has been stopped.")
		os._exit(0)

log_line("Starting server...")

log_line("Calling fork()...")
pid = os.fork()
if (pid == -1):
	log_line("Fatal error: fork() failed.")
	os._exit(8)
if (pid != 0):
	os._exit(0)

log_line("Calling setsid()...")
if (os.setsid() == -1):
	log_line("Fatal error: setsid() failed.")
	os._exit(9)

os.umask(0)
os.chdir("/")

log_line("Redirecting stdin, stdout, stderr...")
devnullr = fopen("/dev/null", "r")
if (devnullr == None):
	log_line("Fatal error: open() of \"/dev/null\" failed.")
	os._exit(10)
errlog = fopen(errlogfile, "a")
if (errlog == None):
	log_line("Fatal error: open() of \"" + errlogfile + "\" failed.")
	os._exit(10)

if ((os.dup2(devnullr.fileno(), 0) == -1) or (os.dup2(errlog.fileno(), 1) == -1) or (os.dup2(errlog.fileno(), 2) == -1)):
	log_line("Fatal error: dup2() of stdin, or stdout, or stderr has been failed.")
	os._exit(11)

pid = os.getpid()
file_put_contents(pidfile, str(pid))

log_line("Assigning signal handler...")
signal.signal(signal.SIGTERM, sighnd)
signal.signal(signal.SIGINT, sighnd)
signal.signal(signal.SIGHUP, sighnd)

userlist = bytearray()
users = {}
connections = []
addresses = []
buffers = []
bufflens = []
shifts = []
userids = []
connids = {}
sockmap = {}
sockets = []

port = 54321

if (load_config() != 0):
	os._exit(12)

if (load_users() != 0):
	os._exit(13)

open_listening_socket()

tf = False
run = True
load = False
pause = False

log_line("Starting helper thread...")
poller = select.poll()
rt = threading.Thread(target=recv_thread, args=())
rt.start()

log_line("Server is running.")

while run:
	try:
		ready = select.select([sock], [], [], 0.05)
	except ValueError:
		log_line("FATAL ERROR: Listening socket broke.")
		run = False
	else:
		if (ready[0]):
			c, a = sock.accept()
			c.setblocking(0)
			ni = len(connections)
			sockets.append(c.fileno())
			sockmap[c.fileno()] = ni
			connections.append(c)
			addresses.append(a)
			buffers.append(bytearray())
			bufflens.append(0)
			shifts.append(0)
			userids.append("")
			poller.register(c.fileno(), select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLRDHUP)
			log_line("NOTE: A new client from " + a[0] + " connected to the server as #" + str(ni) + ".")
		else:
			if (load == True):
				load = False
				pause = True
				close_connections()
				load_config()
				open_listening_socket()
				pause = False

log_line("Waiting for helper thread to finish...")
while (not tf):
	time.sleep(0.05)
rt.join()

close_connections()

log_line("Server stopped.")

errlog.close()
devnullr.close()
if (os.path.exists(pidfile)):
	try:
		os.unlink(pidfile)
	except OSError:
		""" Theoretically this should be impossible. """
		pass
os._exit(0)

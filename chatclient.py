#!/usr/bin/env python3
"""
	          Name: Practice chat client in Python
	       Version: 2.0.0
	    Written by: TCH (tch@protonmail.com, http://oscomp.hu)
	  Contributors: -
	 Last modified: 2025.07.03.
	Released under: Public Domain

$VER: Practice chat client in Python 2.0.0 (03.07.2025)
"""

from PyQt5.QtCore import QSize, QTimer, Qt
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import QAction, QApplication, QGroupBox, QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QWidget
import select
import socket
import sys
import threading
import time

def show_message(title: str, message: str, icon: QMessageBox.Icon):
	mb = QMessageBox()
	mb.setIcon(icon)
	mb.setWindowTitle(title)
	mb.setText(message)
	mb.setStandardButtons(QMessageBox.Ok)
	mb.exec_()

def show_message_t(title: str, message: str, icon: QMessageBox.Icon):
	global wmain
	
	wmain.msg_t = title
	wmain.msg_m = message
	wmain.msg_i = icon
	wmain.msg_s = True

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

def sendtosocket(d: bytearray):
	global sock
	
	data = bytes(qwordtobinarystr(len(d)) + d)
	tsb = 0
	while (tsb < len(data)):
		sb = sock.send(data)
		if (sb == 0):
			sock = None
			show_message("Transmission error", "Broken connection.", QMessageBox.Critical)
		tsb += sb

def handle_buffer(buf: bytearray):
	global lsb, wmain, userlist
	
	buftype = buf[0]
	if (buftype == 2):
		""" New message. """
		l = buf[1]
		ptr = 2
		rb = bytearray()
		while (len(rb) < l):
			rb.append(buf[ptr])
			ptr += 1
		l = buf[ptr]
		ptr += 1
		username = rb.decode()
		rb = bytearray()
		while (len(rb) < l):
			rb.append(buf[ptr])
			ptr += 1
		message = rb.decode()
		toadd = "<" + username + "> " + message + "\n"
		if (username not in windowbuffers):
			windowbuffers[username] = ""
		windowbuffers[username] += toadd
		if ((wmain.listbox.currentItem() != None) and (username == wmain.listbox.currentItem().text())):
			wmain.toadd = toadd
	elif (buftype == 3):
		""" List. """
		ll = (buf[1] << 56) | (buf[2] << 48) | (buf[3] << 40) | (buf[4] << 32) | (buf[5] << 24) | (buf[6] << 16) | (buf[7] << 8) | buf[8]
		ptr = 9
		userlist = []
		for i in range(0, ll):
			nl = buf[ptr]
			ptr += 1
			rb = bytearray()
			while (len(rb) < nl):
				rb.append(buf[ptr])
				ptr += 1
			n = rb.decode()
			userlist.append(n)
			if (n not in windowbuffers):
				windowbuffers[n] = ""
		wmain.list_users = True
	elif (buftype == 4):
		""" Error code. """
		errc = buf[1]
		if (errc != 0):
			if (lsb == 0):
				mt = "Registration"
			elif (lsb == 1):
				mt = "Authentication"
			elif (lsb == 2):
				mt = "Transmission"
			else:
				""" Should not ever happen. """
				mt = "Unknown"
			errl = mt + " error"
			if (errc == 254):
				show_message_t(errl, "Broken buffer.", QMessageBox.Critical)
			else:
				if (lsb < 3):
					if (errc == 0):
						show_message_t(errl, "Invalid username.", QMessageBox.Critical)
					elif (errc == 1):
						show_message_t(errl, "Empty username.", QMessageBox.Critical)
					if (errc == 2):
						show_message_t(errl, "Invalid password.", QMessageBox.Critical)
					elif (errc == 3):
						show_message_t(errl, "Empty password.", QMessageBox.Critical)
					else:
						if (lsb == 0):
							if (errc == 5):
								show_message_t(errl, "User already exists.", QMessageBox.Critical)
							elif (errc == 6):
								show_message_t(errl, "Server error: unable to open user database file.", QMessageBox.Critical)
						elif (lsb == 1):
							if (errc == 5):
								show_message_t(errl, "User does not exist, or password does not match.", QMessageBox.Critical)
							elif (errc == 6):
								show_message_t(errl, "User already logged in.", QMessageBox.Critical)
						elif (lsb == 2):
							if (errc == 5):
								show_message_t(errl, "Recipient has a broken connection.", QMessageBox.Critical)
		else:
			if (lsb == 0):
				show_message_t("Message", "User has been registered.", QMessageBox.Information)
			elif (lsb == 1):
				wmain.switch_windows = True
				show_message_t("Message", "Login successful.", QMessageBox.Information)
		lsb = -1

def recv_thread():
	global run, tf, sock, buf, buflen, shift, glerrmsg
	
	run = True
	tf = False
	while (run):
		try:
			ready = select.select([sock], [], [], 0.05)
		except ValueError:
			glerrmsg = "Invalid socket."
			sock = None
			run = False
		else:
			if (ready[0] and (sock.fileno() > 2)):
				try:
					data = sock.recv(256)
				except BlockingIOError:
					pass
				except ConnectionResetError:
					sock = None
					run = False
				except OSError:
					glerrmsg = "Invalid file descriptor for socket to server."
					sock = None
					run = False
				except Exception as e:
					glerrmsg = "Unexpected exception (\"" + str(e) + "\")."
					sock.close()
					sock = None
					run = False
				else:
					if (len(data) == 0):
						sock = None
						run = False
					else:
						if (len(buf) == 0):
							ptr = 0
							while ((shift < 8) and (ptr < len(data))):
								buflen = (buflen << 8) | data[ptr]
								ptr += 1
								shift += 1
							if ((shift == 8) and (ptr < len(data))):
								while (ptr < len(data)):
									buf.append(data[ptr])
									ptr += 1
						else:
							buf += data
						if (len(buf) == buflen):
							handle_buffer(buf)
							buf = bytearray()
							buflen = 0
							shift = 0
						else:
							""" Broken buffer. Should not happen. """
							glerrmsg = "Broken buffer."
							sock.close()
							sock = None
							run = False
	tf = True

class wlogin_class(QWidget):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Log in/register")
		self.setMinimumSize(0, 0)
		self.setMaximumSize(0xffffff, 0xffffff)
		self.glogin = QGroupBox("Server", self)
		self.glogin.move(0, 0)
		self.glogin.lhost = QLabel("Host:", self.glogin)
		self.glogin.lhost.adjustSize()
		self.glogin.ehost = QLineEdit("127.0.0.1", self.glogin)
		self.glogin.lport = QLabel("Port:", self.glogin)
		self.glogin.lport.adjustSize()
		self.glogin.eport = QLineEdit("54321", self.glogin)
		self.glogin.eport.setValidator(QIntValidator(1, 65535, self))
		self.glogin.luser = QLabel("User:", self.glogin)
		self.glogin.luser.adjustSize()
		self.glogin.euser = QLineEdit("", self.glogin)
		self.glogin.euser.setMaxLength(255)
		self.glogin.lpass = QLabel("Password:", self.glogin)
		self.glogin.lpass.adjustSize()
		self.glogin.epass = QLineEdit("", self.glogin)
		self.glogin.epass.setEchoMode(QLineEdit.Password)
		self.glogin.epass.setMaxLength(255)
		self.glogin.lhost.move(0, 16)
		self.glogin.lport.move(0, self.glogin.lhost.y() + self.glogin.lhost.height() + 8)
		self.glogin.luser.move(0, self.glogin.lport.y() + self.glogin.lport.height() + 8)
		self.glogin.lpass.move(8, self.glogin.luser.y() + self.glogin.luser.height() + 8)
		right = self.glogin.lpass.x() + self.glogin.lpass.width()
		self.glogin.luser.move(right - self.glogin.luser.width(), self.glogin.luser.y())
		self.glogin.lport.move(right - self.glogin.lport.width(), self.glogin.lport.y())
		self.glogin.lhost.move(right - self.glogin.lhost.width(), self.glogin.lhost.y())
		right += 8
		self.glogin.ehost.move(right, self.glogin.lhost.y())
		self.glogin.eport.move(right, self.glogin.lport.y())
		self.glogin.euser.move(right, self.glogin.luser.y())
		self.glogin.epass.move(right, self.glogin.lpass.y())
		self.glogin.resize(self.glogin.epass.x() + self.glogin.epass.width() + 32, self.glogin.epass.y() + self.glogin.epass.height())
		self.blogin = QPushButton("Log in", self)
		self.blogin.clicked.connect(self.blogin_clicked)
		self.blogin.adjustSize()
		self.blogin.move(4, self.glogin.height() + 2)
		self.setFixedSize(self.glogin.width(), self.blogin.y() + self.blogin.height() + 4)
		self.bregister = QPushButton("Register", self)
		self.bregister.clicked.connect(self.bregister_clicked)
		self.bregister.adjustSize()
		self.bregister.move(self.width() - (4 + self.bregister.width()), self.blogin.y())
	
	def show_connecting_error(self, et: str):
		global sock
		
		sock = None
		show_message("Connection error", et, QMessageBox.Critical)
	
	def init_connection(self) -> bool:
		global sock, rt, tf
	
		if (sock != None):
			return True
		
		if ((rt != None) and tf):
			rt.join()
		
		tuser = self.glogin.ehost.text()
		tpass = self.glogin.eport.text()
		cre = "Credential error"
		if (tuser == ""):
			show_message(cre, "Empty username.", QMessageBox.Critical)
			return
		if (tpass == ""):
			show_message(cre, "Empty password.", QMessageBox.Critical)
			return
		
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			sock.connect((tuser, int(tpass)))
		except TimeoutError:
			self.show_connecting_error("Connecting has timed out.")
		except InterruptedError:
			self.show_connecting_error("Connecting has been interrupted.")
		except ConnectionRefusedError:
			self.show_connecting_error("Connecting has been refused.")
		except Exception as e:
			self.show_connecting_error("Unexpected exception (\"" + str(e) + "\") during connecting.")
		
		if (sock == None):
			return False
		
		sock.setblocking(0)
		tf = False
		rt = threading.Thread(target=recv_thread, args=())
		rt.start()
		return True
	
	def send_aor_msg(self, t: int):
		global sock, lsb
		
		lsb = t
		tuser = self.glogin.euser.text().encode()
		tpass = self.glogin.epass.text().encode()
		sendtosocket(bytearray([t, len(tuser)]) + tuser + bytearray([len(tpass)]) + tpass)
	
	def blogin_clicked(self):
		if (self.init_connection()):
			self.send_aor_msg(1)
	
	def bregister_clicked(self):
		if (self.init_connection()):
			self.send_aor_msg(0)
	
	def closeEvent(self, event):
		global wmain
		
		wmain.timer.stop()
		if (sock != None):
			sock.close()
			run = False
			while (not tf):
				time.sleep(0.05)
			rt.join()

class wmain_class(QMainWindow):
	def __init__(self):
		global wmain_title
		
		super().__init__()
		self.setWindowTitle(wmain_title)
		self.setMinimumSize(128, 64)
		self.setMaximumSize(0xffffff, 0xffffff)
		self.resize(640, 480)
		self.timer = QTimer()
		self.timer.timeout.connect(self.msgchk)
		self.timer.start(50)
		self.msg_t = ""
		self.msg_m = ""
		self.msg_i = None
		self.msg_s = False
		self.list_users = False
		self.toadd = None
		self.switch_windows = False
		self.listbox = QListWidget(self)
		self.listbox.currentItemChanged.connect(self.listchg)
		self.emsg = QLineEdit("", self)
		self.emsg.returnPressed.connect(self.send_msg)
		self.log = QPlainTextEdit(self)
		self.log.setReadOnly(True)
		self.btn = QPushButton("Send", self)
		self.btn.clicked.connect(self.send_msg)
		self.formrs()
	
	def formrs(self):
		pad = 2
		lbl = (self.width() - self.listbox.width()) - pad
		self.emsg.move(pad, (self.height() - self.emsg.height()) - pad)
		self.emsg.resize(lbl - (pad + pad), self.emsg.height())
		self.listbox.move(lbl, pad)
		self.listbox.resize(self.listbox.width(), self.emsg.y() - (pad + pad))
		self.log.move(pad, pad)
		self.log.resize(self.emsg.width(), self.listbox.height())
		self.btn.move(lbl, self.emsg.y())
		self.btn.resize(self.listbox.width(), self.emsg.height())
	
	def resizeEvent(self, event):
		self.formrs()
	
	def listchg(self):
		global windowbuffers, wmain_title
		
		if ((self.listbox.currentRow() < 0) or (self.listbox.currentItem() == None)):
			return
		self.log.clear()
		self.log.insertPlainText(windowbuffers[self.listbox.currentItem().text()])
		self.setWindowTitle(wmain_title + " :: " + self.listbox.currentItem().text())
	
	def closeEvent(self, event):
		global run
		
		self.timer.stop()
		if (sock != None):
			sock.close()
			run = False
			while (not tf):
				time.sleep(0.05)
			rt.join()
	
	def msgchk(self):
		global wlogin, userlist, sock, alive, glerrmsg
		
		if (alive and (sock == None)):
			if (glerrmsg == ""):
				glerrmsg = "The connection to the server has been closed."
			show_message("Receive error", glerrmsg, QMessageBox.Critical)
			self.close()
			return
		if (self.msg_s):
			self.msg_s = False
			show_message(self.msg_t, self.msg_m, self.msg_i)
		if (self.switch_windows):
			self.switch_windows = False
			self.show()
			wlogin.hide()
			alive = True
			sendtosocket(bytearray([3]))
		if (self.list_users):
			wmain.listbox.clear()
			for i in range(0, len(userlist)):
				if (userlist[i] != wlogin.glogin.euser.text()):
					wmain.listbox.addItem(userlist[i])
			self.list_users = False
		if (self.toadd != None):
			self.log.insertPlainText(self.toadd)
			self.toadd = None
	
	def send_msg(self):
		if ((self.listbox.currentRow() < 0) or (self.listbox.currentItem() == None)):
			return
		lsb = 2
		tuser = self.listbox.currentItem().text().encode()
		tmsg = self.emsg.text().encode()
		sendtosocket(bytearray([2, len(tuser)]) + tuser + bytearray([len(tmsg)]) + tmsg)
		toadd = "<" + wlogin.glogin.euser.text() + "> " + self.emsg.text() + "\n"
		if (self.listbox.currentItem().text() not in windowbuffers):
			windowbuffers[self.listbox.currentItem().text()] = ""
		windowbuffers[self.listbox.currentItem().text()] += toadd
		self.log.insertPlainText(toadd)
		self.emsg.setText("")

userlist = []
windowbuffers = {}
buf = bytearray()
buflen = 0
shift = 0
sock = None
rt = None
run = False
tf = False
lsb = -1
alive = False
wmain_title = "Practice chat client in Python"
glerrmsg = ""

app = QApplication(sys.argv)
wmain = wmain_class()
wlogin = wlogin_class()
wlogin.show()
app.exec()

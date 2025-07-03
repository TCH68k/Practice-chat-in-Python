# Practice chat in Python
A simple client-server chat implementation in Python, written as a practice and to use it as a reference for junior Python jobs.

Requirements for the server script:
- Some kind of UNIX, or UNIX-like OS (macOS or other BSD-s, Linux, Solaris, AIX etc. It was only tested on Linux, but should work on all.)
- Python 3.5

Server usage:
Server configuration file is `/etc/chatserver.py.conf`. It is a `key=value` type config file. Currently it only has the `port` variable what determines which port the server will listen on. By default, this is `54321`.
The server by passing these keywords to the script can be instructed to `start`, `stop` or `reload` the configuration. (Note that changing the port during a session will cause the clients to drop.)

Requirements for the server script:
- Python 3.3
- PyQt
- Qt5

Client usage:
The user has to set the IP address of the server in the "host" field and the port the server listens on in the "port" field. Before connecting, one must register an account, by filling the "user" and "password" fields and clicking the "register" button. If succeeded, the user may log in. Then the chat window will pop up and the chat partner can be selected and messaged.

Everything in this repository is Public Domain.

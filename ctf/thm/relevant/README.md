Relevant ------------------> CTF Pranay 16/1/2020


'''

export ip=10.10.166.149

'''

Recon

'''
Nmap

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-16 13:17 IST
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 4.10 seconds

Firewall Was not letting us to scan all the ports. 

For first 1000 ports 

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-16 13:31 IST
NSE: Loaded 45 scripts for scanning.
Initiating Parallel DNS resolution of 1 host. at 13:31
Completed Parallel DNS resolution of 1 host. at 13:31, 0.02s elapsed
Initiating SYN Stealth Scan at 13:31
Scanning 10.10.65.43 [1000 ports]
Discovered open port 135/tcp on 10.10.65.43
Discovered open port 80/tcp on 10.10.65.43
Discovered open port 3389/tcp on 10.10.65.43
Discovered open port 445/tcp on 10.10.65.43
Discovered open port 139/tcp on 10.10.65.43
Completed SYN Stealth Scan at 13:31, 19.10s elapsed (1000 total ports)
Initiating Service scan at 13:31
Scanning 5 services on 10.10.65.43
Completed Service scan at 13:33, 114.99s elapsed (5 services on 1 host)
Initiating OS detection (try #1) against 10.10.65.43
Retrying OS detection (try #2) against 10.10.65.43
NSE: Script scanning 10.10.65.43.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 2.22s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 1.74s elapsed
Nmap scan report for 10.10.65.43
Host is up, received user-set (0.42s latency).
Scanned at 2021-01-16 13:31:39 IST for 145s
Not shown: 995 filtered ports
Reason: 995 no-responses
PORT     STATE SERVICE            REASON          VERSION
80/tcp   open  http               syn-ack ttl 125 Microsoft IIS httpd 10.0
135/tcp  open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
139/tcp  open  netbios-ssn        syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       syn-ack ttl 125 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open  ssl/ms-wbt-server? syn-ack ttl 125
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012 (90%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (90%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=1/16%OT=80%CT=%CU=%PV=Y%G=N%TM=60029DF4%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=110%TI=I%II=I%SS=S%TS=A)
OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M505NW8ST11%O5=M505NW8ST11%O6=M505ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.003 days (since Sat Jan 16 13:29:42 2021)
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows



All port scan results:

sudo nmap -Pn -sS -O -sV -vv -p- $ip -oN nmap/full
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-16 13:34 IST
NSE: Loaded 45 scripts for scanning.
Initiating Parallel DNS resolution of 1 host. at 13:34
Completed Parallel DNS resolution of 1 host. at 13:34, 0.00s elapsed
Initiating SYN Stealth Scan at 13:34
Scanning 10.10.65.43 [65535 ports]
Discovered open port 135/tcp on 10.10.65.43
Discovered open port 80/tcp on 10.10.65.43
Discovered open port 139/tcp on 10.10.65.43
Discovered open port 445/tcp on 10.10.65.43
Discovered open port 3389/tcp on 10.10.65.43
SYN Stealth Scan Timing: About 2.81% done; ETC: 13:53 (0:17:52 remaining)
SYN Stealth Scan Timing: About 5.88% done; ETC: 13:51 (0:16:17 remaining)
SYN Stealth Scan Timing: About 9.96% done; ETC: 13:49 (0:13:42 remaining)
SYN Stealth Scan Timing: About 14.87% done; ETC: 13:48 (0:11:33 remaining)
SYN Stealth Scan Timing: About 20.39% done; ETC: 13:46 (0:09:50 remaining)
Discovered open port 49666/tcp on 10.10.65.43
SYN Stealth Scan Timing: About 27.29% done; ETC: 13:45 (0:08:02 remaining)
SYN Stealth Scan Timing: About 34.63% done; ETC: 13:44 (0:06:38 remaining)
SYN Stealth Scan Timing: About 40.83% done; ETC: 13:44 (0:05:49 remaining)
SYN Stealth Scan Timing: About 46.45% done; ETC: 13:44 (0:05:12 remaining)
SYN Stealth Scan Timing: About 52.66% done; ETC: 13:44 (0:04:31 remaining)
SYN Stealth Scan Timing: About 58.76% done; ETC: 13:44 (0:04:01 remaining)
SYN Stealth Scan Timing: About 64.90% done; ETC: 13:44 (0:03:30 remaining)
Discovered open port 49668/tcp on 10.10.65.43
SYN Stealth Scan Timing: About 70.76% done; ETC: 13:44 (0:02:58 remaining)
SYN Stealth Scan Timing: About 75.86% done; ETC: 13:44 (0:02:27 remaining)
Discovered open port 49663/tcp on 10.10.65.43
SYN Stealth Scan Timing: About 81.17% done; ETC: 13:44 (0:01:54 remaining)
SYN Stealth Scan Timing: About 86.50% done; ETC: 13:44 (0:01:22 remaining)
SYN Stealth Scan Timing: About 91.92% done; ETC: 13:44 (0:00:49 remaining)
Completed SYN Stealth Scan at 13:44, 619.02s elapsed (65535 total ports)
Initiating Service scan at 13:44
Scanning 8 services on 10.10.65.43
Completed Service scan at 13:45, 60.85s elapsed (8 services on 1 host)
Initiating OS detection (try #1) against 10.10.65.43
Retrying OS detection (try #2) against 10.10.65.43
NSE: Script scanning 10.10.65.43.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 13:46
Completed NSE at 13:46, 1.90s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 13:46
Completed NSE at 13:46, 1.89s elapsed
Nmap scan report for 10.10.65.43
Host is up, received user-set (0.43s latency).
Scanned at 2021-01-16 13:34:37 IST for 691s
Not shown: 65527 filtered ports
Reason: 65527 no-responses
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 125 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
49663/tcp open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=1/16%OT=80%CT=%CU=%PV=Y%G=N%TM=6002A0C8%P=x86_64-pc-linux-gnu)
SEQ(SP=FF%GCD=1%ISR=10D%TI=I%II=I%SS=S%TS=A)
OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M505NW8ST11%O5=M505NW8ST11%O6=M505ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.011 days (since Sat Jan 16 13:29:42 2021)
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows



Important Ports

80/tcp    open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 125 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
49663/tcp open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
49666/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC




'''
UDP Scan 
'''
sudo nmap -sS -sU $ip -oN nmap/udpscan
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-16 21:12 IST
Nmap scan report for 10.10.55.247
Host is up (0.43s latency).
Not shown: 1000 open|filtered ports, 995 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

 sudo nmap -Pn -sU --script=smb-vuln* -p 139,445,135,3389 $ip -oN nmap/udpVulnScriptScan 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-16 22:08 IST
Nmap scan report for 10.10.55.247
Host is up.

PORT     STATE         SERVICE
135/udp  open|filtered msrpc
139/udp  open|filtered netbios-ssn
445/udp  open|filtered microsoft-ds
3389/udp open|filtered ms-wbt-server

-------Little Verbose Scan---------------




'''

'''


After all the possible technique which i found out was being dropped due to the firewall, so we need our scans to be more stealthy and i need to follow back the nmap recon cycle.


'''

Nmap Scanning cycle

'''
1. Script pre-scanning

Looked for some scripts running but didn't find any thing now the major issue of my scan is that whenever i am increasing the level of my verbose scan option the firewall is filtering it heavily.

To bypass firewall

sudo nmap -sU -sF -p 135,139,445,49663,49666,49668 $ip -oN nmap/finflagScan -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-16 23:08 IST
Nmap scan report for 10.10.55.247
Host is up.

PORT      STATE         SERVICE
135/tcp   open|filtered msrpc
139/tcp   open|filtered netbios-ssn
445/tcp   open|filtered microsoft-ds
49663/tcp open|filtered unknown
49666/tcp open|filtered unknown
49668/tcp open|filtered unknown
135/udp   open|filtered msrpc
139/udp   open|filtered netbios-ssn
445/udp   open|filtered microsoft-ds
49663/udp open|filtered unknown
49666/udp open|filtered unknown
49668/udp open|filtered unknown


'''
Bypassing firewall to get more information from the open ports

'''

Presence of firewall

traceroute 10.10.166.149
traceroute to 10.10.166.149 (10.10.166.149), 30 hops max, 60 byte packets
 1  10.2.0.1 (10.2.0.1)  265.856 ms  266.216 ms  266.206 ms
 2  * * *
 3  * * *
 4  * * *
 5  * * *
 6  * * *
 7  * * *
 8  * * *
 9  * * *
10  * * *
11  * * *
12  * * *
13  * * *
14  * * *
15  * * *
16  * * *

We can do fire-walking to bypass the firewall to check for the open ports so that we can enumerate more information from the open ports which we will use in further penetration testing.

hping3 -S $ip -c 100 -p ++1
[open_sockraw] socket(): Operation not permitted
[main] can't open raw socket


'''

'''

sudo nmap -f -sV -vv -O $ip
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-17 09:05 IST
NSE: Loaded 45 scripts for scanning.
Initiating Ping Scan at 09:05
Scanning 10.10.166.149 [4 ports]
Completed Ping Scan at 09:05, 0.45s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:05
Completed Parallel DNS resolution of 1 host. at 09:05, 0.00s elapsed
Initiating SYN Stealth Scan at 09:05
Scanning 10.10.166.149 [1000 ports]
Discovered open port 3389/tcp on 10.10.166.149
Discovered open port 135/tcp on 10.10.166.149
Discovered open port 139/tcp on 10.10.166.149
Discovered open port 445/tcp on 10.10.166.149
Discovered open port 80/tcp on 10.10.166.149
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 48.25% done; ETC: 09:05 (0:00:17 remaining)
Completed SYN Stealth Scan at 09:05, 24.57s elapsed (1000 total ports)
Initiating Service scan at 09:05
Scanning 5 services on 10.10.166.149
Completed Service scan at 09:05, 14.07s elapsed (5 services on 1 host)
Initiating OS detection (try #1) against 10.10.166.149
Retrying OS detection (try #2) against 10.10.166.149
NSE: Script scanning 10.10.166.149.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 09:05
Completed NSE at 09:05, 1.85s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 09:05
Completed NSE at 09:05, 1.65s elapsed
Nmap scan report for 10.10.166.149
Host is up, received echo-reply ttl 125 (0.42s latency).
Scanned at 2021-01-17 09:05:03 IST for 50s
Not shown: 995 filtered ports
Reason: 995 no-responses
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 125 Microsoft IIS httpd 10.0
135/tcp  open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  syn-ack ttl 125 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_10:1607
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=1/17%OT=80%CT=%CU=%PV=Y%G=N%TM=6003B099%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=10E%TI=I%II=I%SS=S%TS=A)
OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M505NW8ST11%O5=M505NW8ST11%O6=M505ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.014 days (since Sun Jan 17 08:45:34 2021)
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows


nmap -sV --script=vuln -p 49668,49666,49663,3389,445,80 -oN nmap/versionVulnScan.nmap 10.10.166.149
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-17 09:17 IST
Nmap scan report for 10.10.166.149
Host is up (0.41s latency).

PORT      STATE    SERVICE       VERSION
80/tcp    open     http          Microsoft IIS httpd 10.0
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Microsoft-IIS/10.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
445/tcp   open     microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open     ms-wbt-server Microsoft Terminal Services
|_sslv2-drown: 
49663/tcp open     http          Microsoft IIS httpd 10.0
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Microsoft-IIS/10.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
49666/tcp filtered unknown
49668/tcp open     msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143




'''
Enumeration Script

'''
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Jan 17 10:16:45 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.122.213
RID Range ........ 500-550,1000-1050
Username ......... 'RELEVANT'
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===================================================== 
|    Enumerating Workgroup/Domain on 10.10.122.213    |
 ===================================================== 
[E] Can't find workgroup/domain


 ============================================= 
|    Nbtstat Information for 10.10.122.213    |
 ============================================= 
Looking up status of 10.10.122.213
No reply from 10.10.122.213

 ====================================== 
|    Session Check on 10.10.122.213    |
 ====================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[+] Server 10.10.122.213 allows sessions using username 'RELEVANT', password ''
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 451.
[+] Got domain/workgroup name: 

 ============================================ 
|    Getting domain SID for 10.10.122.213    |
 ============================================ 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 359.
Bad SMB2 signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 50 36 5E 51 7A 0B 04 E7   95 D4 0F CC 55 E2 58 64   P6^Qz... ....U.Xd
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================= 
|    OS information on 10.10.122.213    |
 ======================================= 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 458.
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.122.213 from smbclient: 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 467.
[+] Got OS info for 10.10.122.213 from srvinfo:
Bad SMB2 signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] D0 33 E6 41 49 D9 53 8E   3A CB 1F 8C 6D 2C A6 2D   .3.AI.S. :...m,.-
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

 ============================== 
|    Users on 10.10.122.213    |
 ============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 881.
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED

 ========================================== 
|    Share Enumeration on 10.10.122.213    |
 ========================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 640.

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk      
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.122.213
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.122.213/ADMIN$	Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.122.213/C$	Mapping: DENIED, Listing: N/A
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 654.
//10.10.122.213/IPC$	[E] Can't understand response:
NT_STATUS_INVALID_INFO_CLASS listing \*
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum


 ===================================================== 
|    Password Policy Information for 10.10.122.213    |
 ===================================================== 
[E] Unexpected error from polenum:


[+] Attaching to 10.10.122.213 using RELEVANT

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:10.10.122.213)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: rpc_s_access_denied

Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 501.

[E] Failed to get password policy with rpcclient


 =============================== 
|    Groups on 10.10.122.213    |
 =============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting builtin groups:

[+] Getting builtin group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 542.

[+] Getting local groups:

[+] Getting local group memberships:
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 593.

[+] Getting domain groups:

[+] Getting domain group memberships:

 ======================================================================== 
|    Users on 10.10.122.213 via RID cycling (RIDS: 500-550,1000-1050)    |
 ======================================================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 710.
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 742.

 ============================================== 
|    Getting printer info for 10.10.122.213    |
 ============================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 991.
Bad SMB2 signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] 4C 43 3F 7B 09 7C DB 4F   9C A3 63 FE 26 12 54 10   LC?{.|.O ..c.&.T.
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Sun Jan 17 10:18:07 2021

'''

Password from smb share with screen shot in forensic files.

'''

[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk

So if we convert it to simple string
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$

Tried credentials at https://msft-sme.myget.org/Account/Login?ReturnUrl=%2Ffeed%2FIndex%2Fwindows-admin-center-feed
but it didn't pass with any of the above accounts.

'''

Its time for some gobuster scan

'''

After the gobuster scan at 10.10.206.29:49663, where i found out a directory nt4wrksv. http://10.10.206.29:49663/nt4wrksv/
Let's go to http://10.10.206.29:49663/nt4wrksv/
It's redirecting us to some page.


'''

Nikto Scan

'''

- Nikto v2.1.6
-------------------------------------------------------------------------

--
+ Target IP:          10.10.206.29
+ Target Hostname:    10.10.206.29
+ Target Port:        49663
+ Start Time:         2021-01-17 15:46:07 (GMT5.5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/10.0
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 4.0.30319
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect (timeout): Operation now in progress


'''
I need to try some banner grabbing techniques

'''

(NC,FTP,telnet,SSH Backdoor(after getting back a shell)

Lets try some banner grabbing if we find any possible clue.

------------------

No possible outcome from nc on the available ports. I guess the firewall migth be blocking any message header.




------------------
pranay@pranay:~/ctf/thm/relevant$ wget http://$ip:49663/nt4wrksv
--2021-01-18 23:11:21--  http://10.10.0.104:49663/nt4wrksv
Connecting to 10.10.0.104:49663... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: http://10.10.0.104:49663/nt4wrksv/ [following]
--2021-01-18 23:11:22--  http://10.10.0.104:49663/nt4wrksv/
Reusing existing connection to 10.10.0.104:49663.
HTTP request sent, awaiting response... 200 OK
Length: 0
Saving to: ‘nt4wrksv’

nt4wrksv                     [ <=>                            ]       0  --.-KB/s    in 0s      

2021-01-18 23:11:22 (0.00 B/s) - ‘nt4wrksv’ saved [0/0]

pranay@pranay:~/ctf/thm/relevant$ ls
forensic  gobuster  hash-identifier  nikto.txt  nmap  nt4wrksv  pingSweepScan.nmap  README.md
pranay@pranay:~/ctf/thm/relevant$ cat n
nikto.txt  nmap/      nt4wrksv   
pranay@pranay:~/ctf/thm/relevant$ cat nt4wrksv 
pranay@pranay:~/ctf/thm/relevant$ wget http://$ip:49663/nt4wrksv/
--2021-01-18 23:11:56--  http://10.10.0.104:49663/nt4wrksv/
Connecting to 10.10.0.104:49663... connected.
HTTP request sent, awaiting response... 200 OK
Length: 0
Saving to: ‘index.html’

index.html                   [ <=>                            ]       0  --.-KB/s    in 0s      

2021-01-18 23:11:57 (0.00 B/s) - ‘index.html’ saved [0/0]

pranay@pranay:~/ctf/thm/relevant$ ls
forensic  hash-identifier  nikto.txt  nt4wrksv            README.md
gobuster  index.html       nmap       pingSweepScan.nmap
pranay@pranay:~/ctf/thm/relevant$ cat index.html 
pranay@pranay:~/ctf/thm/relevant$ string index.html 
bash: string: command not found
pranay@pranay:~/ctf/thm/relevant$ string index.html 
bash: string: command not found
pranay@pranay:~/ctf/thm/relevant$ strings index.html 
pranay@pranay:~/ctf/thm/relevant$ 




'''


'''
In smb share i found out that we can upload our scripts into the share
so i uploaded aspx file into smbshre and executed the file using curl and we get a reverse shell into our system

whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled



'''



'''

PrintSpoofer exploit that can be used to escalate service user permissions on Windows Server 2016, Server 2019, and Windows 10.

To escalate privileges, the service account must have SeImpersonate privileges. To execute:

PrintSpoofer.exe -i -c cmd
With appropriate privileges this should grant system user shell access.



'''
'''
User Flag
THM{fdk4ka34vk346ksxfr21tg789ktf45}

Root Flag
THM{1fk5kf469devly1gl320zafgl345pv}

'''
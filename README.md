# Penetration-Testing

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
- [ ] Penetration Testing                                                                                                     

 
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
# SQLi WAF                                                                                                            
# LFI Vulnerability                                                                                                 
# Advance LFI (LFI to RCE)                                                                                     
# Web Shell Upload                                                                                                   
# CSRF Vulnerability                                                                                                    
# Kali Linux Tools                                                                                                                 
# Penetration Testing   

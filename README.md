# log4shell
Some information one find useful for incident response purposes. What should you do now to handle this? Well ... Let's give it a try:

1. Identify what is vulnerable within your network
2. Search for your vendors security advisories and act accordingly
3. Deploy updates where possible (**log4j >= 2.15.0**)
4. Shutdown systems you really don't need to survive
5. All other systems should be tightly monitored

## Basic stuff
- What? https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228
- Sophos Security Advisory: https://www.sophos.com/en-us/security-advisories/sophos-sa-20211210-log4j-rce
- McAfee Security Advisory: https://kc.mcafee.com/corporate/index?page=content&id=KB95091
- F-Secure Security Advisory: https://status.f-secure.com/incidents/sk8vmr0h34pd

## 1 - Identify what is vulnerable

### Linux

Anything **older** then 2.15.0 might give you problems.

``find / -type f -name 'log4j-core*'``

### Windows

Powershell:

``Get-ChildItem -Recurse -Filter 'log4j-core*'``

### Web & Embedded systems
If you cannot touch the target system in a way to search for the installation of the system you can test your way through an application. This can be done manually, or semi-automatically with Burp (Professional I guess, since you need the Intruder) or OWASP ZAP:

- Go to https://canarytokens.org/generate
- Select **Log4Shell** (the last one)
- Add an Email address to recieve messages when something is detected as possibly vulnerable (GMail comes in handy: yourgmail+theserviceyoutest@gmail.com)
- Reminder note or label in case you don't have GMail in use
- Copy your canary token test String
- Walk to the interface you want to test
- Activate maximum logging within the web application
- Enter the string everywhere you can and see if you get an email

### Links

- What is vulnerable, according to others Nr.1: https://github.com/YfryTchsGD/Log4jAttackSurface
- What is vulnerable, according to others Nr.2: https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592
- Find vulnerability with scripts: https://gist.github.com/byt3bl33d3r/46661bc206d323e6770907d259e009b6


## 2 - Search for your vendors security advisories and act acoordingly
This one is tricky since you need to have email newsletters activated and/or recieve emails from your account manager or any other people working for your vendors.

- Make a list of all the systems you know you have
- Write down the vendor contact you know for every systems
- Contact them and ask for advice what to do and when to expect patches

## 3 - Deploy updates where possible (**log4j >= 2.15.0**)
Change different parameters for log4j if you have access to it (log4j >= 2.10). Be careful since this change might break something else you are not aware you might need?

- Start the JVM with this parameter: ```-Dlog4j2.formatMsgNoLookups=True```
- Or: Set the environment variable **LOG4J_FORMAT_MSG_NO_LOOKUPS** on **true**

## 4 - Shutdown systems you really don't need to survive
I don't have to explain this, right?

## 5 - All other systems should be tightly monitored

### Networking
Rewrap your network design and make it tight. Isolate the vulnerable devices, if possible, as quick as you can into one quarantine subnet. Restrict traffic to the minimum needed. Go for logging.

### Logging
- Activate the logs of any vulnerable system to the maximum
- Activate the firewall logs in a way to monitor outgoing connections
- Review the logs by yourself if you have time for this
- Send the logs regularly to your security professional of trust
- Let us do our work and identify malicious stuff

### More technology
All of the following categories of systems could help to prevent an attack on unpatched systems. Obviously you need to know how to deploy and configure it properly to identify a malicious scan for the vulnerability.

- Web Application Firewalls
- Intrusion Prevent Systems
- Reverse Proxies

### IOCs / Payload

- https://blog.netlab.360.com/threat-alert-log4j-vulnerability-has-been-adopted-by-two-linux-botnets/

#### DoH services
Used by Muhstik (Log4shell Payload)

```
doh.defaultroutes.de
dns.hostux.net
dns.dns-over-https.com
uncensored.lux1.dns.nixnet.xyz
dns.rubyfish.cn dns.twnic.tw
doh.centraleu.pi-dns.com
doh.dns.sb doh-fi.blahdns.com
fi.doh.dns.snopyta.org
dns.flatuslifir.is
doh.li
dns.digitale-gesellschaft.ch
```

#### Related TOR nodes

```
bvprzqhoz7j2ltin.onion.ws
bvprzqhoz7j2ltin.onion.ly
bvprzqhoz7j2ltin.tor2web.s
```

#### C2 servers

```
nazi.uy
log.exposedbotnets.ru
```

#### URLS

```
http://62.210.130.250/lh.sh
http://62.210.130.250:80/web/admin/x86_64
http://62.210.130.250:80/web/admin/x86
http://62.210.130.250:80/web/admin/x86_g
http://45.130.229.168:9999/Exploit.class
http://18.228.7.109/.log/log
http://18.228.7.109/.log/pty1;
http://18.228.7.109/.log/pty2;
http://18.228.7.109/.log/pty3;
http://18.228.7.109/.log/pty4;
http://18.228.7.109/.log/pty5;
http://210.141.105.67:80/wp-content/themes/twentythirteen/m8
http://159.89.182.117/wp-content/themes/twentyseventeen/ldm
```


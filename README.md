# log4shell
Some information one find useful for incident response purposes. What should you do now to handle this? Well ... Let's give it a try:

1. Identify what is vulnerable within your network
2. Search for your vendors security advisories and act accordingly
3. Deploy updates where possible (**log4j >= 2.15.0**)
4. Shutdown systems you really don't need to survive
5. All other systems should be tightly monitored

## 1 - Identify what is vulnerable

### Linux

Anything **older** then 2.15.0 might give you problems.

``find / -type f -name 'log4j-core*'``

### Windows

Powershell:

``Get-ChildItem -Recurse -Filter 'log4j-core*'``

### Web & Embedded systems
If you cannot touch the target system in a way to search for the installation of the system you can test your way through an application. This can be done manually, or semi-automatically with Burop or OWASP ZAP:

- Go to https://canarytokens.org/generate
- Select **Log4Shell** (the last one)
- Add an Email address to recieve messages when something is detected as possibly vulnerable (GMail comes in handy: yourgmail+theserviceyoutest@gmail.com)
- Reminder note or label in case you don't have GMail in use
- Copy your canary token test String
- Walk to the interface you want to test
- Activate maximum logging within the web application
- Enter the string everywhere you can and see if you get an email

### Links

- https://github.com/YfryTchsGD/Log4jAttackSurface


## 2 - Search for your vendors security advisories and act acoordingly
This one is tricky since you need to have email newsletters activated and/or recieve emails from your account manager or any other people working for your vendors.

- Make a list of all the systems you know you have
- Write down the vendor contact you know for every systems
- Contact them and ask for advice what to do and when to expect patches

## 3 - Deploy updates where possible (**log4j >= 2.15.0**)
TBD

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

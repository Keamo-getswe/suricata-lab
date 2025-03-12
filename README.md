# Suricata Lab

## Overview

An Intrusion detection systems (IDS) is a security control implemented to accurately identify and alert security teams of malicious activity. Suricata is an open-source IDS that can detect threats by comparing network traffic against its database of known attack signatures. In this project, I set up a virtualized home lab inspired by and under the guidance of [this repo](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab) to deploy and test Suricata IDS against simulated cyber attacks. By configuring Suricata on an Ubuntu virtual machine (VM), a victim VM, a Kali Linux VM equipped with penetration testing tools (Tcpdump, Nmap and Metasploit Framework), this lab provided a controlled environment to develop and refine Suricata detection rules.

## Network Diagram

<p align="center">
  <img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/suricata-lab-diagram.png?raw=true" width="60%"/>
</p>

## Environment Setup

### System Specification

The lab was set up using 2 computers, one with the defended network and 1 with which to attack. The defended network VMs ran on a Windows 11 machine using 16GB RAM and 500GB storage. The attacker VM ran on Ubuntu 22.04 machine using 8GB RAM and 500GB storage. VMs were hosted on Oracle VirtualBox on both physical machines.

The following VM provisions were made for the defended network devices on VirtualBox:
<br>

| Machine Function | RAM (GB) | Processors | Storage (GB) |
|---------- |----------|----------|----------|
| Suricata Ubuntu Server 22.04 | 4 | 3 | 30 |
| Metasploitable 2 | 4 | 3 | 8 |

Unlike the previous 2 VMs which used disk images, the attacker VM was setup using a .vbox file acquired from [the Kali website](http://www.kali.org). As such, a 80GB preset storage was provisioned along with 4GB RAM and 4 CPU cores. The .vbox setup was done so that Kali could be used out the box. The Suricata server, under Settings > Network > Advanced > Promiscuous Mode was set to Allow All to support network analyser

### Attacker Machine - Kali Linux

Once system was booted, the user logged in and an internet connection was established, a package update and upgrade was performed:<br>
```sudo apt-get update && sudo apt-get upgrade -y ```

In addition, the system was checked for the required tools (Nmap and Metasploit Framework).

### Suricata IDS - Ubuntu Server 22.04

After configuration and resource provisioning in VirtualBox, the same process was repeated following the initial boot. Suricata was then installed using:<br>
```sudo apt-get install suricata -y```

Upon completion, the installation was confirmed using:<br>
```apt list | grep suricata```

Thereafter, the suricata service was checked using:<br>
```sudo systemctl status suricata```

The service was up and running. The Suricata /etc/suricata/suricata.yaml file was then configured as follows:
- Defined the HOME_NET variable based all devices on this defended network.
- Set EXTERNAL_NET to "any".
- Specified the rule location as /etc/suricata/rules/custom.rules (and later created the file).
- Set the packet capture interface to that of my local machine.
- To test that Suricata could monitor network traffic, the following rule was added to the custom.rules file:<br>
```alert icmp any any -> $HOME_NET any (msg:"Ping Test detected"; sid: 1000000; rev:1;)```
- After saving the file, Suricata was restarted using:<br>
```sudo systemctl restart suricata```
- To ensure that the configuration worked, the Suricata log file was checked using:<br>
```cat /var/log/suricata.suricata.log```
- Verified successful configuration from MTU being found for the specified network interface, all default log files being initialised, the rule being processed with the 1 rule in it being successfully loaded and all AFP capture threads running.
- To test the rule, a ping test was initiated from the attacker machine to this machine's IP address. I then searched for the alert message for the rule in /var/log/suricata/eve.json on the Suricata server.

Finally, tcpdump was installed using:<br>
```sudo apt install tcpdump```

Once complete, the download was confirmed using:<br>
```apt list | grep tcpdump```

This would later be used to derive rules from more complex conversations between the attacker and victim.

### Metasploitable 2

As before, the system was configured, booted and logged in, however given that Metasploitable 2 is a legacy system, packages were not updated/upgraded. On boot, glimpses of service initialisation was seen but to see which ones were available, I ran an Nmap from the attacker machine to confirm running services.

## Simulating and Detecting Attacks:

To monitor the communication between the attacker and the victim (Metasploitable machine), tcpdump was initiated on the Suricata server using this command:<br>
```sudo tcpdump -i <interface> -vvv -nn "host <attacker IP address> > foo.txt```<br>
Thereafter, an attack was launched and once completed, the packet capture was stopped and the contents examined for patterns that could address each challenge.

### Stealth Scan

Challenge: _Create a Suricata rule to detect TCP SYN packets sent to multiple ports within a short time frame, indicative of Nmap stealth scans._

The command for the scan was:<br>
```nmap -sS 192.168.8.230```<br>
The result of the scan was:<scan-screenshot>
The rule crafted was:<br>
```alert tcp any any -> $HOME_NET any (msg: "Possible Nmap stealth scan detected"; flag: S; window: 1024; threshold: typ both, track_by_src, count 5, seconds 10, sid: 1000001; rev:1;)```<br>
This rule alerts on TCP packets, with the SYN flag set, for any port in $HOME_NET. It specifically triggers when a single source sends 5 or more SYN packets within 10 seconds.

### OS Fingerprinting Scan

Challenge: _Develop a Suricata rule to detect ICMP echo requests and responses with specific TTL values, characteristic of Nmap OS fingerprinting activities._

The command for the scan was:<br>
```nmap -O 192.168.8.230```<br>
The result of the scan was:<br><scan-screenshot><br>
The rules crafted were:<br>
```alert icmp any any -> $HOME_NET any (msg: "ECHO ICMP request detected"; ttl:>45; ttl:<60; sid: 1000002; rev:1;)```<br>
```alert icmp $HOME_NET any -> any any (msg: "ECHO ICMP response detected"; ttl: 64; sid: 1000003; rev:1;)```<br>
The first rule alerts on ICMP Echo Request packets sent to $HOME_NET with a TTL between 46 and 5,9 which may help detect operating system specific fingerprinting attempts or unusual ping behavior. The second rule alerts on responses sent with TTL values of 64 (characteristic of Linux-based operating systems).

### Service Version Scan

Challenge: _Formulate a Suricata rule to detect Nmap service version detection probes based on unique HTTP GET requests or TCP SYN/ACK packets._

The command for the scan was:<br>
```nmap -sV 192.168.8.230```<br>
The result of the scan was:<br><scan-screenshot><br>
The rule crafted was:<br>
```alert tcp any any -> $HOME_NET any (msg: "Nmap service version scan detected"; flow:established, to_server; content: "nmap"; http_header; sid: 1000004; rev:1;)```<br>
This rule looks for the string "nmap" in the HTTP headers of TCP traffic going to $HOME_NET when the connection is established and directed to a server.

### Metasploit Exploit Payload - Unreal IRC 3281 (add user payload)

Challenge: _Craft a Suricata rule to detect Metasploit exploit payload traffic based on unique signatures or payloads commonly used in exploits._

Metasploit Framework was launched using ```msfconsole``` on the attacker. With reference to the service versions obtained earlier, an exploit for the Unreal IRC was found using:<br>
```msf6> search unreal irc```<br>
The result of the scan was:<br><scan-screenshot><br>
The rule crafted was:<br>
```alert tcp any any -> $HOME_NET any (msg: "Nmap service version scan detected"; flow:established, to_server; content: "nmap"; http_header; sid: 1000004; rev:1;)```<br>
This rule looks for the string "nmap" in the HTTP headers of TCP traffic going to $HOME_NET when the connection is established and directed to a server.

- Perform network reconnaissance (Nmap scans) and detect scan patterns.
- Launch remote code execution attacks (Metasploit exploits) and monitor reverse shells.

## Evaluating and Improving Detection:

- Analyze Suricata logs to validate detections and refine rules.
- Review false positives/negatives and adjust rule sensitivity.
- Document findings and potential improvements to enhance Suricata’s detection capabilities.

## Lessons Learned & Improvements:

- Insights gained from the setup and attacks.
- Possible enhancements:
    - Executing more attack types for exposure to more attack vectors.
    - Forwarding logs to a SIEM to exercise other SOC analyst skills.

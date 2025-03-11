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

### Stealth Scan

Tcpdump was initiated using the following command:<br>
```sudo tcpdump -i <interface> -vvv -nn "host <attacker IP address> > stealth.txt```<br>
The following was then run from the attacker, targeting the Metasploitable machine:<br>
```nmap -sS 192.168.0.230```<br>

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

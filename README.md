# Suricata Lab

## Overview

An Intrusion detection systems (IDS) is a security control implemented to accurately identify and alert security teams of malicious activity. Suricata is an open-source IDS that can detect threats by comparing network traffic against its database of known attack signatures. In this project, I set up a virtualized home lab inspired by and under the guidance of [this repo](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab) to deploy and test Suricata IDS against simulated cyber attacks. By configuring Suricata on an Ubuntu virtual machine (VM), a victim VM, a Kali Linux VM equipped with penetration testing tools (Tcpdump, Nmap and Metasploit Framework), this lab provided a controlled environment to develop and refine Suricata detection rules.

## Network Diagram

<p align="center">
  <img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/suricata-lab-diagram.png?raw=true" width="60%"/>
</p>

## Environment Setup

### System Specification

The lab was set up using 2 computers, one with the defended network and 1 with which to attack. The defended network was run on a Windows 11 machine using 16GB RAM and 500GB storage. The attacker ran on Ubuntu 22.04 machine using 8GB RAM and 500GB storage. VMs were hosted on Oracle VirtualBox on both physical machines.

The following VM configurations were applied on VirtualBox:
<br>

| Machine Function | RAM (GB) | Processors | Storage (GB) |
|---------- |----------|----------|----------|
| Suricata Ubuntu Server 22.04 | 4 | 3 | 30 |
| Metasploitable 2 | 4 | 3 | 8 |

### Suricata IDS - Ubuntu Server 22.04

Once system was booted, the user logged in and was connected to the internet, a package update and upgrade was performed:<br>
```sudo apt-get update && sudo apt-get upgrade -y ```

Suricata was then installed using:<br>
```sudo apt-get install suricata -y```

Upon completion, the installation was confirmed using:<br>
```apt list | grep suricata```

Thereafter, the suricata service was checked using:<br>
```sudo systemctl status suricata```

The service was up and running. The Suricata /etc/suricata/suricata.yaml file was then configured as follows:
- Defined the HOME_NET variable based a custom subnet.
- Set EXTERNAL_NET to "any".
- Specified the rule location as /etc/suricata/rules/custom.rules (and later created the file).
- To test the functioning of Suricata, the following rule was added to the custom.rules file:<br>
```alert any any -> $HOME_NET any (msg:""; flags:S; window:1024; threshold: type both, track_by_src, count 5, seconds 10; sid: 1000001; rev:1;)```
- After saving the file, suricata was restarted using:
```sudo systemctl restart suricata```

### Deploy and configure the lab environment (Kali Linux VM)

- Configure Kali Linux as an attacker machine with penetration testing tools.

## Simulating and Detecting Attacks:

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

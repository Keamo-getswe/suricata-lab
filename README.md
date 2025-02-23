# Suricata Lab

## Overview

In this project, I set up a virtualized home lab inspired by and under the guidance of [this repo](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab) to deploy and test Suricata IDS against simulated cyber attacks. Using a combination of Ubuntu-based virtual machines, vulnerable applications (DVWA, Metasploitable 2), and penetration testing tools (Tcpdump, Nmap, Hydra, Metasploit), this lab provided a controlled environment to develop and refine Suricata detection rules. 

## Network Diagram

<p align="center">
  <img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/suricata-lab-diagram.png?raw=true" width="60%"/>
</p>

## Environment Setup:

- Deploy and configure a lab environment i.e. Ubuntu based virtual machines.
- Install and configure Suricata IDS on a dedicated monitoring VM.
- Set up vulnerable targets (DVWA, Metasploitable 2) for attack simulations.
- Configure Kali Linux as an attacker machine with penetration testing tools.

## Configuring Suricata:

- Setup up Suricata for intrusion detection on local hardware.
- Define a minimal rule set on Suricata as a baseline.
- Test logging and verify settings were error free.

## Simulating and Detecting Attacks:

- Perform network reconnaissance (Nmap scans) and detect scan patterns.
- Exploit web vulnerabilities (SQL injection, brute-force login) and create detection rules.
- Launch remote code execution attacks (Metasploit exploits) and monitor reverse shells.
- Detect brute-force SSH attacks using Hydra.

## Evaluating and Improving Detection:

- Analyze Suricata logs to validate detections and refine rules.
- Review false positives/negatives and adjust rule sensitivity.
- Document findings and potential improvements to enhance Suricata’s detection capabilities.

## Lessons Learned & Improvements:

- Insights gained from the setup and attacks.
- Possible enhancements:
    - Executing more attack types for exposure to more attack vectors.
    - Forwarding logs to a SIEM to exercise other SOC analyst skills.

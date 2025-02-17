# Suricata-lab

## 1. Overview

In this project, I set up a virtualized home lab inspired by and under the guidance of [this repo](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab) to deploy and test Suricata IDS against simulated cyber attacks. Using a combination of Ubuntu-based virtual machines, vulnerable applications (DVWA, Metasploitable 2), and penetration testing tools (Tcpdump, Nmap, Hydra, Metasploit), this lab provided a controlled environment to develop and refine Suricata detection rules. 

## 2. Network Diagram
Placeholder.

## 3. Environment Setup:

- Deploy and configure a lab environment i.e. Ubuntu based virtual machines.
- Install and configure Suricata IDS on a dedicated monitoring VM.
- Set up vulnerable targets (DVWA, Metasploitable 2) for attack simulations.
- Configure Kali Linux as an attacker machine with penetration testing tools.

## 4. Configuring Suricata:

- Setup up Suricata for intrusion detection on local hardware.
- Define a minimal rule set on Suricata as a baseline.
- Test logging and verify settings were error free.

## 5. Simulating and Detecting Attacks:

- Perform network reconnaissance (Nmap scans) and detect scan patterns.
- Exploit web vulnerabilities (SQL injection, brute-force login) and create detection rules.
- Launch remote code execution attacks (Metasploit exploits) and monitor reverse shells.
- Detect brute-force SSH attacks using Hydra.

## 6. Evaluating and Improving Detection:

- Analyze Suricata logs to validate detections and refine rules.
- Review false positives/negatives and adjust rule sensitivity.
- Document findings and potential improvements to enhance Suricata’s detection capabilities.



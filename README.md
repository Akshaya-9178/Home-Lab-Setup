# Home-Lab-Setup
## Building My Own Home SOC Lab with IDS, Splunk and Attack Simulation

As a cybersecurity student and aspiring SOC analyst, I recently built a home lab to simulate real-world attack and defense scenarios. The goal of this lab is to get hands-on experience with intrusion detection, alerting and actual Security Operation Center (SOC).

In this blog, i'll walk you through how i set up my lab and how i used it to simulate attacks, generate IDS alert using Snort and forward those alert to splunk for analysis.

Home Lab Setup :

I built the lab using VirtualBox and create the following virtual machines,

Kali Linux :- Used as the attacker machine to simulate various cyberattacks.<br>
Windows10 :- Acts as the victim machine.<br>
Metasploitable :- Another intentionally vulnerable target system.<br>
Ubuntu :- Server as both the splunk Enterprise server and the host for Snort IDS/IPS.<br>
Splunk Universal Forwarder :- Installed on Ubuntu to send Snort logs to splunk.<br>

Snort IDS/IPS :

I install Snort on the Ubuntu VM and configured it in IDS mode to monitor traffic across my internal network. I wrote custom Snort rules to detect specific attack signature. For example: 

alert tcp any any -> 192.168.1.110 445 (msg:"SMB Exploit Attempt"; sid:1000001; rev:1;)<br>
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000002; rev:1;)

This rule triggers an alert when someone attempts to connect to the SMB port(445) or ping on the Windows10 machine.

Splunk + Universal Forwarder :

To collect and analyze logs I installed splunk Enterprise on the same Ubuntu server and used Splunk Universal Forwarder to forward Snort's alert logs to Splunk in real time.

This setup lets me monitor the lab environment, trigger alerts from Snort and then visualize and analyze those alerts within Splunk.

Simulating Attacks :

I used Kali Linux to simulate various types of attacks, such as:

Nmap scans<br>
SMB enumeration<br>
Brute-force attempts<br>
Metasploit-based exploitation

The victim machines (Windows10 and Metasploitable) were the targets. When attacks were launched from Kali, Snort monitored the traffic and when the traffic matched any defined rule, it generated an alert. 

Here's what happened next:

Snort detected the attack and wrote an alert to its log file. The Splunk Forwarder picked up that alert and sent it to my Splunk server. Insede Splunk, I used custom dashboards and search queries to monitor and analyze the events.

Analyzing the Alert in Splunk :

Once the alert were in Splunk, I could perform indepth analysis. I built basic dashboards that show: 

Source IP of the attack<br>
Destination IP (Victim)<br>
Type of attack (based on Snort rule msg)<br>
Time of event

Sample Splunk search query:

index=snort_alert sourcetype=snort_alert msg=*

This allow me to track real-time attack and gain SOC-style experience in threat detection, triage and investigation.

What I Learned :

Setting up this Home Lab taught me valuable skills:

Writing and testing Snort IDS rules<br>
Using splunk Universal Forwarder to send data to Splunk<br>
Building visual dashboards and alerts in Kali Linux<br>
Undestanding how SOC teams analyze and respond to threats.

Next Steps (I plane to) :

Add Suricata alongside Snort for comparison.<br>
Integrate Sysmon on the Windows VM for deeper endpoint visibility<br>
Explore SOAR tools to automate incident response.

If you're learning cybersecurity or want to practice threat detection hands-on, building a home SOC Lab like this is one of the best things you can do. Not only does it solidify your theoretical knowledge, but it also prepares you for real-world scenarios in blue team enviroments.

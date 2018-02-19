---
layout: post
title: "My Final Project, Virtual Firewall"
date: 2018-02-19
---

Introduction:

This firewall is built on a linux machine which comprises of a netfilter framework . Netfilter is a packet filtering system within the system and provides a series of 5 hooks over different points of the kernel network stack. Kernel module functions or userspace functions can be registered against these hooks and can be used to pass a decision on the traversal of the packet.

Here we have transferred all packets to userspace using iptables and nfqueue.The running code registered against respective queue number will pass a verdict on the packets.


Netfilter Architecture:

![Architecture](/assets/netfilter_arch.PNG){:class="img-responsive"}

An incoming IP packet travels in the path shown in the figure. It passes through hooks where different functions (dropping, mangling, etc) to exploit these packets can be defined. Initially the packet passes through NF_IP_PRE_ROUTING hook after which it passes through routing code which decided whether it is meant for a local process or to another machine.If it's for the current machine, then netfilter framework is called for the NF_IP_LOCAL_IN hook before being passed to local process. If not for this machine, then it's passed on to the NF_IP_FORWARD hook and finally to NF_IP_POST_ROUTING hook. The hooks are triggered by the kernel after implementation of network procedures.
Kernel modules can register a new table of iptables and ask for a packet to traverse a given table. Several tables of iptables hook onto the NF_IP_LOCAL_IN,NF_IP_FORWARD and NF_IP_LOCAL_OUT points. Netfilter provides a special target in iptables called nfqueue to register user programs for these hooks. Incoming packets get queued to these and are served by the programs. One program can bind to one or several queues using libnetfilter_queue library.  This library can receive queued packets from kernel nfnetlink_queue subsystem, issue verdicts and reinject altered packets to nfnetlink_queue.

Firewall Capabilities include:
1.Flow-level classification
2.Pattern matching
3.Stateful Inspection

Lab Scenario:

Setup:

![VM_setup](/assets/VM_setup.PNG){:class="img-responsive"}

Here we use VM1 and VM2 as two guests on two different physical desktop machines, and each running on a VirtualBox. FW is the virtual firewall running as guest VM which behaves as router and forwards traffic between the hosts VM1 and VM2.


Network Configuration:

![VM_setup](/assets/network_config.PNG){:class="img-responsive"}

FW:
Adapter1: A bridged adapter so that it receives IP from the host’s wifi network.
Adapter2: An internal network adapter so that it can communicate with the VM1, which we call the LAN network
Use VirtualBox’s VBoxManage to setup a dhcp server so that the FW and VM1 can get IP address on the internal network. In the following example, we use “intnet” as internal network.


![VM_setup](/assets/command1.PNG){:class="img-responsive"}

VM1:
Adapter1: An internal network adapter same as FW.

VM2:
Adapter1: A bridged adapter that receives IP from the host’s wifi network.  

Then start the respective VMs.
Once the VMs are started, check if the interfaces on the VMs get IP address. If not manually add entries to /etc/network/interfaces file to get IP from dhcp and then reboot.

![VM_setup](/assets/interface_file.PNG){:class="img-responsive"}

Routing:
To enable forwarding on FW, that is to forward packets from one network card to another. We run the following command in the VM terminal.

![VM_setup](/assets/command2.PNG){:class="img-responsive}

However the VM2 and VM1 cannot communicate with each other. Hence we need to setup a static route on both so that the traffic between them passes through FW.


For eg:
VM2 connected over WiFi:

![VM_setup](/assets/command3.PNG){:class="img-responsive}

VM1 on internal network:

![VM_setup](/assets/command4.PNG){:class="img-responsive}

Once the static routes are added, make sure VM1 and VM2 can ping each other before adding any iptables rule.

Packages to be installed on FW for Netfilter’s NFQUEUE and CONNTRACK modules to interact with the kernel.
Sudo apt-get install libnetfilter-queue-dev
Sudo apt-get install libnetfilter-conntrack-dev

Iptables rule to be added on FW to pass traffic on the forward hook to the NFQUEUE


![VM_setup](/assets/command5.PNG){:class="img-responsive}


Add the same rule in the reverse direction as well.

Rule Table on FW :
Example based on Lab2 Scenarios: “rules.txt”

![VM_setup](/assets/rules.PNG){:class="img-responsive}

Compile the code:
![VM_setup](/assets/command6.PNG){:class="img-responsive}

Running the code:
Note: Make sure rules.txt is in same directory as the source code before running the code.

![VM_setup](/assets/command7.PNG){:class="img-responsive}

Rules Tested:
1.  Allow Ping from the Lan interface to the Wifi interface. (Flow level classification). Verify your settings:
ping 192.168.1.100 from 192.168.0.21 Should get through

![VM_setup](/assets/rules2.PNG){:class="img-responsive}


Note:  The 7th column represents flag/type and here it means ICMP_TYPE, ie echo-request is 8 and icmp-reply is 0

2. Drop TCP with destination address and port 192.168.1.100:5000. Allow TCP connection setup with destination 192.168.1.100:5001-5010. (Flow level classification)
iperf -s -p 5000 <from 192.168.1.100>
iperf -c 192.168.1.100 -p 5000 <from 192.168.0.21>
Should get blocked.

iperf -s -p 5001 <from 192.168.1.100>
iperf -c 192.168.1.100 -p 5001 <from 192.168.0.21>
Should get through.

![VM_setup](/assets/rules3.PNG){:class="img-responsive}

3. Allow ssh services initiated from LAN to wifi. Deny ssh services initiated from firewall to LAN (Stateful firewall rules).
Verify your settings: ssh <your username>@192.168.0.21    <from 192.168.1.100>.Should get successfully accessed.
Verify your settings: ssh <your username>@192.168.1.100    <from 192.168.0.21>. Should get stuck.

![VM_setup](/assets/rules4.PNG){:class="img-responsive}


Note: The second-last says this rule expects stateful inspection, and the last column represents the tcp states allowed. For eg: for NEW state, the tcp states allowed are from NONE(0),SYN_SENT(1),SYN_RECV(2)


![VM_setup](/assets/states.PNG){:class="img-responsive}

4. Drop SYN-ACK packets destine to 192.168.1.100:10000. Allow SYN and ACK packets destine to 192.168.1.100:10000 (Packet level classification).
Verify your settings:
Use hping3 http://www.hping.org/manpage.html
Or scapy http://www.secdev.org/projects/scapy/doc/usage.html
to send an individual SYN/SYN-ACK/ACK packet to 192.168.0.21. The SYN-ACK should get dropped while the SYN/ACK should get through.

![VM_setup](/assets/rules5.PNG){:class="img-responsive}

Note: An iperf server was started at the destination with port 10000 to observe syn-ack packets being blocked, i.e; when a syn packet is sent to port 10000, the port replies with syn-ack but the packet is blocked by firewall. Just sending a syn-ack packet without running a tcp server at destination will not block syn-ack packet and a reset packet is received at the sending host.

5. Block a FTP transmission file bidirectional containing the word “piratebay”. Allow other FTP transmission. (String matching)
Follow https://help.ubuntu.com/lts/serverguide/ftp-server.html or other opensource FTP server (with no encryption) to setup a ftp at 192.168.1.100. Transmit a txt file from 192.168.0.21 to 192.168.1.100 using FTP containing “piratebay”.
Suppose the txt file contains “piratebay”, an empty file gets transferred. Otherwise the file should be successfully transmitted.

![VM_setup](/assets/rules6.PNG){:class="img-responsive}

Note: When a file without the pattern is being transferred, the file gets transferred successfully to destination. However, if a file with the pattern piratebay is being transferred, we apply the pattern action i.e NF_DROP in this case, and the connection is stuck and an empty file is created at destination.

6. Deny any other packets (Default Policy)
By default any packet that does not match any rule in the file rules.txt, will be dropped.


Code:netfil_m.c
Rules:rules.txt

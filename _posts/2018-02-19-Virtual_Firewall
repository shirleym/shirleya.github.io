---
layout: post
title: "My Final Project, Virtual Firewall"
date: 2018-02-19
---

Introduction:

This firewall is built on a linux machine which comprises of a netfilter framework . Netfilter is a packet filtering system within the system and provides a series of 5 hooks over different points of the kernel network stack. Kernel module functions or userspace functions can be registered against these hooks and can be used to pass a decision on the traversal of the packet.

Here we have transferred all packets to userspace using iptables and nfqueue.The running code registered against respective queue number will pass a verdict on the packets.


Netfilter Architecture:

An incoming IP packet travels in the path shown in the figure. It passes through hooks where different functions (dropping, mangling, etc) to exploit these packets can be defined. Initially the packet passes through NF_IP_PRE_ROUTING hook after which it passes through routing code which decided whether it is meant for a local process or to another machine.If it's for the current machine, then netfilter framework is called for the NF_IP_LOCAL_IN hook before being passed to local process. If not for this machine, then it's passed on to the NF_IP_FORWARD hook and finally to NF_IP_POST_ROUTING hook. The hooks are triggered by the kernel after implementation of network procedures. 
Kernel modules can register a new table of iptables and ask for a packet to traverse a given table. Several tables of iptables hook onto the NF_IP_LOCAL_IN,NF_IP_FORWARD and NF_IP_LOCAL_OUT points. Netfilter provides a special target in iptables called nfqueue to register user programs for these hooks. Incoming packets get queued to these and are served by the programs. One program can bind to one or several queues using libnetfilter_queue library.  This library can receive queued packets from kernel nfnetlink_queue subsystem, issue verdicts and reinject altered packets to nfnetlink_queue. 

Firewall Capabilities include:
1.Flow-level classification
2.Pattern matching
3.Stateful Inspection






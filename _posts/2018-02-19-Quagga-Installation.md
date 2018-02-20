---
layout: post
title: "Quagga Installation and Configuration: Ubuntu Server 16.04(rtr and int-rtr)"
date: 2018-02-19
---



Quagga Installation and Configuration: Ubuntu Server 16.04(rtr and int-rtr)


![Architecture](/assets/cnlab.JPG){:class="img-responsive"}


Sudo apt-get install quagga
activate the Quagga daemons matching the routing protocols you want to set on your router
Edit which routing protocols are to run:
	sudo nano /etc/quagga/daemons
		zebra=yes
		bgpd=no
		ospfd=yes
		ospf6d=no
		ripd=no
		ripngd=no

Restart the Quagga service:

#/etc/init.d/quagga restart




3. CONFIGURATION FILES: (/etc/quagga/*.conf files)
You must create a configuration file (even if it is empty) each time you activate a Quagga daemon.
Each daemon is associated with a specific file name:

zebra:
bgpd:
ospfd:
ospf6d:
ripd:
ripngd:
zebra.conf
bgpd.conf
ospfd.conf
ospf6d.conf
ripd.conf
ripngd.conf
To create the config files, copy the sample config files as follows:
In our example, as we activated the zebra and ospfd daemons; we need to create the zebra.conf and ospfd.conf files.
#cp /usr/share/doc/quagga/examples/zebra.conf.sample /etc/quagga/zebra.conf
#cp /usr/share/doc/quagga/examples/ospfd.conf.sample /etc/quagga/ospfd.conf

Another way to do it is to create two empty files called /etc/quagga/ospfd.conf and /etc/quagga/zebra.conf. But in this case you cannot telnet a daemon, you need to configure the telnet permissions with vtsh (see below).

Finally, give user and group ownership to respectively quagga and quaggavty to the files inside the /etc/quagga directory:

#chown quagga.quaggavty /etc/quagga/*.conf
#chmod 640 /etc/quagga/*.conf
Restart the Quagga service:

#/etc/init.d/quagga restart



4.DEBIAN.CONF FILE

# If this option is set the /etc/init.d/quagga script automatically loads 
# the config via "vtysh -b" when the servers are started. 
# Check /etc/pam.d/quagga if you intend to use "vtysh"! 
# 
vtysh_enable=yes 
zebra_options=" --daemon -A " 
bgpd_options=" --daemon -A " 
ospfd_options=" --daemon -A " 
ospf6d_options="--daemon -A " 
ripd_options=" --daemon -A " 
ripngd_options="--daemon -A " 
isisd_options=" --daemon -A " 

The "vtysh_enable=yes" setting is required to access the Quaggga router via vtysh. (see vtysh section).

Restart the Quagga service

#/etc/init.d/quagga restart



5.vtysh
As indicated in the Quagga introduction, you can access the daemons by telnetting their port number because each daemon has its own configuration file and terminal interface.

zebra:
ripd:
ripng:
ospfd:
bgpd:
ospf6d:


2601
2602
2603
2604
2605
2606
By instance, to access the ospfd daemon:

#telnet localhost 2604
 As it's not very practical to configure your router by telnetting its daemons separately, vtysh has been created to configure everything in one single interface. 

To use vtysh, you must first create its configuration file as follows:

#cp /usr/share/doc/quagga/examples/vtysh.conf.sample /etc/quagga/vtysh.conf

/etc/quagga/vtysh.conf 
!
! Sample
!
! service integrated-vtysh-config
hostname quagga-router
username root nopassword
!

Apply correct permissions and restart Quagga:

#chown quagga.quaggavty /etc/quagga/*.conf
#chmod 640 /etc/quagga/*.conf

#/etc/init.d/quagga restart
In the example above the "service integrated-vtysh-config" setting has been disabled (recommended). In this case, when you save the config under vtysh, it will be stored in separate files depending on the protocols you activated.
Below, an example where the Quagga configuration is saved under vtysh. (The zebra and ospfd daemons have been enabled.)

#vtysh

quagga-router#write
Configuration saved to /etc/quagga/zebra.conf
Configuration saved to /etc/quagga/ospfd.conf 

If you activate "service integrated-vtysh-config", the configuration under vtysh will be saved in one file called Quagga.conf in the /etc/quagga/ directory.
With this setting, when you access a daemon via telnet, the daemon will look first to the Quagga.conf file before looking for its own file. This means that, when you telnet a device, there can be a difference between what you see after the "show run" command and the content of the associated file, for example zebra.conf. 

#vtysh

quagga-router#write
Configuration saved to /etc/quagga/Quagga.conf 

It is recommended to disable "service integrated-vtysh-config" because if this setting is enabled and in case of a syntax error in the Quagga.conf file, this can lead to all your daemons being unable to start up. This will not be case when "service integrated-vtysh-config" is disabled because the configurations are stored in separate files. 

 Check that the default "vtysh_enable=yes" setting are configured in your /etc/quagga/debian.conf file. You can read the previous paragraph about the debian.conf file to get more information. 

 Then it's useful to add the "VTYSH_PAGER=more" setting in your /etc/environment file, otherwise you will see an unfriendly "(END)" blinking in the left-down corner of the screen each time your enter a command and will need to press the "q" key to continue. 

#echo VTYSH_PAGER=more > /etc/environment
Log off and log on to enable the environment setting. You can now access the Quagga router with the vtysh command:

#vtysh
Hello, this is Quagga (version 0.99.6).
Copyright 1996-2005 Kunihiro Ishiguro, et al.

quagga-router# 

If you want to run a Quagga command from the Linux shell:

#vtysh -c "command"
For instance, vtysh -c "show ip route" will display the Quagga routing table. 

 You can use Ping and traceroute to perform connectivity checks from the vtysh prompt. Of course, these two programs need to be installed on the Linux machine. Ping is generally installed by default but traceroute often not. 
To install traceroute:

#apt-get install traceroute



6.IP FORWARDING:
IP forwarding is required to transfer packets between the network interfaces of a Linux system.
See a picture of the Linux kernel routing.

#echo "1" > /proc/sys/net/ipv4/ip_forward
The command above will add the "1" value inside the /proc/sys/net/ipv4/ip_forward file and thus activate the IP forwarding. 
If you want to keep the IP forwarding after a Linux reboot:

#echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
It is possible to check the ip_forwarding status under the Quagga router:

#show ip forwarding
IP forwarding is on 

In this case the IP forwarding is activated.

7. SPEED/DUPLEX:

It is not possible to set the duplex and speed settings on the Quagga plateform. You have to configure them at the Linux level.
Use the interface configuration tutorial for assistance.

https://openmaniak.com/quagga_tutorial.php

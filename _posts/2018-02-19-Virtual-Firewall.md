---
layout: post
title: "Virtual Firewall Project"
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

![network_config](/assets/network_config.PNG){:class="img-responsive"}

FW:
Adapter1: A bridged adapter so that it receives IP from the host’s wifi network.
Adapter2: An internal network adapter so that it can communicate with the VM1, which we call the LAN network
Use VirtualBox’s VBoxManage to setup a dhcp server so that the FW and VM1 can get IP address on the internal network. In the following example, we use “intnet” as internal network.


![command1](/assets/command1.PNG){:class="img-responsive"}

VM1:
Adapter1: An internal network adapter same as FW.

VM2:
Adapter1: A bridged adapter that receives IP from the host’s wifi network.  

Then start the respective VMs.
Once the VMs are started, check if the interfaces on the VMs get IP address. If not manually add entries to /etc/network/interfaces file to get IP from dhcp and then reboot.

![interface_file](/assets/interface_file.PNG){:class="img-responsive"}

Routing:
To enable forwarding on FW, that is to forward packets from one network card to another. We run the following command in the VM terminal.

![command2](/assets/command2.PNG){:class="img-responsive}

However the VM2 and VM1 cannot communicate with each other. Hence we need to setup a static route on both so that the traffic between them passes through FW.


For eg:
VM2 connected over WiFi:

![Command3](/assets/Command3.PNG){:class="img-responsive}

VM1 on internal network:

![Command4](/assets/Command4.PNG){:class="img-responsive}

Once the static routes are added, make sure VM1 and VM2 can ping each other before adding any iptables rule.

Packages to be installed on FW for Netfilter’s NFQUEUE and CONNTRACK modules to interact with the kernel.
Sudo apt-get install libnetfilter-queue-dev
Sudo apt-get install libnetfilter-conntrack-dev

Iptables rule to be added on FW to pass traffic on the forward hook to the NFQUEUE


![Command5](/assets/Command5.PNG){:class="img-responsive}


Add the same rule in the reverse direction as well.

Rule Table on FW :
Example based on Lab2 Scenarios: “rules.txt”

![rules](/assets/rules.PNG){:class="img-responsive}

Compile the code:
![Command6](/assets/Command6.PNG){:class="img-responsive}

Running the code:
Note: Make sure rules.txt is in same directory as the source code before running the code.

![command7](/assets/command7.PNG){:class="img-responsive}

Rules Tested:
1.  Allow Ping from the Lan interface to the Wifi interface. (Flow level classification). Verify your settings:
ping 192.168.1.100 from 192.168.0.21 Should get through

![rules2](/assets/rules2.PNG){:class="img-responsive}


Note:  The 7th column represents flag/type and here it means ICMP_TYPE, ie echo-request is 8 and icmp-reply is 0

2. Drop TCP with destination address and port 192.168.1.100:5000. Allow TCP connection setup with destination 192.168.1.100:5001-5010. (Flow level classification)
iperf -s -p 5000 <from 192.168.1.100>
iperf -c 192.168.1.100 -p 5000 <from 192.168.0.21>
Should get blocked.

iperf -s -p 5001 <from 192.168.1.100>
iperf -c 192.168.1.100 -p 5001 <from 192.168.0.21>
Should get through.

![rules3](/assets/rules3.PNG){:class="img-responsive}

3. Allow ssh services initiated from LAN to wifi. Deny ssh services initiated from firewall to LAN (Stateful firewall rules).
Verify your settings: ssh <your username>@192.168.0.21    <from 192.168.1.100>.Should get successfully accessed.
Verify your settings: ssh <your username>@192.168.1.100    <from 192.168.0.21>. Should get stuck.

![rules4](/assets/rules4.PNG){:class="img-responsive}


Note: The second-last says this rule expects stateful inspection, and the last column represents the tcp states allowed. For eg: for NEW state, the tcp states allowed are from NONE(0),SYN_SENT(1),SYN_RECV(2)


![states](/assets/states.PNG){:class="img-responsive}

4. Drop SYN-ACK packets destine to 192.168.1.100:10000. Allow SYN and ACK packets destine to 192.168.1.100:10000 (Packet level classification).
Verify your settings:
Use hping3 http://www.hping.org/manpage.html
Or scapy http://www.secdev.org/projects/scapy/doc/usage.html
to send an individual SYN/SYN-ACK/ACK packet to 192.168.0.21. The SYN-ACK should get dropped while the SYN/ACK should get through.

![rules5](/assets/rules5.PNG){:class="img-responsive}

Note: An iperf server was started at the destination with port 10000 to observe syn-ack packets being blocked, i.e; when a syn packet is sent to port 10000, the port replies with syn-ack but the packet is blocked by firewall. Just sending a syn-ack packet without running a tcp server at destination will not block syn-ack packet and a reset packet is received at the sending host.

5. Block a FTP transmission file bidirectional containing the word “piratebay”. Allow other FTP transmission. (String matching)
Follow https://help.ubuntu.com/lts/serverguide/ftp-server.html or other opensource FTP server (with no encryption) to setup a ftp at 192.168.1.100. Transmit a txt file from 192.168.0.21 to 192.168.1.100 using FTP containing “piratebay”.
Suppose the txt file contains “piratebay”, an empty file gets transferred. Otherwise the file should be successfully transmitted.

![rules6](/assets/rules6.PNG){:class="img-responsive}

Note: When a file without the pattern is being transferred, the file gets transferred successfully to destination. However, if a file with the pattern piratebay is being transferred, we apply the pattern action i.e NF_DROP in this case, and the connection is stuck and an empty file is created at destination.

6. Deny any other packets (Default Policy)
By default any packet that does not match any rule in the file rules.txt, will be dropped.


Code:netfil_m.c
Rules:rules.txt


{% highlight c %}
//Libraries
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include <errno.h>

//ip protocol values
#define ICMP 1
#define TCP 6
#define UDP 17

//structure to store rules
struct rule {
    char s_addr[32];
    char d_addr[32];
    char s_port_start[10];
    char s_port_end[10];
    char d_port_start[10];
    char d_port_end[10];
    char flags[10];
    char proto[10];
    char action[10];
    char signature[10];
    char signature_action[10];
    char stateful[10];
    char states[2][10];

};

//declare an array for rules
struct rule rules[20];
//global value to store total rules
static int rule_count = 0;

//define structure for network address type: ip/prefix
typedef struct network_addr {
    char *addr;
    int pfx;
} network_addr_t;


//TCP STATES, 0:3(NEW), 4:9(ESTABLISHED)
enum states{
	NONE,
	SYN_SENT,
	SYN_RECV,
	ESTABLISHED,
	FIN_WAIT,
	CLOSE_WAIT,
	LAST_ACK,
	TIME_WAIT,
	CLOSE,
	LISTEN
};

//function to read rules from rules.txt
static int read_rules()
{
    FILE* file = fopen("rules.txt","r");
    char buf[256];
    char *ptr;
    while(fscanf(file,"%s %s %s %s %s %s %s %s %s %s %s %s %[^:]:%[^:\n]", rules[rule_count].s_addr,rules[rule_count].d_addr,rules[rule_count].s_port_start,rules[rule_count].s_port_end,rules[rule_count].d_port_start,rules[rule_count].d_port_end,rules[rule_count].flags,rules[rule_count].proto,rules[rule_count].action,rules[rule_count].signature,rules[rule_count].signature_action,rules[rule_count].stateful,rules[rule_count].states[0],rules[rule_count].states[1]) == 14) {
        //print rules
        printf("\nrule : %s %s %s %s %s %s %s %s %s %s %s %s %s %s", rules[rule_count].s_addr,rules[rule_count].d_addr,rules[rule_count].s_port_start,rules[rule_count].s_port_end,rules[rule_count].d_port_start,rules[rule_count].d_port_end,rules[rule_count].flags,rules[rule_count].proto,rules[rule_count].action,rules[rule_count].signature,rules[rule_count].signature_action,rules[rule_count].stateful,rules[rule_count].states[0],rules[rule_count].states[1]);
        //printf("\n****string port ranges****%s,%s ----- %s,%s", rules[rule_count].s_port_start,rules[rule_count].s_port_end,rules[rule_count].d_port_start,rules[rule_count].d_port_end);

        rule_count++;//update total rule_count
    }
    //check if ed of file reached
    if(feof(file))
    {   puts("\nEOF");
        fclose(file);
        return 1;
    } else {
        fclose(file);
        puts("\ncan not read");
        return 0;
    }
    fclose(file);
    return 0;
}

//function to calculate netmask
u_int32_t compute_netmask(int prefix, u_int32_t netmask) {
    printf("\nprefix:%d",prefix);
    u_int32_t mask = 0xFFFFFFFF;
    mask <<= (32 - prefix);
    netmask = ntohl(mask);
    return netmask;

}

//function to split string ip/prefix
network_addr_t get_ip(char *listed_ip) {
    char *input = "/";
    char *ipv4 = strtok(listed_ip,input);
    network_addr_t netaddr;
    netaddr.addr = ipv4;
    ipv4 = strtok(NULL, "/");
    if(ipv4 != NULL)
        netaddr.pfx = atoi(ipv4);
    else
        netaddr.pfx = 0;
    return netaddr;
}


//function to compare string IP addresses
static int compare_ips(char listed_ip[32], char *packet_ip) {
    //printf("%s","**************function to compare ips**************");
    int i = 0,match;    
    char str1[INET_ADDRSTRLEN],str2[INET_ADDRSTRLEN],str3[INET_ADDRSTRLEN];    
    u_int32_t listed, packet, netmask, pkt_network, netstart, netend;

    //check if all ip addresses are allowed
    if(strcmp(listed_ip,"all")==0)
        return 1;
    printf("\n%s",listed_ip);

    //split ip/prefix of listed-ip
    network_addr_t netaddr;
    netaddr = get_ip(listed_ip);    

    //convert ips to u_int32_t datatype
    inet_pton(AF_INET,netaddr.addr,&listed);
    inet_pton(AF_INET,packet_ip,&packet);
    //printf("\n%s..........%s\n", netaddr.addr, packet_ip);
    //printf("%lu.........%lu\n", (unsigned long)listed, (unsigned long)packet);

    //get netmask for the listed ip
    netmask = compute_netmask(netaddr.pfx,netmask);
    //get ip range
    netstart = (listed & netmask);
    netend = (netstart | ~netmask);
    //printf("\nip range:%lu.......%lu",(unsigned long)netstart,(unsigned long)netend);
    printf("\nnetmask:%lu",(unsigned long)netmask);

    //get packet network based on subnetmask
    pkt_network = packet & netmask;
    //printf("\npakt_network:%lu",(unsigned long)pkt_network);
    //printf("\nlisted_ntwk:%lu",(unsigned long)(listed & netmask));

    //print listed ip network-range and mask
    inet_ntop(AF_INET,&netstart,str1,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&netend,str2,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&netmask,str3,INET_ADDRSTRLEN);
    //printf("\nip start:%s.......ip end:%s........mask%s",str1,str2,str3);

    //check if ip falls in the listed ip range
    match = ((packet & netmask) == (listed & netmask));
    if(match) {
        //printf("\n%s\n","######### IP ADDRESES MATCH ########\n\n");
        return 1;
    } else {
        //printf("\n%s\n","######### IP ADDRESS DONT MATCH #########\n\n");
        return 0;
    }
    return 0;
}

//define pseudo header struct for checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

//function to compute checksum
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes == 1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer = (short)~sum;
    return (answer);
}

//function to send tcp reset packet
static int send_tcp_rst(char *saddr,char *daddr, int protocol, int sport, int dport,struct iphdr *piph, unsigned char *pd) {
    int s = socket(PF_INET,SOCK_RAW, IPPROTO_TCP);
    if(s == -1) {
        //socket creation failed
        perror("failed to create socket");
        exit(1);
    }
    //packet tcp data
    struct tcphdr *tcpHeader = (struct tcphdr *)(pd + (piph->ihl<<2));
    //tcpCheck = tcpHeader->check;
    //sport = ntohs(tcpHeader->source);
    //dport = ntohs(tcpHeader->dest);
    //datagram to represent the packet
    char datagram[4096], source_ip[32], *data, *psuedogram;

    //zero out the packet buffer
    memset(datagram,0,4096);

    //ip header
    struct iphdr *iph = (struct iphdr *) datagram;

    //tcp header
    struct tcphdr *tph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    //data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

    //ip address
    strcpy(source_ip,daddr);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(saddr);

    //fill the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;

    //ip checksum
    iph->check = csum((unsigned short *) datagram, iph->tot_len);

    //TCP Header
    tph->source = tcpHeader->dest;
    tph->dest = htons(21);
    tph->seq = random();
    tph->ack_seq = tcpHeader->ack_seq;
    tph->doff = 5;
    tph->fin = 0;
    tph->syn = 0;
    tph->rst = 1;
    tph->psh = 0;
    tph->ack = 0;
    tph->urg = 0;
    tph->window = htons(5840);
    tph->check = 0;
    tph->urg_ptr = 0;

    //tcp checksum
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    psuedogram = malloc(psize);

    memcpy(psuedogram, (char*) &psh, sizeof(struct pseudo_header));
    memcpy(psuedogram + sizeof(struct pseudo_header), tph, sizeof(struct tcphdr)+strlen(data));

    tph->check = csum((unsigned short *) psuedogram, psize);

    //IP_HDRINCL to tell kernel that headers are included in packet
    int one = 1;
    const int *val = &one;

    if(setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("error seting  iphdrinlc");
        exit(0);
    }
    //send the packet
    if(sendto(s,datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("sendto failed");
        exit(-1);
    }
    //data sent successfully
    else {
        printf("\npacket sent length:%d \n", iph->tot_len);
    }

    //close(s);
    return 0;

}

//function for naive-pattern matching in payload
static int pattern_match(struct iphdr *pIph,void *s,char *pat) {
    char *payload;
    int i,j;
    payload = s;
    int M = strlen(pat);
    printf("\nPattern length:%d, Pattern:%s",M,pat);
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    for(i=0; i<tcpLen-M; i++) {
        printf("\n");
        for(j=0; j<M; j++) {
            //printf("%c|",payload[i+j]);
            //printf("%c|",pat[j]);
            //printf("j%d,M%d",j,M);
            if(j==M-1) {
                printf("\n%s","************pattern matched*****************");
                return 0;
            }
            //check single character at a time
            if(payload[i+j]!=pat[j]) {
                printf("\n%s","********pattern not matched**********");
                break;
            }
        }
    }
    printf("\n");
    return 1;
}


//callback function for conntrack query
static int ct_cb(enum nf_conntrack_msg_type type,struct nf_conntrack *ct, void *data){
	char buf[1024];
	nfct_snprintf(buf,sizeof(buf),ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT,NFCT_OF_SHOW_LAYER3);
	//printf("\ncomes in conntrack callback..............");
	printf("%s\n",buf);
	return NFCT_CB_CONTINUE;
}

//function to check tcp state from connection
static int connection_exists(char *saddr,char *daddr, int protocol, int sport, int dport,int k){
    //conntrack code
    int ct_ret,ct_ret2;
    u_int32_t family = AF_INET;
    struct nfct_handle *ct_h;
    struct nf_conntrack *expected;
    //struct nf_expect *exp;
    ct_h = nfct_open(CONNTRACK,0);
    if(!ct_h){
    	perror("---------nfct_open-----");
    	return -1;
    }else{
    expected = nfct_new();
    if(!expected){
	perror("-----nfct_new-----");
	return 0;
    }
    //Variables to query conntrack table
    printf("\n-----conection exists variables:%s----%s----%d-----%d------%d-------%d",saddr,daddr,sport,dport,protocol,k);
    //flow based query
    nfct_set_attr_u8(expected,ATTR_L3PROTO,AF_INET);
    nfct_set_attr_u32(expected,ATTR_IPV4_SRC,inet_addr(saddr));
    nfct_set_attr_u32(expected,ATTR_IPV4_DST,inet_addr(daddr));
    nfct_set_attr_u8(expected,ATTR_L4PROTO,IPPROTO_TCP);
    nfct_set_attr_u16(expected,ATTR_PORT_SRC,htons(sport));
    nfct_set_attr_u16(expected,ATTR_PORT_DST,htons(dport));
    nfct_set_attr_u8(expected,ATTR_TCP_STATE,k);
    nfct_callback_register(ct_h, NFCT_T_ALL,ct_cb, NULL);
    ct_ret = nfct_query(ct_h,NFCT_Q_DUMP,&family);

    if(ct_ret == -1){
	//printf("\n(OK)\n");
	printf("\n(%d)(%s)\n",ct_ret,strerror(errno));
        nfct_destroy(expected);
	nfct_callback_unregister(ct_h);
	nfct_close(ct_h);
	return 0;

    }else{
	printf("\n(OK)");
        nfct_callback_unregister(ct_h);
        nfct_callback_register(ct_h, NFCT_T_ALL,ct_cb, NULL);
        ct_ret2 = nfct_query(ct_h,NFCT_Q_GET,expected);
        //printf("\n------ct_ret2------:%d",ct_ret2);
        //printf("\nTEST:get conntrack:%d",k);
        //exit(EXIT_FAILURE);
        nfct_destroy(expected);
	nfct_callback_unregister(ct_h);
	nfct_close(ct_h);
	return ct_ret2;    
    }
	nfct_destroy(expected);
	nfct_callback_unregister(ct_h);
	nfct_close(ct_h);    
	return 0;
     }//conntrack code ends
}


//function to perform linear search through rules array
static int linear_search(char *saddr,char *daddr, int protocol, int sport, int dport, u_int8_t flag_type, int payload_len, struct iphdr *pIph, unsigned char *pd) {
    printf("\nflow to match in rules array table");
    printf("%s	%s	%d	%d	%d\n",saddr,daddr,sport,dport,protocol);

    /*FILE *f = fopen("matches.txt","a");
    FILE *f2 = fopen("flowlog.txt","a");
    if(f == NULL && f2 == NULL) {
        printf("\nerror opening file");
        exit(1);
    }*/

    int ret2 = 0;
    int ret3 = 0;
    int t;
    void *s;

    printf("size of rules:%d",rule_count);
    for(int j=0; j < rule_count; j++) {
        //step: compare source ip addresses
        printf("\n%s - %s - %s\n","compare source ips",rules[j].s_addr, saddr);
        ret2 = compare_ips(rules[j].s_addr,saddr);
        if(!ret2) continue;
        else {
	    //step: compare destination ip addresses
            printf("\n%s - %s - %s\n","compare dest ips",rules[j].d_addr, daddr);
            ret3 = compare_ips(rules[j].d_addr,daddr);
            if(!ret3) continue;
            int proto_flag = 0;
            int state_flag = 0;
            //step: switch based on protocol
            switch(protocol) {
            case ICMP:
                if((strcmp(rules[j].proto,"ICMP")==0) && (atoi(rules[j].flags) == flag_type)) {
                    printf("\nicmp-type%d",flag_type);
                    proto_flag = 1;
                    goto check;
                }
            case TCP:
                if(strcmp(rules[j].proto,"TCP")==0) {
		    struct tcphdr *tcpHeader = (struct tcphdr *)(pd + (pIph->ihl<<2));
		    s = (char*)tcpHeader + 4*(tcpHeader->doff);
		    //printf("\natoi(rules[j].flags)=%d",atoi(rules[j].flags));
                    if(atoi(rules[j].flags) == flag_type || (strcmp(rules[j].flags,"all")==0)) {
                        proto_flag = 1;
                        //printf("\n%s","check TCP");
                    }
                    goto check;
                }
            case UDP:
                if(strcmp(rules[j].proto,"UDP")==0) {
                    proto_flag = 1;
                    printf("\n%s","check UDP");
                    goto check;
                }
            default:
                if(strcmp(rules[j].proto,"all")==0) {
                    proto_flag = 1;
                    //printf("\n%s","in default");
                } else printf("\nUnrecognized Protocol:%d",protocol);
check:
                if(!proto_flag) continue;// protocol mismatch, move on to next packet
                int port_flag = 1;
                printf("\n**********port ranges******%s -%s, %s-%s",rules[j].s_port_start,rules[j].s_port_end,rules[j].d_port_start,rules[j].d_port_end);

		//step: compare port numbers
                if (((((sport >= atoi(rules[j].s_port_start)) && (sport <= atoi(rules[j].s_port_end))) || (strcmp(rules[j].s_port_start,"all") == 0)) && (((dport <= atoi(rules[j].d_port_end)) && (dport >= atoi(rules[j].d_port_start))) || (strcmp(rules[j].d_port_start,"all") == 0)))) {
                    printf("\n%s","@@@@@@@*********success PACKET MATCH**********@@@@@@@");

                    //step: check rule action, if accept
                    if(strcmp(rules[j].action,"NF_ACCEPT")==0) {

		       //check if pattern defined for the rule                        
			if(strcmp(rules[j].signature,"none") != 0 && strcmp(rules[j].proto,"TCP")==0 && strcmp(rules[j].signature_action,"NF_DROP") == 0) {
                            printf("\n%s","*******check pattern********");
                            t=pattern_match(pIph,s,rules[j].signature);
                            //check if pattern matched
                            if(!t) {
                                printf("\n%s","Pattern matched");
                                //send_tcp_rst(saddr,daddr,protocol,sport,dport, pIph, pd);
                                return 0;
                            } else {
                                return 1;
                            }
			//check if rule is stateful
                        } else if(strcmp(rules[j].stateful,"yes") == 0 && strcmp(rules[j].proto,"TCP")==0){
				    int ct_ret=0;				   
				    for(int k=atoi(rules[j].states[0]);k<atoi(rules[j].states[1]);k++){
					ct_ret = connection_exists(saddr,daddr,protocol,sport,dport,k);
					if (ct_ret != -1) return 1;//flow match i conntrack table
					else if(ct_ret == -1 && k==9) return 1;//new connection
					else continue;
				    }				    
			}else {
                            printf("\n*****rule match:%d*********",j+1);
                            //write to file
                            printf("%d	%s	%s	%d	%d	%d\n",j+1,saddr,daddr,sport,dport,protocol);
                            //fprintf(f2,"%d %d\n",j+1,payload_len);
                            //fclose(f2);
                            //fclose(f);
                            return 1;
                        }
                    }
                    else {
                        printf("%s","******packet dropped1*********");
                        return 0;
                    }
                } else {
                    //printf("\nports not matched:%d.........%d",sport,dport);
                    continue;
                }
                printf("%s","******packet dropped2*********");
            }
            printf("%s","******packet dropped3*********");
        }
        printf("%s","******packet dropped4*********");
        return 0;
    }
    return 0;
    printf("%s","******packet dropped5*********");
}

//callback function called whenever a packet is queued
static int cb(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    //printf("entering callback\n");
    u_int32_t id, mark, ifi;
    int ret;
    int payload_len, tcp_flags[8];
    unsigned char *data1;
    unsigned char *packet = NULL;

    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;

    struct iphdr *ipHeader = NULL;
    struct tcphdr *tcpHeader = NULL;
    struct udphdr *udpHeader = NULL;
    struct icmphdr *icmpHeader = NULL;

    unsigned short ipCheck, udpCheck, tcpCheck,sport=0,dport=0;
    unsigned char *payloadData;
    char saddr[INET_ADDRSTRLEN],daddr[INET_ADDRSTRLEN];

    payload_len = nfq_get_payload(nfa, &payloadData);
    //printf("ip datagram len= %d", payload_len);

    ipHeader = (struct iphdr*)payloadData;
    ipCheck = ipHeader->check;
    u_int8_t flag_type = 0;

    //print ip headers
    printf("ip payload length: %d-----%s" ,payload_len,payloadData);
    printf("\nip header protocol=%d",ipHeader->protocol);
    fprintf(stdout, "\nIP{v=%u; ihl=%u; tos=%u; tot_len=%u; id=%u; ttl=%u; protocol=%u;",ipHeader->version, ipHeader->ihl*4,ipHeader->tos, ntohs(ipHeader->tot_len),ntohs(ipHeader->id),ipHeader->ttl, ipHeader->protocol);

    //convert ip address to string format
    inet_ntop(AF_INET,&ipHeader->saddr,saddr,INET_ADDRSTRLEN);
    fprintf(stdout,"saddr=%s;",saddr);
    inet_ntop(AF_INET,&ipHeader->daddr,daddr,INET_ADDRSTRLEN);
    fprintf(stdout, "daddr=%s}\n",daddr);
    printf("\nsource ip-dest ip:%s-%s",saddr,daddr);

    switch(ipHeader->protocol){
	case TCP:	tcpHeader = (struct tcphdr *)(payloadData + (ipHeader->ihl<<2));
			tcpCheck = tcpHeader->check;
			sport = ntohs(tcpHeader->source);
			dport = ntohs(tcpHeader->dest);
			tcp_flags[0]= tcpHeader->urg;
			tcp_flags[1]= tcpHeader->ack;
			tcp_flags[2]= tcpHeader->psh;
			tcp_flags[3]= tcpHeader->rst;
			tcp_flags[4]= tcpHeader->syn;
			tcp_flags[5]= tcpHeader->fin;
			tcp_flags[6]= tcpHeader->ece;
			tcp_flags[7]= tcpHeader->cwr;
			u_int8_t listed = 0;
			for(int k=0; k<8; k++) {
			    listed += (tcp_flags[k] << k);
			}
			flag_type = listed;
			printf("th_flags:%d",flag_type);
			//printf("tcp checksum: %04x", tcpHeader->check);
			fprintf(stdout, "TCP{sport=%u; dport=%u; seq=%u; ack_seq=%u; flags=u%ua%up%ur%us%uf%u; window=%u; urg=%u}\n",ntohs(tcpHeader->source),ntohs(tcpHeader->dest),ntohl(tcpHeader->seq),ntohl(tcpHeader->ack_seq),tcpHeader->urg,tcpHeader->ack,tcpHeader->psh,tcpHeader->rst,tcpHeader->syn,tcpHeader->fin,ntohs(tcpHeader->window),tcpHeader->urg_ptr);
			break;
	case UDP:	udpHeader = (struct udphdr *)(payloadData + (ipHeader->ihl<<2));
			udpCheck = udpHeader->check;
			sport = udpHeader->source;
			dport = udpHeader->dest;
			//printf("udp checksum:%04x", udpHeader->check);
			//fprintf(stdout, "UDP{sport=%u,dport=%u;len=%u}\n",ntohs(udpHeader->source), ntohs(udpHeader->dest),udpHeader->len);
			break;
	case ICMP:  	icmpHeader = (struct icmphdr *)(payloadData + (ipHeader->ihl<<2));
 		       	flag_type = icmpHeader->type;
        		printf("\n******ICMP Header type*******************%d",8);
			break;
	default:return 0;    
	}
    //returns the metadataheader that wraps the packet
    ph = nfq_get_msg_packet_hdr(nfa);
    //unique id of packet in queue
    id = ntohl(ph->packet_id);
    //printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);

    //function to perform linear search
    int ret4=linear_search(saddr,daddr,ipHeader->protocol,sport,dport,flag_type,payload_len,ipHeader,payloadData);
    if (!ret4)
	//default policy to drop packets
        return nfq_set_verdict(qh, id,NF_DROP,0,NULL);
    else
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    //check if tcp/syn
    fputc('\n', stdout);
    //set verdict -- set rule action
    return nfq_set_verdict(qh, id,NF_DROP,0,NULL);
}

int main(int argc, char **argv)
{    
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;

    char buf[4096] __attribute__((aligned));
    printf("opening library handle\n");

    if(!read_rules()) {
        fprintf(stderr, "no rules set to process packets");
        exit(1);
    }

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nfqueue\n");
    if (nfq_unbind_pf(h,AF_INET) <0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink '0'\n");
    if (nfq_bind_pf(h,AF_INET) <0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,0,&cb,NULL);
    if(!qh) {
        fprintf(stderr,"error during nfq_create_queue()\n");
        exit(1);
    }
    printf("setting copy_packet mode \n");
    if (nfq_set_mode(qh,NFQNL_COPY_PACKET, 0xffff)< 0) {
        fprintf(stderr, "cant set packet_copy mode \n");
        exit(1);
    }
    printf("nfq_fd");
    fd = nfq_fd(h);

    while((rv = recv(fd,buf, sizeof(buf),0)))
    {
        //printf("pkt received\n");
        nfq_handle_packet(h,buf,rv);
    }
    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE

    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h,AF_INET);
#endif
    printf("closing library handle\n");
    nfq_close(h);

    exit(0);

}

{% endhighlight %}

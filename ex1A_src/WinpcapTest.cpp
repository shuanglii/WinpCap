#include <stdlib.h>
#include <stdio.h>
#include<iostream>
#include <pcap.h>
#include "sniffer.h"
using namespace std;

//报文内容解析函数
void HexDatagram(const u_char* packetData) {
	/* Print the packet */
	cout << "-------------------------------------十六进制数据报如下：---------------------------------------" << endl;
	for (int i = 1; i < strlen((char*)packetData)-1; i++)
	{
		printf("%.2x", packetData[i]);

		if ((i % 16) == 0) printf("\n");
	}
	cout << endl;
	cout << "-------------------------------------十六进制数据报输出结束---------------------------------------" << endl;
	cout << "-----------------------------------------数据报内容如下：---------------------------------------" << endl;
	for (int i = 1; i < strlen((char*)packetData); i++)
	{
		printf("%c", packetData[i - 1]);
		if ((i % 16) == 0) printf("\n");
	}
	cout << endl;
	cout << "------------------------------------------数据报输出结束---------------------------------------" << endl;
}
//CM函数
void ARPFrameResolution(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	struct arphdr* arpHead;
	arpHead = (struct arphdr*)(packetData + 14);//MAC首部是14位的，加上14位得到ARP协议首部   
	printf("-----------------------------------------ARP数据报解析-------------------------------------------\n");
	printf("硬件类型:%d。", arpHead->hrd);
	printf("协议类型:%d\n", arpHead->pro);
	printf("硬件长度:%d\n", ntohs(arpHead->hln));
	printf("协议长度:%d\n", ntohs(arpHead->pln));
	printf("操作码:%d\n", ntohs(arpHead->op));
	printf("MAC帧源地址:");
	u_char* ARPstr;
	printf("MAC帧源地址:");
	ARPstr = arpHead->srcmac;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *ARPstr, *(ARPstr + 1), *(ARPstr + 2), *(ARPstr + 3), *(ARPstr + 4), *(ARPstr + 5));
	printf("源IP地址:");
	hexToCharIP(arpHead->saddr);
	printf("MAC帧目的地址:");
	ARPstr = arpHead->destmac;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *ARPstr, *(ARPstr + 1), *(ARPstr + 2), *(ARPstr + 3), *(ARPstr + 4), *(ARPstr + 5));
	printf("目的地址:");
	hexToCharIP(arpHead->daddr);
	HexDatagram(packetData);
}
//HTTP解析函数
void httpAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("-----------------------------------------HTTP数据报解析-------------------------------------------\n");

	/*char buffer[65536];
	int bufsize = 0;
	int flag = 0;
	char data;
	data = (char)packetData;
	for (int i = 0; i < 1460; i++)//TCP数据包最大长度为1460
	{
		cout << "fdsafasdfasdfasdfasdfadfas" << endl;
		//http请求
		if (!flag && (strncmp(&data, "GET", 4) == 0 || strncmp(&data, "POST", 5) == 0))
		{
			flag = 1;
		}

		//http回应
		if (!flag && (strncmp(&data, "HTTP/1.1", strlen("HTTP/1.1")) == 0))
		{
			flag = 1;
		}
		if (flag)
		{
			buffer[bufsize] = packetData[i];
			bufsize++;
		}
		if (flag) {
			buffer[bufsize] = '\0';
			printf("%s\n", buffer);
		}
	}*/
	HexDatagram(packetData);
}
//HTTPS解析函数
void httpsAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("---------------------------采用https协议进行加密传输，无法获得有效数据信息！--------------------\n");
	HexDatagram(packetData);
}

void FTPAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("---------------------------------------应用层采用FTP协议------------------------------------------\n");
	printf("时间有限不做分析了，o(╥﹏╥)o\n");
	HexDatagram(packetData);
}
void TelnetAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("---------------------------------------应用层采用Telnet协议------------------------------------------\n");
	printf("时间有限不做分析了，o(╥﹏╥)o\n");
	HexDatagram(packetData);
}
void SMTPAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("---------------------------------------应用层采用SMTP协议------------------------------------------\n");
	printf("时间有限不做分析了，o(╥﹏╥)o\n");

	HexDatagram(packetData);
}
void pop3Analysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("---------------------------------------应用层采用pop3协议------------------------------------------\n");
	printf("时间有限不做分析了，o(╥﹏╥)o\n");

	HexDatagram(packetData);
}
void DNSAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("---------------------------------------应用层采用DNS协议------------------------------------------\n");
	printf("时间有限不做分析了，o(╥﹏╥)o\n");

	HexDatagram(packetData);
}
void TFTPAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("---------------------------------------应用层采用TFTP协议------------------------------------------\n");
	printf("时间有限不做分析了，o(╥﹏╥)o\n");

	HexDatagram(packetData);
}
void SNMPAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	printf("---------------------------------------应用层采用SNMP协议------------------------------------------\n");
	printf("时间有限不做分析了，o(╥﹏╥)o\n");

	HexDatagram(packetData);
}

//传输层解析函数
void transportLayerAnalysis(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData,int proto) {
	printf("-----------------------------------------传输层报文解析-------------------------------------------\n");
	if (proto==6)
	{
		cout << "传输层协议是：TCP协议\n"<<endl;
		struct tcphdr* tcpData;
		tcpData = (struct tcphdr*)(packetData + 14 + 20);
		printf("源端口：\t%d\n", ntohs(tcpData->sport));
		printf("目的端口：\t%d\n", ntohs(tcpData->dport));
		int appProtocol = (ntohs(tcpData->dport) < ntohs(tcpData->sport)) ? ntohs(tcpData->dport) : ntohs(tcpData->sport);
		cout << "应用层协议是：\t";
		switch (appProtocol)
		{
		case 80:printf("超文本传输协议（HTTP）");
			break;
		case 21:printf("文件传输协议（FTP）");
			break;
		case 23:printf("Telnet服务");
			break;
		case 25:printf("简单邮件传输协议（SMTP）");
			break;
		case 110:printf("pop3邮局协议版本3");
			break;
		case 443:printf("HTTPS(安全超文本传输协议)");
			break;
		default:printf("【其他类型】");
			break;
		}
		cout << endl;
		printf("序列号：\t%u\n", ntohs(tcpData->seq));
		printf("确认号：\t%u\n", ntohs(tcpData->ack_seq));
		printf("首部长度：\t%d\n", tcpData->doff * 4);
		printf("保留位：\t%d\n", tcpData->res1);
		printf("标识位：");
		printf("fin:%d,", tcpData->fin);
		printf("syn:%d,", tcpData->syn);
		printf("rst:%d,", tcpData->rst);
		printf("psh:%d,", tcpData->psh);
		printf("ack:%d,", tcpData->ack);
		printf("urg:%d,", tcpData->urg);
		printf("ece:%d,", tcpData->ece);
		printf("cwr:%d,", tcpData->cwr);
		cout << endl;
		printf("窗口大小:\t%d\n", ntohs(tcpData->window));
		printf("检验和:\t%d\n", ntohs(tcpData->check));
		printf("紧急指针字段:\t%d\n", ntohs(tcpData->urg_ptr));
		if (appProtocol==80)
		{
			httpAnalysis(argument, packetHeader, packetData);
		}
		else if (appProtocol==443)
		{
			httpsAnalysis(argument, packetHeader, packetData);
		}
		else if (appProtocol == 21)
		{
			FTPAnalysis(argument, packetHeader, packetData);
		}
		else if (appProtocol == 23)
		{
			TelnetAnalysis(argument, packetHeader, packetData);
		}
		else if (appProtocol == 25)
		{
			SMTPAnalysis(argument, packetHeader, packetData);
		}
		else if (appProtocol == 110)
		{
			pop3Analysis(argument, packetHeader, packetData);
		}
		else
		{
			cout << "应用层采用了某不知名协议.\n" << endl;
			HexDatagram(packetData);
		}

	}
	else if (proto==17)
	{
		struct udphdr* udpData;
		cout << "传输层协议是：UDP协议\n" << endl;
		udpData = (struct udphdr*)(packetData + 14 + 20);
		printf("源端口：\t%d\n", udpData->sport);
		printf("目的端口：\t%d\n", udpData->dport);

		int appProtocol = (udpData->dport < udpData->sport) ? udpData->dport : udpData->sport;
		cout << "应用层协议是：\t";
		switch (appProtocol)
		{
		case 53:printf("DNS域名服务");
			break;
		case 69:printf("TFTP简单文件传输协议");
			break;
		case 161:printf("SNMP简单网络管理协议");
			break;
		default:printf("【其他类型】");
			break;
		}
		cout << endl;
		printf("UDP数据报长度为：%d\n",udpData->len);
		printf("校验和为：%d\n",udpData->check);
		if (appProtocol == 53)
		{
			DNSAnalysis(argument, packetHeader, packetData);
		}
		else if (appProtocol == 69)
		{
			TFTPAnalysis(argument, packetHeader, packetData);
		}
		else if (appProtocol == 161)
		{
			SNMPAnalysis(argument, packetHeader, packetData);
		}
		else
		{
			cout << "应用层采用了某不知名协议。\n" << endl;
			HexDatagram(packetData);
		}

	}
	else if (proto==1)
	{
		struct icmphdr* icmpData;
		cout << "传输层协议是：ICMP协议\n" << endl;
		icmpData = (struct icmphdr*)(packetData + 14 + 8);
		printf("类型：\t%d，", icmpData->type);
		switch (icmpData->type)
		{
		case 0:printf("回显请求。\n");
			break;
		case 3:printf("无法到达目标。\n");
			break;
		case 4:printf("源抑制。\n");
			break;
		case 5:printf("重定向。\n");
			break;
		case 8:printf("回显应答。\n");
			break;
		case 11:printf("超时。\n");
			break;
		default:
			break;
		}
		printf("代码：\t%d\n", icmpData->code);
		printf("校验和：%d\n", icmpData->check);
		printf("其他部分：%d\n", icmpData->other);
		HexDatagram(packetData);
	}
	else if (proto == 2)
	{
		struct igmphdr* igmpData;
		cout << "传输层协议是：ICMP协议\n" << endl;
		igmpData = (struct igmphdr*)(packetData + 14 + 8);
		printf("版本号：\t%d，", igmpData->type);
		printf("报文类型：%d", igmpData->type);
		if (igmpData->type==1)
		{
			printf("主机成员查询。\n");
		}
		else if (igmpData->type==2)
		{
			printf("主机成员报告。\n");
		}
		printf("校验和：%d\n", igmpData->check);
		printf("组播地址:");
		hexToCharIP(igmpData->groupAddress);
		HexDatagram(packetData);
		cout << endl;
	}
}
//IP数据包解析函数
void IPFrameResolution(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData)
{
	struct iphdr* ipHead;
	ipHead = (struct iphdr*)(packetData + 14);//MAC首部是14位的，加上14位得到IP协议首部   
	printf("-----------------------------------------IP数据报解析-------------------------------------------\n");
	printf("版本号:%d。", ipHead->version);
	printf("长度:%d。", ipHead->ihl);
	printf("TOS服务类型:%d\n", ipHead->tos);
	printf("总长度:%d\n", ntohs(ipHead->tlen));
	printf("标识:%d\n", ntohs(ipHead->id));
	printf("偏移:%d\n", (ntohs(ipHead->frag_off) & 0x1fff) * 8);
	printf("生存时间:%d\n", ipHead->ttl);
	switch (ipHead->proto)
	{
	case 1: printf("上层协议是ICMP协议\n"); break;
	case 2: printf("上层协议是IGMP协议\n"); break;
	case 6: printf("上层协议是TCP协议\n"); break;
	case 17: printf("上层协议是UDP协议\n"); break;
	default:break;
	}
	printf("检验和:%d\n", ntohs(ipHead->check));
	printf("源IP地址:");
	hexToCharIP(ipHead->saddr);
	printf("目的地址:"); 
	hexToCharIP(ipHead->daddr);
	if (ipHead->proto == 1|| ipHead->proto == 2|| ipHead->proto == 6|| ipHead->proto == 17)//继续传输层协议分析   
	{
		transportLayerAnalysis(argument, packetHeader, packetData,ipHead->proto);
	}	
}
//IPv6数据包解析函数
void IPv6FrameResolution(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData) {
	struct ipv6hdr* ipHead;
	ipHead = (struct ipv6hdr*)(packetData + 14);//MAC首部是14位的，加上14位得到IP协议首部   
	printf("-----------------------------------------IPv6数据报解析-------------------------------------------\n");
	printf("版本号:%d。", ipHead->version);
	printf("流类型:%d。", ntohs(ipHead->flowtype));
	printf("流标签:%d\n", ntohs(ipHead->flowid));
	printf("有效载荷长度:%d\n", ntohs(ipHead->plen));
	printf("下一个头部:%d\n", ipHead->nh);
	printf("跳限制:%d\n", ipHead->hlim);
}
//以太帧解析函数
void ethernetFrameResolution(u_char* argument, const struct pcap_pkthdr* packetHeader, const u_char* packetData)
{
	static int packetNumber = 1;
	printf("**************************************捕获第%d个网络数据包信息**********************************\n", packetNumber);
	packetNumber++;

	//获取当前时间
	time_t current = time(&current);
	char buff[26];
	ctime_s(buff, sizeof buff, &current);
	printf("获取数据包的时间为：%s", buff);

	//获取长度
	printf("捕获的数据长度：%d，数据包实际长度:%d\n", packetHeader->caplen, packetHeader->len);

	printf("-----------------------------------------以太网帧解析------------------------------------------\n");
	//获取以太网帧上层协议类型
	u_short ethernetType;
	struct ethhdr* ethernetFrame;
	ethernetFrame = (struct ethhdr*)packetData;//获得以太网帧  
	ethernetType = ntohs(ethernetFrame->type);//获得以太网帧上层协议类型   
	switch (ethernetType)
	{
	case 0x0800: printf("以太网帧上层协议是IP协议。\n"); break;
	case 0x0806: printf("以太网帧上层协议是ARP协议。\n"); break;
	case 0x86DD: printf("以太网帧上层协议是IPV6协议。\n"); break;
	default:break;
	}

	//获取MAC目的地址和源地址
	u_char* MACstr;
	printf("MAC帧源地址:");
	MACstr = ethernetFrame->src;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *MACstr, *(MACstr + 1), *(MACstr + 2), *(MACstr + 3), *(MACstr + 4), *(MACstr + 5));
	printf("MAC帧目的地址:");
	MACstr = ethernetFrame->dest;
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *MACstr, *(MACstr + 1), *(MACstr + 2), *(MACstr + 3), *(MACstr + 4), *(MACstr + 5));
	if (ethernetType == 0x0800)//继续分析IP协议   
	{
		IPFrameResolution(argument, packetHeader, packetData);
	}
	else if (ethernetType == 0x0806)//继续分析ARP协议   
	{
		ARPFrameResolution(argument, packetHeader, packetData);

	}
	else if (ethernetType == 0x86DD)//继续分析IPv6协议   
	{
		IPv6FrameResolution(argument, packetHeader, packetData);
	}
}

int main() {


	char* errorBuffer_find = 0;//错误信息的字符串指针
	//pcap_if_t* d;
	pcap_if_t* item;
	pcap_if_t* item_find;//使用该变量输出设备列表
	//列出winpcap可以打开的设备列表
	if (pcap_findalldevs(&item, errorBuffer_find) == -1)//出错
	{
		printf("设备列表未成功打开，错误信息：%s", errorBuffer_find);
		return 1;
	}
	else
	{
		printf("设备列表成功打开！\n");
	}
	item_find = item;
	int n = 1;//记录设备个数
	while (item_find)
	{
		printf("第%d个设备名称为：%s\n", n, item_find->name);
		item_find = item_find->next;
		n++;
	}

	pcap_if_t* item_open;
	int Nth = 0;
	printf("请选择打开第几个设备\n");
	cin >> Nth;
	if (Nth<1 || Nth>(n - 1))
	{
		printf("不存在该设备。\n");
		return 1;
	}
	item_open = item;
	for (int i = 0; i < Nth - 1; i++)
	{
		item_open = item_open->next;
	}


	pcap_t* phandle;//会话句柄，网络接口
	int snaplen = 65525;//捕获的最大字节数设为64kB
	int promisc = 1;//默认为使用混杂模式
	int to_ms = 10000;//最多读取1s
	char* errorBuffer_open = 0;//错误消息
	char promiscMode[] = "Y";//选择是否使用混杂模式
	printf("是否使用混杂模式（默认选择混杂模式）？（Y/N）\n");
	cin >> promiscMode;
	if (strcmp(const_cast<char*>(promiscMode), "N") == 0)
	{
		printf("使用非混杂模式。\n");
		promisc = 0;
	}
	else
	{
		printf("使用混杂模式。\n");
	}


	phandle = pcap_open_live(item_open->name, snaplen, promisc, to_ms, errorBuffer_open);
	if (phandle == NULL)
	{
		printf("打开网络设备%s失败。\n", item->name);
		printf("设备列表未成功打开，错误信息：%s", errorBuffer_open);
		return 1;
	}


	//编译数据包过滤器，转换过滤表达式
	struct bpf_program filterCode;//编译程序指针
	printf("请设置过滤规则(请选择输入端口（1），协议类型（2），自主输入规则（3），应用层协议解析（4）种选项)。\n");
	
	char strFilter[20] = "ip";
	int strFilterNum = 2;
	cin >> strFilterNum;
	if (strFilterNum==1)
	{
		printf("请输入端口号。\n");
		char n[]="80";
		cin >> n;
		char port[] = "port ";
		strplus(port,n);
		strcpy_s(strFilter, 20, port);
		cout << "过滤规则为：" << strFilter << endl;
	}
	else if(strFilterNum == 2)
	{
		int pronum = 1;
		printf("请输入协议类型:ip协议（1）, arp协议（2）\n");
		cin >> pronum;
		if (pronum==1)
		{
			strcpy_s(strFilter,20,"ip");
		}
		else if(pronum == 2)
		{
			strcpy_s(strFilter, 20, "arp");
		}
		/*else if (pronum == 3)
		{
			strcpy_s(strFilter, 20, "ipv6");
		}
		else if (pronum == 4)
		{
			strcpy_s(strFilter, 20, "tcp");
		}
		else if (pronum == 5)
		{
			strcpy_s(strFilter, 20, "udp");
		}*/
		cout << "过滤规则为：" << strFilter << endl;
	}
	else if (strFilterNum == 3)
	{
		printf("请输入过滤语句，语法可参考网址：https://www.winpcap.org/docs/docs_40_2/html/group__language.html\n");
		getchar();//有趣
		cin.getline(strFilter,100);
		cout << "过滤规则为：" << strFilter << endl;
	}
	else if (strFilterNum==4)
	{
		printf("请选择监控模式：HTTP监控（1），QQ监控（2），QQ群共享文件下载监控（3），迅雷下载数据监控（4），迅雷看看数据监控（5）五种选项)。\n");
		//qq群共享文件下载使用端口9910 tcp，QQ使用端口8000 8001 ，迅雷看看使用端口4000 8000 8888 udp 迅雷使用端口5200 6200 tcp。
		int proSelect;
		cin >> proSelect;
		if (proSelect==1)
		{
			printf("开始HTTP数据监控\n");
			strcpy_s(strFilter, 20, "port 80");
		}
		else if (proSelect==2)
		{
			printf("开始QQ数据监控\n");
			strcpy_s(strFilter, 20, "port 8000");
		}
		else if (proSelect == 3)
		{
			printf("开始QQ群共享文件数据监控\n");
			strcpy_s(strFilter, 20, "port 9910");
		}
		else if (proSelect == 4)
		{
			printf("开始迅雷下载数据监控\n");
			strcpy_s(strFilter, 20, "port 5200");
		}
		else if (proSelect == 5)
		{
			printf("开始迅雷看看数据监控\n");
			strcpy_s(strFilter, 20, "port 4000");
		}
	}
	u_int netMask = 0;
	if (item_open->addresses != NULL)
	{
		netMask = ((struct sockaddr_in*)(item_open->addresses->netmask))->sin_addr.S_un.S_addr;//获取接口的第一个地址地掩码
	}
	else
	{
		netMask = 0xffffff;//若地址为空，默认掩码为255.255.255.255
	}
	if (pcap_compile(phandle, &filterCode, strFilter, 1, netMask) >= 0)//默认采用优化模式
	{
		if (pcap_setfilter(phandle, &filterCode) < 0)
		{
			printf("过滤器设置失败。\n");
			return 1;
		}
	}
	else
	{
		printf("过滤器设置出错。\n");
		return 1;
	}

	printf("请选择是否采用结构化解析模式:输出链路层，网络层，传输层和应用层各数据报详细信息？（Y/N）\n");
	char details[]="Y";
	cin >> details;
	if (strcmp(details, "N") != 0)
	{
		int sum=0;
		printf("请输出需要解析的数据报个数。\n");
		cin >> sum;
		pcap_loop(phandle, sum, ethernetFrameResolution, NULL);
	}
	else
	{
		//从网络接口或离线文件中读取数据包
		struct pcap_pkthdr* packetHeader;
		const u_char* packetData;
		/*  1 : 成功
			0 : 获取报文超时
		  - 1 : 发生错误
		  - 2 : 获取到离线记录文件的最后一个报文
		*/
		/*
		if (pcapRusult == 1)
		{
			printf("*****************************************捕获成功！**********************************************\n");
			//释放网络接口
			void pcap_freealldevs(pcap_if_t * item);
			printf("%d len:%d,%s\n", packetHeader->ts.tv_usec, packetHeader->len, packetData);
		}
		else if (pcapRusult == 0)
		{
			printf("获取报文超时。\n");
		}
		else if (pcapRusult == -1)
		{
			printf("发生错误。\n");
			return 1;
		}
		else if (pcapRusult == -2)
		{
			printf("获取到离线记录文件的最后一个报文。\n");
		}
		*/
		int pcapResult;
		while ((pcapResult = pcap_next_ex(phandle, &packetHeader, &packetData)) >= 0)
		{

			if (pcapResult == 0)
				/* Timeout elapsed */
				continue;

			/* print pkt timestamp and pkt len */
			printf("%ld:%ld (%ld)\n", packetHeader->ts.tv_sec, packetHeader->ts.tv_usec, packetHeader->len);

			/* Print the packet */
			for (int i = 1; (i < packetHeader->caplen + 1); i++)
			{
				printf("%.2x ", packetData[i - 1]);
				if ((i % 16) == 0) printf("\n");
			}

			printf("\n\n");
		}

		if (pcapResult == -1)
		{
			fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(phandle));
			return -1;
		}
	}
    return 0;
}
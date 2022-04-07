#pragma once
#include <stdlib.h>
#include <stdio.h>
#include<iostream>
#include <pcap.h>
using namespace std;

void strplus(char* str1, char* str2);
char* hexToCharIP(u_int32_t addrIP);


//����TCPͷ
typedef struct tcphdr {
	u_short sport;//Դ�˿ڵ�ַ16λ
	u_short dport;//Ŀ�Ķ˿ڵ�ַ16λ
	u_int seq;//���к�32λ
	u_int ack_seq;//ȷ�����к�
	u_short res1 : 4,
		doff : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;
	u_short window;//���ڴ�С 16λ
	u_short check;//У��� 16λ
	u_short urg_ptr;//����ָ�� 16λ
	u_int opt;//ѡ��
};
//����UDPͷ
typedef struct udphdr {
	u_short sport;//Դ�˿ڵ�ַ16λ
	u_short dport;//Ŀ�Ķ˿ڵ�ַ16λ
	u_short len;// udp����
	u_short check;//У��� 16λ
};
//����ICMPͷ
typedef struct icmphdr {
	u_int type;//���� 8λ
	u_int code;//���� 8λ
	u_short check;//У��� 16λ
	u_int32_t other;
};
//����IGMPͷ
typedef struct igmphdr {
	u_char version : 4, type : 4;
	u_char unused;
	u_int16_t check;
	u_int32_t groupAddress;
};
//������̫��֡ͷ
struct ethhdr
{
	u_char dest[6]; //Ŀ��Mac��ַ   
	u_char src[6]; //ԴMac��ַ   
	u_char type;    //Э������   
};
//����IPͷ
struct iphdr
{

	u_char   ihl : 4;//ͷ������4bit
	u_char	 version : 4; //�汾��4bit
	u_char    tos;//tos��������
	u_short   tlen;//���ܳ�
	u_short   id;//��ʶ
	u_short   frag_off;//Ƭλ��
	u_char    ttl;//����ʱ��
	u_char    proto;//Э��
	u_short   check;//У���
	u_int32_t saddr;
	u_int32_t daddr;
	u_int op_pad;//ѡ��
};
//����IPv6
typedef struct ipv6hdr
{
	u_int version : 4,				//�汾
		flowtype : 8,			//������
		flowid : 20;				//����ǩ
	u_short plen;					//��Ч�غɳ���
	u_char nh;						//��һ��ͷ��
	u_char hlim;					//������
	u_int32_t saddr;
	u_int32_t daddr;
};
//ARPͷ
typedef struct arphdr
{
	u_short hrd;						//Ӳ������
	u_short pro;						//Э������
	u_char hln;						//Ӳ����ַ����
	u_char pln;						//Э���ַ����
	u_short op;						//�����룬1Ϊ���� 2Ϊ�ظ�
	u_char srcmac[6];			//���ͷ�MAC
	u_int32_t saddr;			//���ͷ�IP
	u_char destmac[6];			//���շ�MAC
	u_int32_t daddr;			//���շ�IP
};
//DNSͷ
typedef struct dnshdr
{
	u_short id;	//��ʶ
	u_short flag;	//��־
}dns_header;
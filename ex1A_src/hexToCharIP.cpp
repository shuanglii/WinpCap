#include <pcap.h>
//ת��IP��ַ��ʽ
char* hexToCharIP(u_int32_t addrIP) {
	char* ip;
	unsigned int intIP;
	memcpy(&intIP, &addrIP, sizeof(unsigned int));
	int a = (intIP >> 24) & 0xFF;
	int b = (intIP >> 16) & 0xFF;
	int c = (intIP >> 8) & 0xFF;
	int d = intIP & 0xFF;

	if ((ip = (char*)malloc(16 * sizeof(char))) == NULL) {
		return NULL;
	}
	printf("%d.%d.%d.%d\n", d, c, b, a);
	return ip;
}
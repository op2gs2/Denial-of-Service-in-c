#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
 
 
 int main(int argc, char **argv)
{
	if (argc < 3) 
	{
		printf("usage: %s <도착지 IP> <목적지 IP> [페이로드 크기]\n", argv[0]);
		exit(0);
	}
	
	unsigned long daddr;
	unsigned long saddr;
	int payload_size = 0, sent, sent_size;
	
	saddr = inet_addr(argv[1]); // 문자열 행태를 숫자 형태로  
	daddr = inet_addr(argv[2]); // 문자열 행태를 숫자 형태로
	
	if (argc > 3)
	{
		payload_size = atoi(argv[3]);
	}

    //  어느 특정한 프로토콜 용의 전송 계층 포맷팅 없이 인터넷 프로토콜 패킷을 직접적으로 주고 받게 해주는 소켓
    // Raw 사용 network layer  을 다루기 위해서 raw socket 을 만들어아햠
    // ipproto_Raw 를 사용하면 계층 3과 직접 상호 작용 가능 
    // ip 패킷의 헤더와 페이로드를 편집할수 있다
	int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    
    if (sockfd < 0) 
	{
		perror("could not create socket");
		return (0);
	}
	
	int on = 1;
	
	
    // 소켓 세부 설정 
    // ip 프로토콜을 옵션을 가져온다 ? ,
    // 	ip hdrincl TRUE로 설정하면 애플리케이션이 IP 헤더를 제공함을 나타냅니다 
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
	{
		perror("setsockopt");
		return (0);
	}

    // 소켓 세부설정 
    /*setSocket 으로 소켓의 ip 헤더를 건드림 + 대역폭 설정 ??*/

    // 페이로드 설정 
    // ip header (20 byte) + icmp header + 8byte + icmp 데이터 크기 변조
    
    //ip 헤더와 icmp 헤더 바꾸기 -> 어떻게 ???

    //소켓 주소 와 구조체 설정 

    
    while (1) {

        //소켓 send

        //체크섬 함수 호출  
    }
}
    
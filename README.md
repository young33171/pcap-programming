# PCAP Programming

화이트햇스쿨 네트워크 보안 PCAP Programming 과제입니다.

## 개발 환경

- OS : Ubuntu (WSL)
- Language : C
- Compiler : GCC
- Library : libpcap

## 구현 기능

- Ethernet Header 출력
  - Source MAC Address
  - Destination MAC Address

- IP Header 출력
  - Source IP Address
  - Destination IP Address

- TCP Header 출력
  - Source Port
  - Destination Port

- HTTP Message 출력

## 실행 방법

```bash
gcc pcap_assignment.c -o pcap_assignment -lpcap
sudo ./pcap_assignment
```

## 사용 기술

- PCAP API
- pcap_open_live()
- pcap_compile()
- pcap_setfilter()
- pcap_loop()

## 실행 화면

패킷을 캡처하여 Ethernet Header, IP Header, TCP Header, HTTP Message를 출력한다.

## 작성자

WhiteHat School 4기

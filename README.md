# GolangARPScan
go언어 ARPScan예제  windows // linux

ARP Scan을 해야하는 상황이있어서 검색을 해본후 정리를 해서 Windows와 Linux용으로 테스트를 거쳤습니다.

ARP.go // ARP_windows.go // ARP_linux.go 3가지가 주 코드이며 windows는 윈도우용 linux는 리눅스용입니다.

리눅스에서 사용할경우 관리자권한이 필요합니다.

필수 설치 라이브러리
-----
windows : NPCAP  (https://nmap.org/npcap/)
linux :  libpcap (sudo apt-get install libpcap-dev) [Root require]

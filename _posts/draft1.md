
Các challenge OSINT trong giải này cho ta nhập vai vào điều tra viên của biệt đội `NIGHTFALL`.

Mỗi challenge cho ta một máy chủ từ xa có đủ cơ sở dữ liệu cần thiết. Việc của ta là đọc briefing, lọc dấu hiệu liên quan, đối chiếu giữa các nguồn rồi nhập kết quả vào flag holder.

Dưới đây là write up cho 5 challenges tương ứng với 5 cases của `ANALYST-7`.

---
# FIRST LIGHT

Chuyên án 01, ta được cấp `Aviation Database` (csdl hàng không) và `Aviation Tracker` (hệ thống theo dõi hàng không). Đầu tiên, ta sẽ mở `Case Briefing` (hồ sơ tóm tắt) để nắm được nhiệm vụ.

## Báo cáo sơ bộ

![](attachment/Pasted%20image%2020260518231159.png)

Bốn mươi tám giờ trước **cuộc bầu cử**, có một chiếc máy bay vận tải *Antonov An-26* mang đánh dấu của *Korvia* đã được phát hiện bởi một người đam mê hàng không dân dụng khi đang cất cảnh tại một sân bay không được đánh dấu tại *Korvia*.

Phòng Hàng không cần các thông tin nhận dạng cơ bản: số hiệu đuôi (*tail number*, hay còn tên gọi khác là *registration*), đơn vị vận hành, và mã *ICAO* của điểm đến cuối cùng của chiếc phi cơ.

![](attachment/Pasted%20image%2020260518231218.png)

Các manh mối về chiếc máy bay ta cần tìm kiếm:
1. Dữ liệu tới từ *database dân sự*
2. Loại máy bay: *Antonov An-26* 
3. Partial reg (một phần số hiệu đuôi): `UR-???7`
4. Vị trí: phía Đông *Korvia*; FIR (vùng thông báo bay) `LKKR`
5. Thời điểm: `2026-03-14 06:12 UTC`
6. Trạng thái cất cánh: bay về phía Tây, đang lấy thêm độ cao qua mức khoảng 3000 ft
7. Ghi chú: động cơ nóng, vừa mới khởi hành; không có kế hoạch bay nào được nộp tại địa phương.

## Phân tích hàng không

Mở `Aviation Database`, lọc loại phi cơ *Antonov An-26*. Ta sẽ thấy chiếc `UR-CKL7` khớp với partial registration `UR-???7`, loại máy bay *An-26* và khu vực hoạt động trong FIR `LKKR`.

![](attachment/2026-05-18_23-13.png)

Ta tiếp tục thẩm định bằng `Aviation Tracker`, kiểm tra position pings (tín hiệu định vị) quanh timestamp (mốc thời gian) `2026-03-14 06:12 UTC`.

![](attachment/Pasted%20image%2020260519155100.png)

Độ cao, hướng bay và trạng thái lấy độ cao đều khớp với báo cáo hiện trường. Vì máy bay vừa rời đường băng không lâu trước đó, ghi chú “*engines hot, recent departure*”  (động cơ nóng, vừa khởi hành) cũng hợp lý.

## Kết luận & Flag

Đến đây ta chắc chắn rằng `UR-CKL7` là chiếc máy bay ta cần báo cáo.

![](attachment/Pasted%20image%2020260518231225.png)

`HTB{UR-CKL7_KORVIAN-AIRLIFT_LKKB}`

---
# QUIET WAKE

Chuyên án 02, ta được cấp `Maritime Tracker` (hệ thống theo dõi hàng hải)  và `Vessel Register` (sổ đăng ký tàu biển).

## Báo cáo sơ bộ

![](attachment/Pasted%20image%2020260518113631.png)

Một tàu chở hàng tổng hợp treo cờ *Panama* gần đây đã thực hiện nhiều chuyến ghé cảng không theo lịch trình tại Cảng *Vargstad* – đây chính là cảng có mạng lưới hệ thống điều khiển công nghiệp (*ICS*) logistics bị nghi ngờ là đã bị Phe *Rust* cài cắm vịz trí từ trước.
Ta có một phần mã *MMSI* (Maritime Mobile Service Identity) từ tín hiệu vô tuyến bị chặn và một báo cáo quan sát từ camera nhiệt.

Yêu cầu xác định: 
- Số *IMO* (International Maritime Organization) đầy đủ
- Chủ sở hữu hưởng lợi thực tế
- Ngày cập cảng *Vargstad* gần đây nhất của con tàu này.

## Phân tích & So khớp

![](attachment/Pasted%20image%2020260518115818.png)

Từ phần chặn tín hiệu, ta bắt được mã nhận diện vô tuyến *MMSI* dạng `352****7`, tàu treo cờ *Panama* và đang hướng về *Vargstad*. 

![](attachment/Pasted%20image%2020260518115604.png)

Từ báo cáo camera nhiệt, tên tàu bắt đầu bằng chữ *N*, loại tàu là *general cargo* (tàu chở hàng tổng hợp), *LOA* (chiều dài toàn bộ tàu) khoảng 120 m và có một cần cẩu đơn phía trước.

Xem qua danh sách tàu trong `Maritime Tracker`, sau khi lọc theo các dấu hiệu trên thì còn 2 ứng cử viên là *MV NORDLYS TRADER* và *MV NEPTUNE STAR*.

Kiểm tra phần lịch sử cập cảng cho từng tàu, ta thấy *MV NORDLYS TRADER* có tới *Vargstad*.

![](attachment/Pasted%20image%2020260518120048.png)

Hướng di chuyển trong *AIS positions* (hệ thống định vị tự động tàu thuyền) cũng khớp với hướng tiếp cận từ báo cáo camera nhiệt. Vì vậy ta kết luận được tàu cần báo lại là *MV NORDLYS TRADER*, số hiệu *IMO* `9678234` 

![](attachment/Pasted%20image%2020260518120402.png)

## Tổng hợp & Flag

Sử dụng `Vessel Registry` với số *IMO* `9678234` ta tìm được chủ sở hữu hưởng lợi thực tế  `NYRDEN HOLDINGS S.A.`

![](attachment/Pasted%20image%2020260518121323.png)

`Port Call History` cho biết lần cập *Vargstad* gần nhất là `2026-03-09`.

![](attachment/Pasted%20image%2020260518121407.png)

![](attachment/Pasted%20image%2020260519164821.png)

`HTB{9678234_NYRDEN-HOLDINGS-SA_2026-03-09}`

--- 
# PHANTOM ECHO

Chuyên án 03 quay lại mảng hàng không. Lần này ta không chỉ tìm một chiếc máy bay, mà còn kiểm chứng dải tín hiệu *ADS-B* (hệ thống giám sát tự động phụ thuộc - phát sóng) bị giả mạo.

## Báo cáo sơ bộ

![](attachment/Pasted%20image%2020260518232759.png)

Hệ thống trao đổi dữ liệu giám sát hàng không (*ADB-S Exchange*) bắt được một chuyến bay phát *squawk* (mã radar nhận diện) thương mại thông thường, bay thấp qua cụm trạm biến áp *Vestmark*.
Kế hoạch bay khai báo đây là một chuyến bay "*regional positioning, empty leg*" (vận chuyển nội vùng, chặng trống). Tuy nhiên, tổ trinh sát tín hiệu (*SIGINT cell*) cho biết chiếc máy bay có số đăng ký trùng khớp với chuyến bay này đang đỗ trên mặt đất tại một vị trí cách đó 600 km vào cùng thời điểm.

Nhiệm vụ gồm ba phần:
- Xác nhận *spoof* bằng dữ liệu vật lý và thời tiết.
- Giải mã *fragment D9* để tìm *ICAO24* thật.
- Xác định *operator* thực sự.

## Phân tích & So khớp

![](attachment/Pasted%20image%2020260518232749.png)

*ADS-B summary* ghi số hiệu chuyến bay `KOR1337`, *ICAO24* khai báo `481A22`, loại A320, độ cao 1,800 ft *AGL* (độ cao so với mặt đất), tốc độ mặt đất khoảng 320 kts (hải lý/giờ).
Quỹ đạo bay đi qua cụm trạm biến áp *Vestmark* trong khung `2026-03-12 23:14-23:32 UTC`.

![](attachment/Pasted%20image%2020260518232830.png)

![](attachment/Pasted%20image%2020260518233750.png)

Báo cáo thời tiết sân bay định kỳ tại *VST* lúc `23:00Z` báo gió 240 độ (thổi từ Tây-Tây Nam), tốc độ 45 kts, giật 56 kts; tầm nhìn thấp, bão tuyết thổi mạnh, sương giá tích tụ, hoạt động sóng núi và nhiễu động không khí dữ dội.

Có thể thấy điều kiện thời tiết rất nguy hiểm đổi với các chuyến bay.

### Xác nhận spoof

Trong `Aviation Tracker`, dải *position pings* của `KOR1337` đã bị đánh dấu bất thường.

![](attachment/Pasted%20image%2020260518233022.png)
![họ note sẵn cho ta](attachment/Pasted%20image%2020260518232959.png)

Trong đây, họ đã soạn sẵn `Anomaly Note`, có những điểm sau:
- Với địa hình hành lang có đỉnh vượt 6,000 ft *AMSL* (độ cao so với mực nước biển trung bình), tàu bay ở độ cao 1.800 ft *AGL* sẽ ở vị trí thấp hơn mặt đất tại nhiều phân đoạn.
- Mã *Squawk 2000 = VFR Conspicuity* (mã radar nhận diện cho chuyến bay tự do bằng mắt). Không có kế hoạch bay IFR (bay bằng thiết bị/quy tắc bay bặt cụ) nào được nộp để bay qua vùng địa hình núi hiểm trở vào ban đêm.
- Báo cáo thời tiết đã cho thấy rằng tuyến bay qua đó rất nguy hiểm, Không một hãng khai thác thương mại nào sẽ cấp phép cho đường bay này.
- Độ cao được duy trì bằng phẳng một cách hoàn hảo trong suốt 18 phút băng qua vùng địa hình đồi núi -> dấu hiệu điển hình của việc giả mạo dữ liệu *ADS-B*.

## Kết luận & Flag

Chừng đó thông tin là đủ để ta xác nhận đây là chuyến bay bị phát giả.
Ta giải mã ICAO24 & xác định operator:

![](attachment/Pasted%20image%2020260518232837.png)

Manh mối cho thấy *true asset* là `XOR-37(7C2D62) = 4B1A55`.
Operator được ghi rõ là `D9-SIGINT-WING`.

Đến đây ta có đầy đủ các thông tin cấu thành:

![](attachment/Pasted%20image%2020260518232927.png)

`HTB{KOR1337_4B1A55_D9-SIGINT-WING}`

---
# DARK LANE

Chuyên án 04 chuyển sang chuỗi hàng hải ngầm: một tàu *tanker LR2* (tàu chở dầu cỡ lớn lớp Long Range 2) biến mất khỏi *AIS* trong thời gian dài rồi tái xuất hiện với thay đổi bất thường.

## Báo cáo sơ bộ

![](attachment/Pasted%20image%2020260518235559.png)

Một tàu chở dầu cỡ lớn lớp *LR2* nằm trong danh sách giám sát của chúng ta, chiếc *MV STORMRIDER*, đã chủ động tắt thiết bị định danh hệ thống *AIS* suốt 71 giờ khi di chuyển qua vùng bồn địa *Adric Basin*. 

Khi bật lại *AIS*, con tàu có sự thay đổi rõ rệt về *draft* (mớn nước) và *freeboard* (khoảng cao mạn khô) – dấu hiệu cho thấy nó đã nhận thêm một lượng tải trọng lớn thông qua hình thức chuyển tải giữa hai tàu (*Ship-to-Ship transfer - STS*) trong thời gian tắt tín hiệu.

Trong khoảng thời gian tắt tín hiệu này, tổ chức ***Gilded Weaver*** (?) cũng đang tiến hành trinh sát một hệ thống cáp quang ngầm đi qua bồn địa này.

Do không có ảnh vệ tinh hỗ trợ, ta phải dựa vào lịch sử vị trí *AIS*, nhật ký radar *SAR* (Radar khẩu độ tổng hợp/vệ tinh radar) và cơ sở dữ liệu cáp ngầm để xác định:
- Tàu thứ hai tham gia chuyển tải.
- Tên hệ thống cáp bị ảnh hưởng.
- Tọa độ chính xác của cuộc gặp.

## Phân tích & So khớp

![](attachment/Pasted%20image%2020260521183206.png)

Theo báo cáo bất thường (*TARGET VESSEL AIS GAP REPORT*), tàu mục tiêu là
***MV STORMRIDER*** (*IMO* `7512098`).

Ghi nhận mất tín hiệu từ ngày `2026-03-05 19:42 UTC` tại tọa độ `42.7841 N, 18.2210 E`, bật lại lúc `2026-03-08 18:51 UTC` tại tọa độ `40.5012 N, 14.8550 E`.

Mớn nước tăng thêm tới ~3m chứng tỏ tàu đã nhận thêm hàng khi tắt *AIS*.

![](attachment/Pasted%20image%2020260521183144.png)

Tiếp tục đọc cảnh báo an ninh hàng hải (*MARITIME DOMAIN AWARENESS ALERT* - ID: `MDA-2026-0307-0042`), hệ thống điều khiển và radar *SAR* đã phát hiện ra một cặp tàu áp mạn nhau (*two-hull cluster*) nằm trong vùng trôi dạt dự tính của tàu *STORMRIDER*.

Để ý thời điểm cảnh báo `2026-03-07 02:15 UTC` nằm trong *AIS gap* của tàu mục tiêu. Ta đi kiểm tra các log liên quan.

Mở `Maritime Tracker`, lọc khu vực *Adric Basin*.

Trong danh sách tàu, *MV STORMRIDER* được đánh dấu *AIS GAP*, ngoài ra còn có *MV BLACKWATER PRIDE* cũng có trạng thái bất thường.

![](attachment/Pasted%20image%2020260518235732.png)

Ta mở `SAR Detection Log` (nhật ký phát hiện của radar vệ tinh), đối chiếu được rằng 2 tàu bị đánh dấu ở trên chính là 2 tàu ta cần báo cáo.

![](attachment/Pasted%20image%2020260521185412.png)

Ngoài ra, cờ tàu cho biết quốc gia nơi tàu được đăng ký và chịu quản lý pháp lý. Tra cứu trong `Vessel Registry` cho thấy *MV BLACKWATER PRIDE* được đổi cờ nhiều lần trong thời gian ngắn.

Đổi cờ nhiều lần là cách để né quy định, né trừng phạt, che chủ sở hữu, hoặc làm mờ lịch sử hoạt động của tàu.

![](attachment/Pasted%20image%2020260521185557.png)

Điều này ám chỉ rằng con tàu có hoạt động mờ ám (*dark fleet* - tàu lậu).

## Kết luận & Flag

Đến đây, ta đã tìm được tàu *MV STORMRIDER* & *MV BLACKWATER PRIDE* là 2 tàu thực hiện *STS Transfer*.

Nhưng vẫn còn nữa: trong chuyên án này, briefing nghi ngờ STS có thể là hoạt động hỗ trợ chiến dịch trinh sát cáp ngầm của ***Glided Weaver***, nên tuyến điều tra ta nối thêm 1 lớp:

	AIS gap của STORMRIDER
	→ nghi có STS transfer
	→ tọa độ STS nằm trong khu vực Adric Basin
	→ cùng khu vực có tuyến cáp ngầm bị Gilded Weaver trinh sát
	→ dùng tọa độ STS để tra Cable Database

Lấy vĩ độ (*LAT*), kinh độ (*LON*) tại `SAR Log` đem vào `Cable Database` (csdl cáp ngầm) tra cứu ta có được tên hệ thống cáp.

![](attachment/Pasted%20image%2020260521190732.png)

![](attachment/Pasted%20image%2020260518235638.png)

`HTB{9512098_9765432_VARDA-SUBLINK_42.1234_18.5678}`

---
# BLACKOUT ARCHITECT

Chuyên án 05 là mắt xích cuối của chuỗi điều tra.

## Báo cáo sơ bộ

![](attachment/Pasted%20image%2020260519001510.png)

Sau khi lần theo đường đi của máy bay, tàu chuyển tải, container & cảng nhận hàng, ta cần xác nhận đơn vị *ICS* (nhà cung cấp hệ thống điều khiển công nghiệp) bị cài cắm đã đứng ra nhận lô thiết bị dùng cho đợt tấn công hạ tầng đêm bầu cử.

Phần cứng mà **Gilded Weaver** dự định dùng để tấn công sự cố hạ tầng trong đêm bầu cử đã được đưa vào quốc gia thông qua một chuỗi logistics đã được tẩy rửa nhiều lớp.

Việc còn lại của ta là tìm **mắt xích cuối cùng**: nhà thầu *ICS* đã được ủy quyền nhận và lắp đặt thiết bị tại trạm biến áp. Từ đó, ta cần lấy được **mã hợp đồng** trong hồ sơ procurement.

Nhiệm vụ gồm hai phần:
1. Xác định *ICS vendor* trong danh sách 4 ứng viên.
2. Lấy *contract number* (số hợp đồng) tương ứng với vendor đó.

## Xâu chuỗi từ dossier

Mở `Consolidated Intelligence Dossier` (Hồ sơ Tình báo Hợp nhất), ta thấy báo cáo tổng hợp lại toàn bộ chuỗi trước đó, bao gồm cả những thông tin chưa có trong các chuyên án trước của ta.

![](attachment/Pasted%20image%2020260522233018.png)

Kiện hàng `KORV1488221` được thả trên biển & được tàu *MV STORMRIDER* nhận, sau đó chuyển tải với *MV BLACKWATER PRIDE*.
Sau đó, nó được rửa giấy tờ trên đường và cuối cùng được tải tới cảng *Vargstad* bởi tàu *MV NORDLYS TRADER*.

Phần xử lý sau khi cập cảng là đoạn bắt đầu liên quan trực tiếp tới chuyên án này.

![](attachment/Pasted%20image%2020260522231508.png)

Dossier ghi:
- Container được vận chuyển khỏi cảng bởi một *ICS vendor* theo hợp đồng dịch vụ thường trực với đơn vị vận hành trạm biến áp *Vestmark*.
- Vendor thỏa đồng thời:
	-  Có cấu trúc sở hữu vỏ bọc sâu **2 lớp**.
	- Chủ sở hữu hưởng lợi cuối cùng nằm trong ****OFAC SDN list****.
	- Chủ sở hữu đó có liên hệ với ***Korvia****.
	- Vendor nằm trong procurement memo của ***Vestmark Grid Operating Company***.

## Kiểm tra & So khớp

### Vận đơn đường biển & Bản ghi đấu thầu

Mở *Bill of Lading* của container:

![](attachment/Pasted%20image%2020260522232221.png)

Ta thấy thời điểm cập cảng, tàu chở đến, người nhận hàng, *manifest* (bản kê khai hàng hóa) khai báo đều khớp với báo cáo trong *dossier*.

Ta tiếp tục xem *procurement memo* `VGOC-PROC-FY26-0114` để biết danh sách người nhận được ủy quyền.

Danh sách gồm 4 vendor; trong đó, chỉ có ***TRUSTED GRID SOLUTION LLC*** có parent company ở nước ngoài, đây là ứng viên phù hợp nhất với chỉ báo "*shell ownership 2 layers deep*".

![](attachment/Pasted%20image%2020260522233515.png)

### Csdl đăng ký doanh nghiệp

Ta mở *Corporate Registry*, kiểm tra thẳng *TRUSTED GRID SOLUTION LLC*:

![](attachment/Pasted%20image%2020260522234030.png)

Thấy rằng công ty này khớp đầy đủ các chỉ báo:
- Có công ty mẹ: *MERIDIAN INDUSTRIAL HOLDINGS.
- Công ty mẹ đăng ký tại *Marshall Islands*.
- Chủ sở hữu hưởng lợi cuối cùng là **VICTOR KOSEV**:
	- **OFAC SDN-listed** (Danh sách các công dân bị chỉ định đặc biệt của Văn phòng Kiểm soát Tài sản Nước ngoài Hoa Kỳ)
	- Có liên hệ tới Korvia.
- Nằm trong procurement memo của Vestmark Grid Operating Company.

## Kết luận & Flag

Vậy vendor bị cài cắm là  *TRUSTED GRID SOLUTION LLC*, contract tương ứng là `CDR-9988-VST`.

![](attachment/Pasted%20image%2020260519001528.png)

`HTB{CDR-9988-VST_TRUSTED-GRID-SOLUTIONS-LLC}`

## Final thoughts

Các thử thách 
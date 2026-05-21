
Các challenge OSINT trong giải này cho ta nhập vai vào điều tra viên `ANALYST-7` của biệt đội `NIGHTFALL`.

![](attachment/Pasted%20image%2020260518231656.png)

Mỗi instance cho ta một máy remote có đủ cơ sở dữ liệu cần thiết. Việc của ta là đọc briefing, lọc dấu hiệu liên quan, đối chiếu giữa các nguồn rồi nhập kết quả vào flag holder.

Dưới đây là write up cho 5 challenges tương ứng với 5 cases của `ANALYST-7`.

---
# FIRST LIGHT

Chuyên án 01, ta được cấp cho các công cụ `Aviation Database`, `Aviation Tracker`. Đầu tiên, ta sẽ mở `Case Briefing` để nắm được nhiệm vụ.

## Tóm tắt vụ việc

![](attachment/Pasted%20image%2020260518231159.png)

Bốn mươi tám giờ trước **cuộc bầu cử**, có một chiếc máy bay vận tải *Antonov An-26* mang đánh dấu của *Korvia* đã được phát hiện bởi một người đam mê hàng không dân dụng khi đang cất cảnh tại một sân bay không được đánh dấu tại *Korvia*.

Phòng Hàng không cần các thông tin nhận dạng cơ bản: số hiệu đuôi, đơn vị vận hành, và mã *ICAO* của điểm đến cuối cùng của chiếc phi cơ.

![](attachment/Pasted%20image%2020260518231218.png)

Các manh mối về chiếc máy bay ta cần tìm kiếm:
1. Dữ liệu tới từ *database dân sự*
2. Loại máy bay: *Antonov An-26* 
3. Partial reg (Registration - Số đăng ký máy bay): `UR-???7`
4. Vị trí: phía Đông *Korvia*; FIR (Flight Information Region) `LKKR`
5. Thời điểm: `2026-03-14 06:12 UTC`
6. Trạng thái cất cánh: bay về phía Tây, đang lấy thêm độ cao qua mức khoảng 3000 ft
7. Ghi chú: động cơ nóng, vừa mới khởi hành; không có kế hoạch bay nào được nộp tại địa phương.

## So khớp

Mở `Aviation Database`, lọc loại phi cơ *Antonov An-26*. Ta sẽ thấy chiếc `UR-CKL7` khớp với partial registration `UR-???7`, loại máy bay *An-26* và khu vực hoạt động trong FIR `LKKR`.

![](attachment/2026-05-18_23-13.png)

Ta tiếp tục thẩm định bằng `Aviation Tracker`, kiểm tra position pings quanh timestamp `2026-03-14 06:12 UTC`.

![](attachment/Pasted%20image%2020260519155100.png)

Độ cao, hướng bay và trạng thái climb đều khớp với báo cáo hiện trường. Vì máy bay vừa rời đường băng không lâu trước đó, ghi chú “engines hot, recent departure” cũng hợp lý.

Đến đây ta chắc chắn rằng `UR-CKL7` là chiếc máy bay ta cần báo cáo.

## Flag

![](attachment/Pasted%20image%2020260518231225.png)

`HTB{UR-CKL7_KORVIAN-AIRLIFT_LKKB}`

---
# QUIET WAKE

Chuyên án 02, ta được cấp `Maritime Tracker`  và `Vessel Register`.

## Tóm tắt vụ việc

![](attachment/Pasted%20image%2020260518113631.png)

Một tàu chở hàng tổng hợp treo cờ *Panama* gần đây đã thực hiện nhiều chuyến ghé cảng không theo lịch trình tại Cảng *Vargstad* – đây chính là cảng có mạng lưới hệ thống điều khiển công nghiệp (*ICS*) logistics bị nghi ngờ là đã bị Phe *Rust* cài cắm vị trí từ trước.
Ta có một phần mã *MMSI* (Maritime Mobile Service Identity) từ tín hiệu vô tuyến bị chặn và một báo cáo quan sát từ camera nhiệt.

Yêu cầu xác định: 
- Số *IMO* (International Maritime Organization) đầy đủ
- Chủ sở hữu hưởng lợi thực tế
- Ngày cập cảng *Vargstad* gần đây nhất của con tàu này.

## Tìm kiếm hàng hải

![](attachment/Pasted%20image%2020260518115818.png)

Từ phần chặn tín hiệu, ta bắt được mã nhận diện vô tuyến *MMSI* dạng `352****7`, tàu treo cờ *Panama* và đang hướng về *Vargstad*. 

![](attachment/Pasted%20image%2020260518115604.png)

Từ báo cáo camera nhiệt, tên tàu bắt đầu bằng chữ *N*, loại tàu là *general cargo*, *LOA* (Length Overall) khoảng *120 m* và có một cần cẩu đơn phía trước.

Xem qua danh sách tàu trong `Maritime Tracker`, sau khi lọc theo các dấu hiệu trên thì còn 2 ứng cử viên là *MV NORDLYS TRADER* và *MV NEPTUNE STAR*.

Kiểm tra phần `Port Call History` cho từng tàu, ta thấy *MV NORDLYS TRADER* có tới *Vargstad*.

![](attachment/Pasted%20image%2020260518120048.png)

Hướng di chuyển trong `AIS positions`(Automatic Identification System) cũng khớp với hướng tiếp cận từ báo cáo camera nhiệt. Vì vậy ta kết luận được tàu cần báo lại là *MV NORDLYS TRADER*, số hiệu *IMO* `9678234` 

![](attachment/Pasted%20image%2020260518120402.png)

## Tổng hợp thông tin

Sử dụng `Vessel Registry` với số *IMO* `9678234` ta tìm được chủ sở hữu hưởng lợi thực tế  `NYRDEN HOLDINGS S.A.`

![](attachment/Pasted%20image%2020260518121323.png)

`Port Call History` cho biết lần cập *Vargstad* gần nhất là `2026-03-09`.

![](attachment/Pasted%20image%2020260518121407.png)

## Flag

![](attachment/Pasted%20image%2020260519164821.png)

`HTB{9678234_NYRDEN-HOLDINGS-SA_2026-03-09}`

--- 
# PHANTOM ECHO

Chuyên án 03 quay lại mảng hàng không. Lần này ta không chỉ tìm một chiếc máy bay, mà còn kiểm chứng dải tín hiệu *ADS-B* bị giả mạo.

## Tóm tắt vụ việc

![](attachment/Pasted%20image%2020260518232759.png)

Hệ thống trao đổi dữ liệu giám sát hàng không (*ADB-S Exchange*) bắt được một chuyến bay phát *squawk* thương mại thông thường, bay thấp qua cụm trạm biến áp *Vestmark*.
Kế hoạch bay khai báo đây là một chuyến bay "vận chuyển nội vùng, chặng trống" (*regional positioning, empty leg*). Tuy nhiên, tổ trinh sát tín hiệu (*SIGINT cell*) cho biết chiếc máy bay có số đăng ký trùng khớp với chuyến bay này đang đỗ trên mặt đất tại một vị trí cách đó 600 km vào cùng thời điểm.

Nhiệm vụ gồm ba phần:
- Xác nhận *spoof* bằng dữ liệu vật lý và thời tiết.
- Giải mã *fragment D9* để tìm *ICAO24* thật.
- Xác định *operator* thực sự.

## Duyệt qua các manh mối

![](attachment/Pasted%20image%2020260518232749.png)

*ADS-B summary* ghi *callsign* `KOR1337`, *ICAO24* khai báo `481A22`, loại A320, độ cao 1,800 ft *AGL* (Above Ground Level), tốc độ mặt đất khoảng 320 kts.
Track đi qua cụm trạm biến áp Vestmark trong khung `2026-03-12 23:14-23:32 UTC`.

![](attachment/Pasted%20image%2020260518232830.png)

![](attachment/Pasted%20image%2020260518233750.png)

Báo cáo thời tiết sân bay định kỳ tại VST lúc `23:00Z` báo gió 240 độ (thổi từ Tây-Tây Nam), tốc độ 45 knot (hải lý/giờ), giật 56 knot; tầm nhìn thấp, bão tuyết thổi mạnh, sương giá tích tụ, hoạt động sóng núi và nhiễu động không khí dữ dội.

Có thể thấy điều kiện thời tiết rất nguy hiểm đổi với các chuyến bay.

## Xác nhận spoof

Trong `Aviation Tracker`, dải position pings của `KOR1337` đã bị đánh dấu bất thường.

![](attachment/Pasted%20image%2020260518233022.png)
![họ note sẵn cho ta](attachment/Pasted%20image%2020260518232959.png)

Trong đây, họ đã soạn sẵn `Anomaly Note`, có những điểm sau:
- Với địa hình hành lang có đỉnh vượt 6,000 ft *AMSL*, tàu bay ở độ cao 1.800 ft *AGL* sẽ ở vị trí thấp hơn mặt đất tại nhiều phân đoạn.
- Mã Squawk 2000 = VFR Conspicuity (Mã radar nhận diện bay VFR tự do). Không có kế hoạch bay IFR nào được nộp để bay qua vùng địa hình núi hiểm trở vào ban đêm.
- Báo cáo thời tiết đã cho thấy rằng tuyến bay qua đó rất nguy hiểm, Không một hãng khai thác thương mại nào sẽ cấp phép cho đường bay này.
- Độ cao được duy trì bằng phẳng một cách hoàn hảo trong suốt 18 phút băng qua vùng địa hình đồi núi -> dấu hiệu điển hình của việc giả mạo dữ liệu *ADS-B*.

Chừng đó thông tin là đủ để ta xác nhận đây là chuyến bay bị phát giả.

## Giải mã ICAO24 & Xác định operator

![](attachment/Pasted%20image%2020260518232837.png)

Manh mối cho thấy *true asset* là `XOR-37(7C2D62) = 4B1A55`.
Operator được ghi rõ là `D9-SIGINT-WING`.

## Flag

Đến đây ta có đầy đủ các thông tin cấu thành:

![](attachment/Pasted%20image%2020260518232927.png)

`HTB{KOR1337_4B1A55_D9-SIGINT-WING}`

---
# DARK LANE

Chuyên án 04 chuyển sang chuỗi hàng hải ngầm: một tàu *tanker LR2* biến mất khỏi *AIS* trong thời gian dài rồi tái xuất hiện với thay đổi bất thường.

## Tóm tắt vụ việc

![](attachment/Pasted%20image%2020260518235559.png)

Một tàu chở dầu cỡ lớn lớp *LR2* nằm trong danh sách giám sát của chúng ta, chiếc *MV STORMRIDER*, đã chủ động tắt thiết bị định danh hệ thống *AIS* suốt 71 giờ khi di chuyển qua vùng bồn địa *Adric Basin*. 

Khi bật lại *AIS*, con tàu có sự thay đổi rõ rệt về *draft* (mớn nước) và *freeboard* (khoảng cao mạn khô) – dấu hiệu cho thấy nó đã nhận thêm một lượng tải trọng lớn thông qua hình thức chuyển tải giữa hai tàu (*Ship-to-Ship transfer*) trong thời gian tắt tín hiệu.

Trong khoảng thời gian tắt tín hiệu này, tổ chức ***Gilded Weaver*** (?) cũng đang tiến hành  trinh sát một hệ thống cáp quang ngầm đi qua bồn địa này.

Do không có ảnh vệ tinh hỗ trợ, ta phải dựa vào lịch sử vị trí *AIS*, nhật ký radar *SAR* và cơ sở dữ liệu cáp ngầm để xác định:
- Tàu thứ hai tham gia chuyển tải.
- Tên hệ thống cáp bị ảnh hưởng.
- Tọa độ chính xác của cuộc gặp.

## Phân tích manh mối

![](attachment/Pasted%20image%2020260521183206.png)

Theo báo cáo bất thường (*TARGET VESSEL AIS GAP REPORT*), tàu mục tiêu là
***MV STORMRIDER*** (*IMO* `7512098`).

Ghi nhận mất tín hiệu từ ngày `2026-03-05 19:42 UTC` tại tọa độ `42.7841 N, 18.2210 E`, bật lại lúc `2026-03-08 18:51 UTC` tại tọa độ `40.5012 N, 14.8550 E`.

Mớn nước tăng thêm tới ~3m chứng tỏ tàu đã nhận thêm hàng khi tắt *AIS*.

![](attachment/Pasted%20image%2020260521183144.png)

Tiếp tục đọc cảnh báo an ninh hàng hải (*MARITIME DOMAIN AWARENESS ALERT* - ID: `MDA-2026-0307-0042`), hệ thống điều khiển và radar *SAR* đã phát hiện ra một cụm hai thân tàu (*two-hull cluster*) áp sát nhau nằm trong vùng trôi dạt dự tính của tàu *STORMRIDER*.

Để ý thời điểm cảnh báo `2026-03-07 02:15 UTC` nằm trong *AIS gap* của tàu mục tiêu. Ta đi kiểm tra các log liên quan.

## So khớp dữ liệu

Mở `Maritime Tracker`, lọc khu vực *Adric Basin*.

Trong danh sách tàu, *MV STORMRIDER* được đánh dấu *AIS GAP*, ngoài ra còn có *MV BLACKWATER PRIDE* cũng có trạng thái bất thường.

![](attachment/Pasted%20image%2020260518235732.png)

Ta mở `SAR Detection Log`, đối chiếu được rằng 2 tàu bị đánh dấu ở trên chính là 2 tàu ta cần báo cáo.

![](attachment/Pasted%20image%2020260521185412.png)

Ngoài ra, cờ tàu cho biết quốc gia nơi tàu được đăng ký và chịu quản lý pháp lý. Tra cứu trong `Vessel Registry` cho thấy *MV BLACKWATER PRIDE* được đổi cờ nhiều lần trong thời gian ngắn.

Đổi cờ nhiều lần là cách để né quy định, né trừng phạt, che chủ sở hữu, hoặc làm mờ lịch sử hoạt động của tàu.

![](attachment/Pasted%20image%2020260521185557.png)

Điều này ám chỉ rằng con tàu có hoạt động mờ ám (*dark fleet*).

## Tổng hợp

Đến đây, ta đã tìm được tàu *MV STORMRIDER* & *MV BLACKWATER PRIDE* là 2 tàu thực hiện *STS Transfer*.

Lấy vĩ độ (*LAT*), kinh độ (*LON*) tại `SAR Log` đem vào `Cable Database` tra cứu ta có được tên hệ thống cáp.

![](attachment/Pasted%20image%2020260521190732.png)

## Flag

![](attachment/Pasted%20image%2020260518235638.png)

`HTB{9512098_9765432_VARDA-SUBLINK_42.1234_18.5678}`

---
# BLACKOUT ARCHITECT

![](attachment/Pasted%20image%2020260519001550.png)

Chuyên án 05 là mắt xích cuối của chuỗi điều tra. Ta điểm lại

![](attachment/Pasted%20image%2020260519001510.png)

![](attachment/Pasted%20image%2020260519001521.png)
![](attachment/Pasted%20image%2020260519001528.png)

![](attachment/Pasted%20image%2020260519001823.png)
![](attachment/Pasted%20image%2020260519001834.png)


![](attachment/Pasted%20image%2020260519001654.png)

![](attachment/Pasted%20image%2020260519001710.png)

![](attachment/Pasted%20image%2020260519001735.png)

![](attachment/Pasted%20image%2020260519001749.png)

![](attachment/Pasted%20image%2020260519001802.png)

![](attachment/Pasted%20image%2020260519001914.png)

![](attachment/Pasted%20image%2020260519002141.png)


![](attachment/Pasted%20image%2020260519002051.png)

![](attachment/Pasted%20image%2020260519002105.png)

## Flag

`HTB{CDR-9988-VST_TRUSTED-GRID-SOLUTIONS-LLC}`

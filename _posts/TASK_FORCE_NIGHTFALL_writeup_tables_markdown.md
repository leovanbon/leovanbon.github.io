TASK FORCE NIGHTFALL
Write-up OSINT - ANALYST-7

Các challenge OSINT trong giải này cho ta nhập vai vào điều tra viên ANALYST-7 của biệt đội NIGHTFALL.
Mỗi instance cấp cho ta một máy remote có đủ cơ sở dữ liệu cần thiết. Việc của ta là đọc briefing, lọc dấu hiệu liên quan, đối chiếu giữa các nguồn rồi nhập kết quả vào flag holder.
Dưới đây là write-up cho 5 challenges, tương ứng 5 case của ANALYST-7. Các phần sau giữ cùng mạch xử lý: tóm tắt vụ việc, bóc manh mối, so khớp dữ liệu, tổng hợp thông tin và chốt flag.
Trivia - bộ từ khóa dùng xuyên suốt

| Thuật ngữ   | Giải thích nhanh                                                                                                    |
| ----------- | ------------------------------------------------------------------------------------------------------------------- |
| OSINT       | Open-source intelligence: thu thập và phân tích thông tin từ nguồn mở hoặc từ các cơ sở dữ liệu được cấp trong bài. |
| Flag holder | Ô nhập kết quả cuối cùng của challenge. Định dạng flag thường được briefing cho sẵn.                                |
| Instance    | Môi trường máy/ứng dụng riêng cho người chơi, chứa database, tracker và các công cụ điều tra của case.              |

# FIRST LIGHT - BÌNH MINH
Chuyên án 01, ta được cấp Aviation Database và Aviation Tracker. Đầu tiên, ta mở Case Briefing để nắm nhiệm vụ.
## Tóm tắt vụ việc
48h trước cuộc bầu cử, một chiếc máy bay vận tải An-26 mang dấu hiệu của Korvia được một người đam mê hàng không dân dụng nhìn thấy khi đang cất cánh tại một sân bay không được đánh dấu ở phía Đông Korvia.
Phòng Hàng không cần ba thông tin nhận dạng cơ bản: số hiệu đăng ký, đơn vị vận hành và mã ICAO của sân bay đích.
## Các manh mối chính
Nguồn dữ liệu đến từ database dân sự.
Loại máy bay: Antonov An-26.
Partial reg: UR-???7.
Vị trí: phía Đông Korvia, trong FIR LKKR.
Thời điểm: 2026-03-14 06:12 UTC.
Trạng thái: bay về phía Tây, đang lấy thêm độ cao qua khoảng 3000 ft.
Ghi chú: động cơ nóng, vừa mới khởi hành; không nộp kế hoạch bay tại địa phương.
## So khớp
Mở Aviation Database, lọc loại phi cơ Antonov An-26. Trong danh sách thu được, chiếc UR-CKL7 là bản ghi khớp với partial registration UR-???7, loại máy bay An-26 và khu vực hoạt động trong FIR LKKR.
Tiếp tục thẩm định bằng Aviation Tracker, ta kiểm tra position pings tại đúng timestamp 2026-03-14 06:12 UTC. Độ cao, hướng bay và trạng thái climb đều khớp với báo cáo hiện trường. Vì máy bay vừa rời đường băng không lâu trước đó, ghi chú “engines hot, recent departure” cũng hợp lý.
## Tổng hợp thông tin
Registration: UR-CKL7.
Operator: KORVIAN AIRLIFT.
Destination ICAO: LKKB.
Flag

| HTB{UR-CKL7_KORVIAN-AIRLIFT_LKKB} |
| --- |

Trivia - hàng không - Case 01

| Thuật ngữ          | Giải thích nhanh                                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| Registration / reg | Số đăng ký của máy bay, tương tự biển số. Mỗi quốc gia có prefix riêng; ở bài này manh mối là UR-???7.                               |
| Operator           | Đơn vị vận hành thực tế của máy bay. Operator không nhất thiết trùng với chủ sở hữu pháp lý.                                         |
| ICAO airport code  | Mã 4 ký tự do ICAO dùng cho sân bay/điểm bay. Khác với mã IATA 3 ký tự hay dùng cho hành khách.                                      |
| FIR                | Flight Information Region - vùng thông báo bay, nơi một cơ quan kiểm soát không lưu chịu trách nhiệm cung cấp dịch vụ thông tin bay. |
| Heading / HDG      | Hướng mũi máy bay tính theo độ, 0/360 là Bắc, 90 là Đông, 180 là Nam, 270 là Tây.                                                    |

# QUIET WAKE - ĐÊM THỨC TỈNH
Chuyên án 02, ta được cấp Maritime Tracker và Vessel Register.
## Tóm tắt vụ việc
Một tàu chở hàng tổng hợp treo cờ Panama gần đây thực hiện nhiều chuyến ghé cảng không theo lịch trình tại Cảng Vargstad. Đây là cảng có mạng lưới hệ thống điều khiển công nghiệp logistics bị nghi ngờ đã bị Phe Rust cài cắm vị trí từ trước.
Ta có một phần mã MMSI từ tín hiệu vô tuyến bị chặn và một báo cáo quan sát từ camera nhiệt. Yêu cầu là xác định số IMO đầy đủ, chủ sở hữu hưởng lợi thực tế và ngày cập cảng Vargstad gần đây nhất.
## Tìm kiếm hàng hải
Từ radio intercept, ta có mảnh MMSI dạng 352****, tàu treo cờ Panama và đang hướng về Vargstad. Từ báo cáo camera nhiệt, tên tàu bắt đầu bằng chữ N, loại tàu là general cargo, LOA khoảng 120 m và có một cần cẩu đơn phía trước.
Xem qua danh sách tàu trong Maritime Tracker, sau khi lọc theo các dấu hiệu trên thì còn hai ứng cử viên đáng chú ý: MV NORDLYS TRADER và MV NEPTUNE STAR.
Kiểm tra Port Call History cho từng tàu, MV NORDLYS TRADER có bản ghi tới Vargstad. Hướng di chuyển trong AIS positions cũng khớp với hướng tiếp cận từ báo cáo camera nhiệt. Vì vậy ta chọn MV NORDLYS TRADER, IMO 9678234.
## Tổng hợp thông tin
Sử dụng Vessel Registry với số IMO 9678234, ta tìm được beneficial owner là NYRDEN HOLDINGS S.A. Port Call History cho biết lần cập Vargstad gần nhất là 2026-03-09.
Vessel: MV NORDLYS TRADER.
IMO: 9678234.
Beneficial owner: NYRDEN HOLDINGS S.A.
Most recent Vargstad arrival: 2026-03-09.
Flag

| HTB{9678234_NYRDEN-HOLDINGS-SA_2026-03-09} |
| --- |

Trivia - hàng hải - Case 02

| Thuật ngữ        | Giải thích nhanh                                                                                                  |
| ---------------- | ----------------------------------------------------------------------------------------------------------------- |
| IMO number       | Mã nhận dạng vĩnh viễn của tàu biển do IMO quản lý. Tàu đổi tên, đổi chủ hoặc đổi cờ thì IMO vẫn giữ nguyên.      |
| MMSI             | Maritime Mobile Service Identity - mã 9 chữ số dùng trong liên lạc vô tuyến/AIS để nhận diện trạm tàu.            |
| AIS              | Automatic Identification System - hệ thống phát vị trí, hướng, tốc độ và danh tính tàu cho an toàn hàng hải.      |
| Flag state       | Quốc gia mà tàu đăng ký treo cờ. Flag state khác với chủ sở hữu thực tế.                                          |
| Beneficial owner | Chủ hưởng lợi thực tế đứng sau các lớp công ty đăng ký, quan trọng khi điều tra shell company hoặc né trừng phạt. |
| Port call        | Một lần tàu ghé/cập cảng. Port Call History thường có ngày đến, ngày rời và mục đích cập cảng.                    |

# PHANTOM ECHO - BÓNG MA
Chuyên án 03 quay lại mảng hàng không. Lần này ta không chỉ tìm một chiếc máy bay, mà phải chứng minh một tín hiệu ADS-B bị giả mạo.
## Tóm tắt vụ việc
ADS-B Exchange bắt được một chuyến bay phát squawk thương mại thông thường, bay thấp qua cụm trạm biến áp Vestmark. Kế hoạch bay khai báo đây là chuyến “regional positioning, empty leg”. Tuy nhiên SIGINT cho biết chiếc máy bay có số đăng ký trùng với chuyến bay này đang nằm trên mặt đất ở một vị trí cách đó khoảng 600 km vào cùng thời điểm.
Nhiệm vụ gồm ba phần: xác nhận spoof bằng dữ liệu vật lý và thời tiết, giải mã fragment D9 để tìm ICAO24 thật, rồi xác định operator thực sự.
## Bóc manh mối
ADS-B summary ghi callsign KOR1337, ICAO24 khai báo 481A22, loại A320, altitude 1,800 ft AGL, ground speed khoảng 320 kts.
Track đi qua cụm trạm biến áp Vestmark trong khung 2026-03-12 23:14-23:32 UTC.
METAR tại VST lúc 23:00Z báo gió 240/45 gust 56 kts, tầm nhìn thấp, bão tuyết thổi, sương đóng băng, mountain wave activity và turbulence nặng.
Leaked D9 internal fragment nêu block 481A bị phân bổ giữa các dải SW/SI Mode-S, có cover dùng cho NORDIC201, còn true asset dùng chuỗi XOR với key 0x37.
## Xác nhận spoof bằng vật lý và thời tiết
Trong Aviation Tracker, dải position pings của KOR1337 gần như phẳng ở 1,800 ft AGL trong 18 phút, ground speed quanh 320 kts. Với địa hình hành lang có đỉnh vượt 6,000 ft AMSL, một A320 bay thương mại ở độ cao này là phi lý.
Đối chiếu Weather Archive tại VST, điều kiện thời tiết lúc đó cũng chống lại hoạt động bay thấp: gió giật mạnh, tầm nhìn 1,200 m, bão tuyết thổi, sương đóng băng và nhiễu động nặng. Ghi chú METAR còn nói không có commercial traffic trong hành lang. Như vậy track này không phải chuyến bay thật mà là tín hiệu ADS-B synthetic injection.
## Giải mã ICAO24 thật
Briefing cho fragment D9: SPOOF hex là NOR-07C201, cần XOR để lấy true asset. Trong Mode-S Decoder, ta lấy phần hex 7C2D62 và XOR với key 37. Kết quả trả về là 4B1A55.

| 0x7C2D62 XOR 0x37 = 0x4B1A55 |
| --- |

Tra cứu allocation cho 4B1A55 cho thấy đây là mã thuộc block phù hợp với true asset, không phải ICAO24 481A22 đã bị phát giả trên ADS-B.
## Xác định operator
Leaked D9 fragment ghi rõ operator block là D9-SIGINT-WING. Khi ghép với callsign spoofed KOR1337 và real ICAO24 4B1A55, ta có đủ ba trường của flag.
Spoofed callsign: KOR1337.
Claimed ICAO24: 481A22.
Real ICAO24: 4B1A55.
True operator: D9-SIGINT-WING.
Flag

| HTB{KOR1337_4B1A55_D9-SIGINT-WING} |
| --- |

Trivia - hàng không - Case 03

| Thuật ngữ               | Giải thích nhanh                                                                                                                                                                              |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ADS-B                   | Automatic Dependent Surveillance-Broadcast - máy bay tự phát vị trí, độ cao, vận tốc và định danh. Vì phụ thuộc vào tín hiệu phát ra, ADS-B có thể bị giả mạo nếu không được kiểm chứng chéo. |
| ICAO24 / Mode-S address | Mã định danh 24-bit gắn với transponder Mode-S của máy bay. Trong bài, 481A22 là mã bị mạo danh, 4B1A55 là mã thật sau khi giải XOR.                                                          |
| Squawk                  | Mã 4 chữ số phi công đặt trên transponder để ATC nhận diện/chỉ trạng thái chuyến bay.                                                                                                         |
| AGL vs AMSL             | AGL là độ cao so với mặt đất bên dưới; AMSL là độ cao so với mực nước biển trung bình. Đọc sai hai hệ quy chiếu này rất dễ dẫn đến kết luận sai.                                              |
| METAR                   | Bản tin thời tiết sân bay theo chuẩn hàng không, gồm gió, tầm nhìn, mây, hiện tượng thời tiết và ghi chú vận hành.                                                                            |
| Empty leg               | Chặng bay không chở khách/hàng để reposition máy bay. Đây là vỏ bọc hợp lý nhưng vẫn phải khớp dữ liệu vật lý và thời tiết.                                                                   |

# DARK LANE
Chuyên án 04 chuyển sang chuỗi hàng hải tối: một tàu tanker LR2 biến mất khỏi AIS trong thời gian dài, sau đó xuất hiện lại với draft thay đổi bất thường.
## Tóm tắt vụ việc
MV STORMRIDER tắt AIS 71 giờ trong Adriac Basin. Khi bật lại, tàu ở cách vị trí cũ khoảng 480 hải lý và có draft khác rõ rệt. Drone không thể ghi hình, nên ta phải dựa vào AIS history, SAR detection log và cable database để xác định tàu liên quan, hệ thống cáp bị ảnh hưởng và tọa độ chuyển giao.
## Xác định tàu chính
Trong Maritime Tracker, MV STORMRIDER có AIS gap đúng khung báo cáo: last ping 2026-03-05 19:42 UTC, AIS resume 2026-03-08 18:51 UTC, gap duration 71.15h. Registry xác nhận STORMRIDER là LR2 tanker, IMO 9512098, owner STORMRIDER SHIPPING LTD, manager MONTASE MARITIME MGT.
## Tìm tàu rendezvous
Maritime Domain Awareness Alert cho biết có một dark-fleet rendezvous, SAR phát hiện hai vỏ tàu trong footprint của STORMRIDER. Trong tracker cùng giai đoạn, MV BLACKWATER PRIDE cũng có AIS gap, last ping 2026-03-07 02:00 UTC và AIS resume 2026-03-07 08:00 UTC. Đây là ứng viên khớp nhất với việc tiếp cận STORMRIDER khi cả hai cùng hạn chế phát AIS.
Vessel Registry cho BLACKWATER PRIDE ghi IMO 9765432, LR2 tanker, owner BLACKWATER MARITIME SA, manager OFFSHORE VESSEL MGT. Flag history có nhiều lần đổi cờ trong 18 tháng, đúng dấu hiệu dark-fleet indicator.
## Tọa độ chuyển giao và cáp bị ảnh hưởng
Mở SAR Detection Log, bản ghi đáng chú ý là SAR-2026-107-4: hull count 2, centroid 42.1234 / 18.5678, ghi chú “STS transfer pattern - both hulls drifting together”. Bản ghi này gắn với MV STORMRIDER và MV BLACKWATER PRIDE.
Dùng tọa độ 42.1234, 18.5678 tra trong Cable Database, kết quả trả về tuyến VARDA-SUBLINK, vận hành bởi ARDIC NETWORKS LTD, nối Port Varda với Port Dransa. Khoảng cách nearest waypoint là 0.0000°, nên đây là hệ thống cáp đi qua đúng điểm chuyển giao.
LR2 tanker chính: MV STORMRIDER - IMO 9512098.
Tàu rendezvous: MV BLACKWATER PRIDE - IMO 9765432.
Affected cable system: VARDA-SUBLINK.
Transfer coordinates: 42.1234, 18.5678.
Flag

| HTB{9512098_9765432_VARDA-SUBLINK_42.1234_18.5678} |
| --- |

Trivia - hàng hải - Case 04

| Thuật ngữ | Giải thích nhanh |
| --- | --- |
| AIS gap / going dark | Khoảng thời gian tàu không phát AIS. Có thể do lỗi kỹ thuật, mất sóng, hoặc cố ý tắt để che hoạt động. |
| Draft | Độ chìm của tàu dưới mặt nước. Draft thay đổi bất thường sau AIS gap có thể gợi ý bốc/dỡ hàng hoặc chuyển tải. |
| SAR | Synthetic Aperture Radar - radar vệ tinh có thể phát hiện tàu kể cả ban đêm hoặc mây che, hữu ích khi AIS bị tắt. |
| STS transfer | Ship-to-ship transfer - chuyển hàng giữa hai tàu trên biển, thường thấy với dầu/hóa chất và có thể bị lợi dụng để che nguồn gốc hàng. |
| LR2 tanker | Long Range 2 tanker - nhóm tàu chở dầu/sản phẩm dầu cỡ lớn, thường khoảng 80,000-120,000 DWT. |
| Subsea cable | Cáp biển truyền dữ liệu/điện dưới đáy biển. Hoạt động neo, kéo hoặc chuyển tải gần tuyến cáp có thể gây rủi ro an ninh hạ tầng. |

# BLACKOUT ARCHITECT
Chuyên án 05 gom các chuỗi đã điều tra trước đó lại thành một đường dây hậu cần: hàng không, hàng hải, cảng và nhà thầu ICS.
## Tóm tắt vụ việc
Đối thủ Gilded Weaver định kích hoạt cascade hạ tầng trong đêm bầu cử thông qua phần cứng được đưa vào Vestmark. Ta cần tìm vendor ICS đã được phê duyệt nhận thiết bị tại trạm biến áp và tìm contract number trong procurement file. Contract number chính là kill-switch để hành động.
Workflow hint yêu cầu đọc Dossier, xem Procurement Memo với 4 vendor, đối chiếu qua Corporate Registry để tìm vendor có cấu trúc sở hữu đúng: chủ hưởng lợi thật nằm sâu 2 lớp và liên quan OFAC/Korvia.
## Lần theo chuỗi logistics
Dossier TFN-F-2026-0314 cho biết máy bay An-26 UR-CKL7 của KORVIAN AIRLIFT rời Eastern Korvia Airfield, thả pallet tại điểm rendezvous hàng hải 42.741N, 18.210E. Hàng sau đó được nhận bởi MV STORMRIDER, chuyển sang MV BLACKWATER PRIDE, rồi cuối cùng được đưa lên MV NORDLYS TRADER.
MV NORDLYS TRADER chở container KORV148221 tới Port Vargstad ngày 2026-03-09. Bill of Lading xác nhận consignee là Vestmark Grid Operating Company, hàng được release cho “authorized ICS service vendor” theo standing contract. Manifest khai báo là industrial control PLC modules - spares.
## Đọc Procurement Memo
Procurement Memo VGOC-PROC-FY26-0114 liệt kê 4 vendor ICS được giữ lại cho field-service work:
APEX CONTROL ENGINEERING - contract APX-1107-VST.
NORDIC OPERATIONS PARTNERS - contract NOP-25-VST.
TRUSTED GRID SOLUTIONS LLC - contract CDR-998-VST.
CIVIC POWER MAINTENANCE CO. - contract CPM-3318-VST.
Chỉ một vendor có ownership pattern trùng chỉ báo trong Dossier, nên ta kiểm từng ứng viên trong Corporate Registry thay vì đoán theo tên.
## Đối chiếu Corporate Registry
Với TRUSTED GRID SOLUTIONS LLC, registry cho biết công ty có parent là MERIDIAN INDUSTRIAL HOLDINGS tại Marshall Islands. Trong phần linked entities, MERIDIAN INDUSTRIAL HOLDINGS lại có ultimate beneficial owner là VICTOR KOSEV, bị đánh dấu SDN-listed và liên quan Korvia năm 2024. Đây đúng pattern “shell ownership 2 layers deep + OFAC SDN beneficial owner + Korvian-linked”.
Các vendor còn lại hoặc độc lập, hoặc không có lớp sở hữu và chỉ báo trừng phạt phù hợp. Vì vậy vendor cần báo cáo là TRUSTED GRID SOLUTIONS LLC, contract number CDR-998-VST.
Container: KORV148221.
Procurement memo: VGOC-PROC-FY26-0114.
Vendor: TRUSTED GRID SOLUTIONS LLC.
Parent: MERIDIAN INDUSTRIAL HOLDINGS.
Ultimate beneficial owner: VICTOR KOSEV - SDN-listed, Korvian-linked.
Contract number: CDR-998-VST.
Flag

| HTB{CDR-998-VST_TRUSTED-GRID-SOLUTIONS-LLC} |
| --- |

Trivia - logistics, cảng và ICS - Case 05

| Thuật ngữ | Giải thích nhanh |
| --- | --- |
| ICS | Industrial Control System - hệ thống điều khiển công nghiệp dùng trong điện, cảng, logistics, nước, dầu khí. Tấn công ICS có thể gây tác động vật lý. |
| PLC | Programmable Logic Controller - bộ điều khiển lập trình được, thường điều khiển thiết bị công nghiệp tại hiện trường. |
| Bill of Lading | Vận đơn đường biển: chứng từ ghi container, tàu, người nhận hàng, manifest và điều kiện release. |
| Consignee | Bên nhận hàng trên vận đơn. Không nhất thiết là người cuối cùng sử dụng hàng. |
| UN/LOCODE | Mã địa điểm logistics/cảng do Liên Hợp Quốc quản lý. Trong bài, Vargstad có UN/LOCODE KO VST. |
| Standing contract | Hợp đồng dịch vụ đang có hiệu lực, cho phép vendor nhận hàng hoặc thực hiện công việc mà không cần phê duyệt từng lần. |
| OFAC SDN | Danh sách Specially Designated Nationals của OFAC. Việc một UBO nằm trong danh sách này là chỉ báo rủi ro trừng phạt rất mạnh. |

# TỔNG KẾT FLAG

| Case | Mục tiêu | Flag |
| --- | --- | --- |
| 01 - First Light | Máy bay An-26 Korvia | HTB{UR-CKL7_KORVIAN-AIRLIFT_LKKB} |
| 02 - Quiet Wake | Tàu hàng Panama tới Vargstad | HTB{9678234_NYRDEN-HOLDINGS-SA_2026-03-09} |
| 03 - Phantom Echo | ADS-B spoof qua Vestmark | HTB{KOR1337_4B1A55_D9-SIGINT-WING} |
| 04 - Dark Lane | Dark fleet rendezvous và tuyến cáp | HTB{9512098_9765432_VARDA-SUBLINK_42.1234_18.5678} |
| 05 - Blackout Architect | Vendor ICS và contract kill-switch | HTB{CDR-998-VST_TRUSTED-GRID-SOLUTIONS-LLC} |

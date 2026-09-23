# VulnShop — Quy trình DevSecOps năm tầng, tích hợp kiểm thử SAST và DAST

> ## ⚠️ CẢNH BÁO
> Đây là **ứng dụng cố ý chứa lỗ hổng**, viết cho mục đích học tập, tương tự
> WebGoat hay DVWA. Nó chỉ dùng để chạy trên `localhost` trong môi trường lab.
>
> **Không triển khai lên Internet. Không dùng lại bất kỳ đoạn mã nào trong
> `Controllers/ProductController.cs` vào sản phẩm thật.** Cơ sở dữ liệu SQLite
> được tạo lại mỗi lần khởi động và chỉ chứa dữ liệu giả.

Đồ án môn học **An toàn Web và Cơ sở dữ liệu** — Trường Đại học Kinh tế – Tài chính TP.HCM (UEF).

---

## Vấn đề

SAST chỉ ra được dòng code sinh lỗi nhưng sinh nhiều cảnh báo sai. DAST cho bằng
chứng khai thác thật nhưng không biết lỗi nằm ở đâu trong mã nguồn, và quét mù thì
tốn thời gian theo số endpoint.

Đồ án dùng **kết quả SAST để quyết định DAST quét cái gì**, thay vì để hai công cụ
quét độc lập rồi đối chiếu kết quả về sau.

Nhưng cả hai họ công cụ này chỉ nhìn thấy *mã nguồn ứng dụng*. Sản phẩm giao cho
người dùng còn gồm thư viện bên thứ ba, container image với hàng trăm gói hệ điều
hành, và tệp cấu hình triển khai — phần thường chứa nhiều lỗ hổng hơn chính mã do
lập trình viên viết. Vì vậy quy trình có **năm tầng**, không phải hai.

## Năm tầng

Xếp theo **chi phí tăng dần** — tầng rẻ nhất thất bại trước. Không có lý do gì
phải build cả ứng dụng và khởi động ZAP nếu Semgrep đã báo SQL injection ở bước
trước đó.

| Tầng | Công cụ | Đối tượng | Kết quả | ~Thời gian |
|---|---|---|---|---|
| 0. Secret | Gitleaks | nội dung tệp | khoá, mật khẩu lọt vào mã nguồn | 10s |
| 1. Thư viện | `tools/sca.py` | gói NuGet | **CVE** | 15s |
| 2. Mã nguồn | Semgrep | C#, Razor | **CWE** | 40s |
| 3. Hạ tầng | Trivy | image, Dockerfile | **CVE** + lỗi cấu hình | 90s |
| 4. Đối sánh | `tools/correlate.py` + ZAP | ứng dụng đang chạy | **ba nhãn** | 130s |

**CWE ≠ CVE.** CWE là một *lớp* điểm yếu trong cách viết mã — mã bạn viết chỉ có
thể mắc CWE, không bao giờ có CVE. CVE là một lỗ hổng *cụ thể* trong một phần mềm
*cụ thể* đã công bố; không rule SAST nào phát hiện được, vì lỗi nằm bên trong thư
viện chứ không nằm trong cách bạn gọi nó. Đó là lý do phải có cả tầng 1 và tầng 3.

## Cơ chế ba nhãn

Điểm khác biệt chính so với cách gắn nhãn nhị phân thông thường. Nhãn được quyết
định bởi **loại bằng chứng**, không phải bởi kết quả quét:

| Nhãn | Bằng chứng cần có | Hành động của pipeline |
|---|---|---|
| `CONFIRMED` | Bằng chứng **động**: ZAP khai thác thành công tại đúng (URL, tham số) | Chặn build, gửi cảnh báo |
| `FILTERED` | Bằng chứng **tĩnh**: rule phát hiện sanitizer chứng minh dữ liệu đã bị vô hiệu hóa | Ghi phụ lục, đánh dấu suppressed |
| `UNCONFIRMED` | Không có bằng chứng nào thuộc hai loại trên | Cảnh báo, chờ review thủ công |

Nguyên tắc: **im lặng không phải là bằng chứng**. Việc DAST không khai thác được
không chứng minh mã nguồn an toàn — nó chỉ chứng minh DAST không khai thác được.
Gộp trường hợp này vào "dương tính giả" là cách nhanh nhất để âm thầm loại bỏ lỗ
hổng có thật.

`UNCONFIRMED` là nhãn **mặc định** — không phải một phán quyết mà là sự vắng mặt
của phán quyết. Khi nghi ngờ thì rơi về `UNCONFIRMED`, không rơi về `FILTERED`.

## Bốn cổng cưỡng chế

Quy trình DevSecOps không phải một công cụ hay một pipeline. Nó là một **tập kiểm
soát đặt ở các điểm trong vòng đời phần mềm**, mỗi cái có chính sách riêng về việc
chặn hay chỉ cảnh báo.

| Cổng | Kích hoạt | Chạy tầng nào | Chặn được gì |
|---|---|---|---|
| 1. IDE | lúc gõ code | — (ngoài phạm vi) | không |
| 2. **pre-commit** | `git commit` | SAST, chỉ tệp đang commit | chặn commit — `--no-verify` bỏ qua được |
| 3. **CI / Pull Request** | `git push`, mở PR | **cả 5 tầng** | **chặn merge — không bỏ qua được** |
| 4. **Quét định kỳ** | lịch hằng tuần | SCA + hạ tầng | không chặn, mở issue |

Cổng 2 *cố ý* cho phép bỏ qua: một cổng chặn trên máy cá nhân mà không bỏ qua được
thì người dùng sẽ gỡ hẳn nó ra.

Cổng 4 tồn tại vì ba cổng đầu đều kích hoạt bởi *một thay đổi mã nguồn*, nên cả ba
mù với cùng một loại rủi ro: **mã nguồn đứng yên nhưng thế giới thì không.** Repo
không đổi từ tháng Một, tháng Ba có người công bố CVE cho thư viện đang dùng —
không commit nào xảy ra, không lần chạy nào được kích hoạt, và không ai biết.

## Kết quả thực nghiệm

### Bộ dữ liệu 1 — VulnShop (đo tính đúng đắn)

6 ca gieo lỗi có chủ đích, ground truth chốt trước khi chạy (`ground_truth.csv`).

| Chỉ số | Giá trị |
|---|---|
| Độ chính xác ánh xạ (tệp, dòng) → (URL, tham số) | 6/6 |
| Precision trên nhãn CONFIRMED | 4/4 |
| Recall | 4/4 |
| Tỉ lệ phân giải tự động | 100% |

So sánh ba nghiệm thức, cùng cấu hình scanner, mỗi lần một phiên ZAP mới:

| Nghiệm thức | Thời gian | URL bị quét | Lỗ hổng tìm được |
|---|---|---|---|
| B1 Quét mù | 474 s | 23 | **0 / 4** |
| B2 Biết endpoint | 198 s | 6 | 4 / 4 (7 alert thô) |
| B3 Có chủ đích | 132 s | 4 | 4 / 4 |

B1 tìm được 0 lỗ hổng không phải vì scanner yếu mà vì **giai đoạn thu thập**:
không trang nào có liên kết trỏ tới `/Product/Search?q=`. Đây là khác biệt *về
chất*, không phải về tốc độ — SAST cho biết endpoint **tồn tại**, điều mà việc bò
từ trang chủ không suy ra được.

B2 báo 7 alert cho 4 lỗ hổng, trong đó **1 là dương tính giả của chính DAST**:
`/Product/SafeSearch` đã tham số hóa và an toàn có chứng minh, nhưng payload `'a%'`
làm tập kết quả `LIKE` thay đổi, và heuristic so sánh phản hồi của ZAP kết luận
nhầm. Ca này được gán `FILTERED` nhờ bằng chứng tĩnh **trước khi ZAP kịp được hỏi**
— thứ tự ưu tiên của lược đồ ba nhãn đã ngăn được một dương tính giả mà bản thân
DAST không tự nhận ra.

### Bộ dữ liệu 2 — eShopOnWeb (đo phạm vi áp dụng)

Ứng dụng tham chiếu ASP.NET Core của Microsoft. **Không có ground truth**, nên
không dùng để tính precision hay recall. Nó trả lời câu hỏi khác: công cụ này chạm
được tới bao nhiêu phần của một hệ thống thật.

| Tình trạng endpoint | Số lượng | Tỉ lệ |
|---|---|---|
| Kiểm thử động được ngay | 4 | 9% |
| Yêu cầu đăng nhập | 28 | 65% |
| Không phải GET | 6 | 14% |
| Không có tham số kiểu đơn giản | 5 | 12% |
| **Tổng** | **43** | 100% |

Trong 43 endpoint có 25 thuộc Controller và **18 thuộc Razor Pages**. Con số 9% là
một ranh giới áp dụng trung thực, không phải thất bại cần che giấu.

Tầng thư viện trên cùng dự án: **10 gói dính lỗ hổng** (1 Critical, 6 High,
3 Moderate), trong đó **8/10 là phụ thuộc gián tiếp** — thư viện của thư viện, lập
trình viên không chủ động chọn và không thấy trong `.csproj`.

## Chạy lại

Cần: .NET SDK 9, Docker, Python 3.10+.

### Cách nhanh nhất — giao diện web

```bash
pip install requests
python tools/webui.py          # tự mở http://localhost:8000
```

Dán đường dẫn thư mục mã nguồn, tùy chọn điền URL ứng dụng đang chạy để bật tầng
động, bấm Quét. Báo cáo hiện ngay trong trang.

### Từng bước bằng dòng lệnh

```bash
# 1. Chạy ứng dụng
dotnet run --launch-profile http          # lắng nghe 0.0.0.0:5000

# 2. Tầng 1 — thư viện
python tools/sca.py --repo . --out reports/sca.json

# 3. Tầng 2 — mã nguồn
mkdir -p reports
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep \
  semgrep scan --config semgrep-rules/sast-detect.yaml --exclude semgrep-rules \
  --sarif --output reports/semgrep.sarif --metrics=off
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep \
  semgrep scan --config semgrep-rules/sanitizer-check.yaml --exclude semgrep-rules \
  --sarif --output reports/sanitizers.sarif --metrics=off

# 4. Tầng 3 — hạ tầng (dựng cả 2 Dockerfile rồi so số CVE)
python tools/trivy.py --compare --config . --sbom .

# 5. Bản đồ endpoint + kiểm tra ánh xạ trước, chưa cần ZAP
python tools/gen_routes_map.py --root . --base-url http://localhost:5000
python tools/correlate.py --dry-run

# 6. OWASP ZAP
docker run -d --name zap -p 8090:8090 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8090 \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
  -config api.disablekey=true

# 7. Tầng 4 — đối sánh và gắn nhãn
pip install requests
python tools/correlate.py --zap http://localhost:8090 \
  --base-url http://host.docker.internal:5000 --scan-timeout 300

# 8. Dựng báo cáo
python tools/report.py --title "VulnShop" \
  --sca reports/sca.json --sast reports/semgrep.sarif \
  --routes routes_map.json --dast reports/findings.json \
  --trivy reports/trivy.json --out reports/bao_cao.html
```

Trên Linux, thay `host.docker.internal` bằng `localhost` và thêm `--network host`
cho container ZAP.

### Quét một repo ASP.NET bất kỳ

```bash
python tools/sca.py --repo /duong/dan/repo --out reports/sca_x.json
python tools/gen_routes_map.py --root /duong/dan/repo --out reports/routes_x.json
```

Tầng 2 dùng bộ rule cộng đồng thay vì rule cục bộ:
`--config=p/csharp`. Không có tệp sanitizer thì sẽ **không có nhãn `FILTERED`** —
đúng nguyên tắc: không có bằng chứng thì không kết luận.

### Cài cổng pre-commit

```bash
python tools/pre_commit_scan.py --install     # gỡ: --uninstall
```

Quét các tệp đang trong staging area, dưới 5 giây, chặn commit nếu có lỗi mức
`ERROR`. Đường thoát duy nhất là chú thích `// nosemgrep: <tên-rule>` ngay trên
dòng đó — **để lại dấu vết trong mã nguồn**, khác với `git commit --no-verify` là
bỏ qua âm thầm.

## Giới hạn

Các điểm dưới đây được xác định bằng thực nghiệm, không phải phỏng đoán.

1. **Độ phủ trong vòng đời DevSecOps**: đồ án phủ 6/13 kiểm soát, tập trung hoàn
   toàn vào giai đoạn Code–Build–Test. Mô hình hóa mối đe dọa, ký artifact, quản lý
   bí mật lúc chạy, giám sát thời gian chạy đều **nằm ngoài phạm vi**. Định vị
   trung thực: *một cổng cưỡng chế trong giai đoạn tích hợp liên tục.*
2. **Phạm vi khóa cứng của tầng động**: chỉ CWE-89 và CWE-79, chỉ phương thức GET,
   không xác thực. POST vướng anti-forgery token của ASP.NET.
3. **Mù với lỗi logic nghiệp vụ**: không tầng nào phát hiện được việc đổi `userId`
   trên URL để xem dữ liệu người khác, vì không rule nào biết giá trị đó *đáng lẽ*
   phải thuộc về ai.
4. **Semgrep không phân tích cú pháp Razor** (`.cshtml`), nên ca XSS trong view
   phải dùng chế độ `generic` khớp văn bản.
5. **ZAP 2.17.0 không có active scan rule cho SQLite** (chỉ có MySQL, Oracle,
   PostgreSQL, MsSQL, Hypersonic). Việc xác nhận dựa vào rule tổng quát 40018,
   vốn so sánh phản hồi nên không phụ thuộc DBMS.
6. **Giá trị mồi quyết định chất lượng xác nhận**: mồi khiến ứng dụng trả về trang
   lỗi hoặc trang rỗng sẽ phá hỏng phép so sánh phản hồi của DAST và làm lỗ hổng
   thật bị bỏ sót. Lỗi này đã xảy ra **hai lần dưới hai hình thức**, nên giá trị mồi
   giờ được chọn theo **kiểu dữ liệu** chứ không đoán theo tên tham số. Xem khóa
   `test_seed` trong `routes_map.json`.
7. **Bằng chứng tĩnh đè lên bằng chứng động**: nếu rule kiểm sanitizer viết sai, nó
   sẽ làm im một lỗ hổng thật. Đây là rủi ro cố hữu của kiến trúc.
8. **Trần độ phủ**: hệ thống không phát hiện lỗ hổng nằm ngoài tập Semgrep tìm
   thấy. Đánh đổi có chủ ý — đổi độ phủ lấy độ tin cậy của cảnh báo.
9. **Quy mô thực nghiệm nhỏ**: 6 ca trên ứng dụng do chính tác giả viết. Kết quả
   100% chứng minh pipeline chạy đúng thiết kế, không chứng minh hệ thống hoàn hảo.

## Định vị so với công trình liên quan

Kỹ thuật ánh xạ cảnh báo SAST sang endpoint không mới. Hybrid Analysis Mapping
(ThreadFix, được cấp bằng sáng chế 2018) và nhánh mã nguồn mở
[astam-correlator](https://github.com/secdec/astam-correlator) đã làm việc này,
kể cả cho ASP.NET.

Khác biệt nằm ở **chiều dữ liệu**: các công cụ đó hợp nhất hai tập kết quả *sau
khi* cả hai đã quét xong, nên DAST vẫn phải quét toàn bộ bề mặt ứng dụng. Ở đây
kết quả SAST là đầu vào quyết định phạm vi quét, nên chi phí quét động tỉ lệ với
số cảnh báo thay vì với số endpoint.

Trên thị trường, hướng kết hợp này gọi là **ASPM** (Snyk, Apiiro, ArmorCode). Bản
mạnh hơn là **IAST**, đặt agent bên trong ứng dụng đang chạy để quan sát trực tiếp
luồng dữ liệu chạm tới sink, thay vì suy ra từ bên ngoài theo kiểu hộp đen như ở đây.

## Cấu trúc thư mục

```
Controllers/ProductController.cs     6 ca gieo lỗi, đánh dấu C1..C6
Views/Product/                       view chứa ca XSS qua Html.Raw
Data/Db.cs                           khởi tạo SQLite với dữ liệu giả
Dockerfile                           bản ngây thơ — sdk làm runtime, chạy root
Dockerfile.hardened                  bản gia cố — multi-stage, non-root, healthcheck
ground_truth.csv                     bảng sự thật, chốt trước khi chạy

semgrep-rules/sast-detect.yaml       4 rule phát hiện (cố ý viết ngây thơ)
semgrep-rules/sanitizer-check.yaml   2 rule tìm bằng chứng tĩnh loại trừ

tools/gen_routes_map.py              bản đồ dòng code -> URL (Controller + Razor Pages)
tools/correlate.py                   engine tương quan, gắn ba nhãn, quality gate
tools/sca.py                         tầng thư viện — CVE trong gói NuGet
tools/trivy.py                       tầng hạ tầng — image, cấu hình, SBOM
tools/report.py                      dựng báo cáo HTML năm tầng
tools/webui.py                       giao diện vận hành cục bộ (chỉ thư viện chuẩn)
tools/pre_commit_scan.py             cổng pre-commit, cài/gỡ git hook
tools/benchmark.py                   chạy ba nghiệm thức B1, B2, B3
tools/notify.py                      gửi cảnh báo Telegram

.github/workflows/devsecops.yml      pipeline CI — 24 bước, 4 kích hoạt
```

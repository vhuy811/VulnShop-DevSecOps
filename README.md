# VulnShop — Quy trình DevSecOps tích hợp kiểm thử SAST và DAST

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

## Kiến trúc

```
git push
   └─> Gitleaks              quét secret
   └─> Semgrep               2 bộ rule: phát hiện + kiểm sanitizer, xuất SARIF
   └─> gen_routes_map.py     ánh xạ (tệp, dòng) -> (URL, tham số)
   └─> correlate.py          điều khiển OWASP ZAP, gắn ba nhãn
   └─> quality gate          fail build khi có CONFIRMED
   └─> SARIF + Telegram      Code Scanning và cảnh báo
```

## Kết quả thực nghiệm

Bộ dữ liệu gồm 6 ca gieo lỗi có chủ đích, ground truth chốt trước khi chạy
(xem `ground_truth.csv`).

| Chỉ số | Giá trị |
|---|---|
| Độ chính xác ánh xạ (tệp, dòng) → (URL, tham số) | 6/6 |
| Precision trên nhãn CONFIRMED | 4/4 |
| Recall | 4/4 |
| Tỉ lệ phân giải tự động | 100% |

Hai ca `SafeSearch` và `SafeGreet` bị Semgrep báo nhầm và được cơ chế tĩnh loại
trừ đúng — đó là phần mà DAST đơn lẻ không làm được.

## Chạy lại

Cần: .NET SDK 9, Docker, Python 3.10+.

```bash
# 1. Chạy ứng dụng
dotnet run --launch-profile http          # lắng nghe 0.0.0.0:5000

# 2. SAST
mkdir -p reports
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep \
  semgrep scan --config semgrep-rules/sast-detect.yaml --exclude semgrep-rules \
  --sarif --output reports/semgrep.sarif --metrics=off
docker run --rm -v "$PWD:/src" -w /src semgrep/semgrep \
  semgrep scan --config semgrep-rules/sanitizer-check.yaml --exclude semgrep-rules \
  --sarif --output reports/sanitizers.sarif --metrics=off

# 3. Kiểm tra ánh xạ trước, chưa cần ZAP
python tools/correlate.py --dry-run

# 4. OWASP ZAP
docker run -d --name zap -p 8090:8090 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8090 \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
  -config api.disablekey=true

# 5. Tương quan và gắn nhãn
pip install requests
python tools/correlate.py --zap http://localhost:8090 \
  --base-url http://host.docker.internal:5000 --scan-timeout 300
```

Trên Linux, thay `host.docker.internal` bằng `localhost` và thêm `--network host`
cho container ZAP.

## Giới hạn

Các điểm dưới đây được xác định bằng thực nghiệm trong quá trình làm đồ án, không
phải phỏng đoán:

1. **Phạm vi khóa cứng**: chỉ CWE-89 và CWE-79, chỉ phương thức GET, không xác
   thực. POST vướng anti-forgery token của ASP.NET.
2. **Semgrep không phân tích cú pháp Razor** (`.cshtml`), nên ca XSS trong view
   phải dùng chế độ `generic` khớp văn bản.
3. **ZAP 2.17.0 không có active scan rule cho SQLite** (chỉ có MySQL, Oracle,
   PostgreSQL, MsSQL, Hypersonic). Việc xác nhận dựa vào rule tổng quát 40018,
   vốn so sánh phản hồi nên không phụ thuộc DBMS.
4. **Giá trị mồi quyết định chất lượng xác nhận**: mồi khiến ứng dụng trả về trang
   lỗi hoặc trang rỗng sẽ phá hỏng phép so sánh phản hồi của DAST và làm lỗ hổng
   thật bị bỏ sót. Xem khóa `test_seed` trong `routes_map.json`.
5. **Trần độ phủ**: hệ thống không phát hiện lỗ hổng nằm ngoài tập Semgrep tìm
   thấy. Đây là đánh đổi có chủ ý — đổi độ phủ lấy độ tin cậy của cảnh báo.
6. **Quy mô thực nghiệm nhỏ**: 6 ca trên ứng dụng do chính nhóm viết. Kết quả
   100% chứng minh pipeline chạy đúng thiết kế, không phải chứng minh hệ thống
   hoàn hảo, và không suy rộng ra ứng dụng thật.

## Định vị so với công trình liên quan

Kỹ thuật ánh xạ cảnh báo SAST sang endpoint không mới. Hybrid Analysis Mapping
(ThreadFix, được cấp bằng sáng chế 2018) và nhánh mã nguồn mở
[astam-correlator](https://github.com/secdec/astam-correlator) đã làm việc này,
kể cả cho ASP.NET.

Khác biệt nằm ở **chiều dữ liệu**: các công cụ đó hợp nhất hai tập kết quả *sau
khi* cả hai đã quét xong, nên DAST vẫn phải quét toàn bộ bề mặt ứng dụng. Ở đây
kết quả SAST là đầu vào quyết định phạm vi quét, nên chi phí quét động tỉ lệ với
số cảnh báo thay vì với số endpoint.

## Cấu trúc thư mục

```
Controllers/ProductController.cs   6 ca gieo lỗi, đánh dấu C1..C6
Views/Product/                     view chứa ca XSS qua Html.Raw
Data/Db.cs                         khởi tạo SQLite với dữ liệu giả
semgrep-rules/sast-detect.yaml     rule phát hiện (cố ý viết ngây thơ)
semgrep-rules/sanitizer-check.yaml rule tìm bằng chứng tĩnh loại trừ
tools/gen_routes_map.py            sinh bản đồ dòng code -> URL
tools/correlate.py                 engine tương quan, gắn ba nhãn
tools/notify.py                    gửi cảnh báo Telegram
ground_truth.csv                   bảng sự thật, chốt trước khi chạy
.github/workflows/devsecops.yml    pipeline CI
```

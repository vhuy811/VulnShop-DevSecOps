# Quy trình DevSecOps — tích hợp kiểm thử SAST và DAST

Bộ công cụ quét bảo mật năm tầng cho dự án .NET, chạy được tại máy lập trình viên và trên GitHub Actions. Áp dụng cho **repo bất kỳ** — bộ công cụ đi theo pipeline, không cần sao chép vào từng dự án.

Điểm khác biệt so với việc ghép rời từng scanner: kết quả tĩnh và kết quả động được **đối sánh với nhau** để gán ba nhãn có bằng chứng, thay vì đổ ra một danh sách cảnh báo chưa ai kiểm chứng.

Đồ án môn học **An toàn Web và Cơ sở dữ liệu** — Trường Đại học Kinh tế – Tài chính TP.HCM (UEF).

---

## Nguyên tắc chi phối

> **Im lặng không phải là bằng chứng.**

Scanner không tìm thấy gì **không** đồng nghĩa với an toàn. Mọi cảnh báo mặc định mang nhãn `UNCONFIRMED` cho tới khi có bằng chứng theo một chiều cụ thể. Công cụ không bao giờ được phép trình bày "chưa kiểm tra được" như "đã kiểm tra và sạch".

Nguyên tắc này chi phối từng quyết định kỹ thuật trong repo: một tầng bị bỏ qua phải nói rõ lý do, một bước không chạy được phải ghi nhận là không có kết quả, và một tệp báo cáo thiếu không bao giờ được thay bằng số liệu của lần chạy trước.

---

## Ba nhãn

| Nhãn | Nghĩa | Bằng chứng |
|---|---|---|
| **CONFIRMED** | khai thác được trên ứng dụng đang chạy | DAST bắn payload thành công |
| **FILTERED** | có hàm khử độc nằm trên đúng luồng dữ liệu | rule sanitizer khớp tại dòng cụ thể |
| **UNCONFIRMED** | chưa có bằng chứng theo chiều nào | **không có** — đây là nợ kiểm thử |

`FILTERED` **không** có nghĩa là "đã sửa". Nó có nghĩa là tìm thấy bằng chứng tĩnh loại trừ.

Bằng chứng tĩnh được xét **trước** khi hỏi DAST. Một endpoint đã có sanitizer sẽ không tốn một payload nào — vừa đúng thứ tự logic, vừa làm kiểm thử động rẻ đi đủ để chạy được ở mỗi pull request.

---

## Năm tầng

| Tầng | Công cụ | Đầu vào | Đầu ra |
|---|---|---|---|
| 0 | Gitleaks | toàn bộ tệp | secret lộ trong mã nguồn |
| 1 | `sca.py` + dotnet | `*.csproj` | CVE trong gói NuGet |
| 2 | Semgrep + rule riêng | `*.cs`, `*.cshtml` | cảnh báo phân loại theo CWE |
| 3 | `gen_routes_map.py` | Controller, Razor Pages | bản đồ (URL, tham số) và **phạm vi phủ được** |
| 4 | Trivy | Dockerfile, manifest | lỗi cấu hình triển khai, SBOM, CVE trong image |
| 5 | `correlate.py` + OWASP ZAP | SARIF + bản đồ + app đang chạy | **ba nhãn kèm bằng chứng** |

Thứ tự xếp theo **chi phí tăng dần** để cái rẻ nhất thất bại trước. Không có lý do gì build cả ứng dụng nếu Semgrep đã báo SQL injection ở bước trước.

Tầng 3 không phải bước trung gian. Nó **đo và công bố giới hạn của chính công cụ**: bao nhiêu phần trăm endpoint kiểm thử động được, và phần còn lại vì sao không. Một bản đồ sai nguy hiểm hơn không có bản đồ.

---

## Bốn cổng kiểm soát

| Cổng | Kích hoạt | Ai bấm | Chặn gì |
|---|---|---|---|
| Hook pre-commit | `git commit` | tự động | commit không thành |
| CI trên mọi nhánh | `git push` | tự động | job đỏ |
| Branch protection | mở pull request | tự động | nút Merge xám |
| Quét định kỳ | 01:00 thứ Ba | tự động | CVE mới trên mã nguồn cũ |

Cổng thứ tư tồn tại vì ba cổng đầu đều bắt nguồn từ **một thay đổi mã nguồn**, nên chúng mù hoàn toàn với rủi ro ngược lại: mã nguồn đứng yên nhưng thế giới thì không. Không commit nào xảy ra, không lần chạy nào được kích hoạt, và không ai biết.

Cơ chế chặn là **mã thoát**. `correlate.py --fail-on-confirmed` trả về 1 khi có nhãn CONFIRMED, job đỏ, và branch protection biến "đỏ" thành "không merge được". Một công cụ chỉ in ra màn hình thì ai cũng có thể phớt lờ.

---

## Bắt đầu

### Cần có sẵn

Docker Desktop, Python 3.9+, Git. Thêm .NET SDK nếu quét dự án .NET.

```bash
git clone https://github.com/vhuy811/VulnShop-DevSecOps.git
cd VulnShop-DevSecOps
pip install requests
python kiem_tra_moi_truong.py
```

Lệnh cuối kiểm tra 9 điều kiện cùng lúc và in ra bảng kèm lệnh sửa cho từng mục còn thiếu.

### Áp cho một repo trên GitHub

Tạo `.github/workflows/bao-mat.yml` trong repo cần bảo vệ:

```yaml
name: Bao mat
on: [push, pull_request, workflow_dispatch]

# Bat buoc: workflow duoc goi xin security-events de day SARIF len Code
# Scanning. Thieu khoi nay thi lan chay bao "Startup failure" ngay lap tuc.
permissions:
  contents: read
  security-events: write

jobs:
  security:
    uses: vhuy811/VulnShop-DevSecOps/.github/workflows/devsecops-reusable.yml@main
    with:
      project-file: src/Web/Web.csproj
      run-dast: false
    secrets: inherit
```

Không sao chép `tools/`, không sao chép `semgrep-rules/` — pipeline tự kéo về lúc chạy.

Rồi vào Settings → Branches, thêm required check tên **`security / scan`**.

### Quét một thư mục tại máy

```bash
python tools/webui.py
```

Điền đường dẫn tới repo cần quét. Bộ rule đi theo công cụ chứ không theo repo đích, nên quét được thư mục bất kỳ.

Hướng dẫn thao tác đầy đủ nằm trong [`HUONG_DAN.md`](HUONG_DAN.md).

---

## Tham số của pipeline

| Tham số | Mặc định | Khi nào đổi |
|---|---|---|
| `project-file` | `''` | đường dẫn `.csproj`; để trống thì bỏ tầng 1 và 5 |
| `run-dast` | `true` | `false` khi app cần CSDL, không khởi động được trong CI |
| `health-path` | `/` | đường dẫn kiểm tra app đã sẵn sàng |
| `app-url` | `http://localhost:5000` | địa chỉ ZAP nhìn thấy |
| `fail-on-confirmed` | `true` | `false` để áp dụng dần ở repo có sẵn nợ kỹ thuật |
| `dockerfile` | `Dockerfile` | tên Dockerfile cho bước quét image |
| `run-image-scan` | `true` | `false` để tiết kiệm vài phút CI |
| `dotnet-version` | `9.0.x` | phiên bản SDK |
| `toolkit-ref` | `main` | ghim tag khi dùng thật |

`fail-on-confirmed: false` dành cho tình huống thực tế hay gặp: repo đã có lỗ hổng từ trước khi áp pipeline. Cổng quét toàn bộ ứng dụng mỗi lần, nên nếu chặn ngay thì không commit nào qua nổi. Đặt `false` để quét và báo cáo đầy đủ trước, trả nợ xong rồi mới bật lên `true`.

---

## Cấu trúc repo

```
tools/                  9 script Python, chỉ dùng thư viện chuẩn + requests
  sca.py                tầng 1 — đối chiếu NuGet với CSDL lỗ hổng
  gen_routes_map.py     tầng 3 — bản đồ endpoint, Controller và Razor Pages
  trivy.py              tầng 4 — cấu hình, SBOM, so sánh image trước/sau gia cố
  correlate.py          tầng 5 — đối sánh tĩnh × động, gán ba nhãn
  report.py             dựng báo cáo HTML
  webui.py              bảng điều khiển cục bộ
  pre_commit_scan.py    cài và chạy hook pre-commit
  notify.py             gửi kết quả lên Telegram
  benchmark.py          đo thời gian từng tầng

semgrep-rules/
  sast-detect.yaml      rule phát hiện — bắt dấu hiệu nguy hiểm
  sanitizer-check.yaml  rule kiểm sanitizer — bắt bằng chứng an toàn

.github/workflows/
  devsecops-reusable.yml  pipeline dùng chung, repo khác gọi tới
  devsecops.yml           repo này tự gọi pipeline của chính mình

vi-du-repo-khac.yml     mẫu dán vào repo khác
kiem_tra_moi_truong.py  chẩn đoán 9 điều kiện trong một lần chạy
HUONG_DAN.md            hướng dẫn thao tác từng bước
```

Hai bộ rule tồn tại vì chúng trả lời hai câu hỏi ngược nhau: một tìm dấu hiệu nguy hiểm, một tìm bằng chứng an toàn. Thiếu bộ thứ hai thì nhãn `FILTERED` không bao giờ xuất hiện, và một phần ba lược đồ ba nhãn biến mất.

---

## Giới hạn đã biết

Những điều dưới đây được đo và công bố, không phải giấu đi.

**Bộ rule là C#.** Repo ngôn ngữ khác thì tầng 1 và 2 không dùng được.

**Bộ rule không đầy đủ, và sẽ bỏ sót.** Bốn rule hiện tại bắt hai mẫu: nối chuỗi vào câu SQL, và in HTML không mã hoá. Nội suy chuỗi (`$"...{x}"`), `FromSqlRaw`, Dapper, và việc đổi tên biến đều thoát được. Các lớp CWE khác — command injection, path traversal, deserialization, SSRF, IDOR — không có rule nào phủ.

**Lược đồ ba nhãn không cứu được lỗ hổng chưa tìm thấy.** Nó bảo vệ chống lại cảnh báo *chưa được kiểm chứng*, chứ không chống được lỗ hổng *chưa được phát hiện*. Semgrep không báo thì `correlate.py` không có gì để hỏi ZAP, nên một lỗ hổng lọt ở tầng 2 sẽ không nhận nhãn `UNCONFIRMED` — nó đơn giản là không xuất hiện ở đâu cả.

**Tầng 5 chỉ chạy với ứng dụng tự chứa.** App cần SQL Server, Redis hay dịch vụ ngoài thì phải thêm service container vào CI, hoặc đặt `run-dast: false` và chấp nhận bốn tầng tĩnh.

**Tầng 5 chỉ phủ endpoint có tham số GET kiểu đơn giản.** Đo trên hai bộ dữ liệu: 43% với ứng dụng mẫu, 9% với eShopOnWeb của Microsoft. Chênh lệch đó là ranh giới áp dụng thật.

**Semgrep không phân tích cú pháp Razor.** Rule cho `.cshtml` chạy ở chế độ generic — khớp văn bản thuần — nên `Html.Raw` trong một dòng chú thích cũng bị báo.

**Hook pre-commit không đi theo git.** Nó nằm trong `.git/hooks/`, nên mỗi người trong nhóm phải tự cài trên máy mình. Chỉ có CI mới là cổng thật sự bắt buộc.

**Cổng quét toàn bộ ứng dụng, không phải phần diff.** Khác với Code Scanning của GitHub vốn chỉ soi phần thay đổi. Hai phạm vi này cho hai kết luận khác nhau trên cùng một pull request, và cả hai đều đúng theo phạm vi của mình.

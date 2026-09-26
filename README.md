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
git clone https://github.com/vhuy811/DevSecOps_VHNAT.git
cd DevSecOps_VHNAT
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
    uses: vhuy811/DevSecOps_VHNAT/.github/workflows/devsecops-reusable.yml@main
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
| `fail-on-unverified` | `true` | `false` để cho phép tắt tầng động mà vẫn xanh |
| `dockerfile` | `Dockerfile` | tên Dockerfile cho bước quét image |
| `run-image-scan` | `true` | `false` để tiết kiệm vài phút CI |
| `semgrep-packs` | `p/csharp p/security-audit` | thêm/bớt bộ rule cộng đồng; để trống `''` thì chỉ chạy rule của dự án |
| `dotnet-version` | `9.0.x` | phiên bản SDK |
| `toolkit-ref` | `main` | ghim tag khi dùng thật |

`fail-on-unverified` bịt một lỗ trong chính cơ chế cổng. Cổng chỉ nổ khi có nhãn `CONFIRMED`, mà `CONFIRMED` chỉ ra đời từ kiểm thử động. Nên nếu không có điều kiện thứ hai này, một dòng `run-dast: false` sẽ **tắt hẳn cổng**: không chạy DAST → không có CONFIRMED → job xanh → merge được tất. "Không kiểm tra được" đi qua y hệt "đã kiểm tra và sạch" — đúng cái lỗi mà cả quy trình này đặt ra để chống.

Điều kiện thứ hai chặn khi có cảnh báo tĩnh **ánh xạ được sang một endpoint có tham số, không có bằng chứng khử độc, và chưa lần nào được hỏi ZAP**. Đó là rủi ro đã biết mà chưa ai kiểm chứng — khác hẳn `UNCONFIRMED` chung chung, vốn gồm cả những endpoint không kiểm thử động được.

### Cổng chỉ chặn phần mới — baseline

Repo đã có lỗ hổng từ trước khi áp pipeline là tình huống thực tế hay gặp nhất, và là lý do số một khiến các đội tắt cổng sau một tuần: mọi PR đều đỏ vì lỗi của người khác viết từ năm ngoái, và cách duy nhất để làm việc tiếp là tắt hẳn cổng đi.

Pipeline xử lý bằng **baseline**: trên PR và push, Semgrep chạy thêm một lượt với `--baseline-commit <nhánh gốc>` để biết cảnh báo nào **mới** do lần thay đổi này đưa vào. Cổng chỉ chặn `CONFIRMED` mới. Nợ cũ vẫn được quét, vẫn hiện đầy đủ trong báo cáo với nhãn *nợ cũ*, chỉ không chặn merge của người không gây ra nó.

Hai quyết định thiết kế ở đây:

- **Baseline áp ở cổng, không áp ở lúc quét.** Dùng `--baseline-commit` ngay từ lượt quét chính thì nợ cũ biến mất khỏi báo cáo — lại là im lặng bị trình bày thành sạch. Nên có hai lượt: lượt đầy đủ để báo cáo, lượt baseline chỉ để cổng đọc.
- **Không có baseline thì coi tất cả là mới.** Quét định kỳ, chạy tay, nhánh vừa tạo, hoặc bước baseline hỏng — cổng chặn hết. Không biết cái nào cũ thì chặn hết, chứ không phải bỏ qua hết.

Hệ quả đáng biết: lần **quét định kỳ** trên repo còn nợ sẽ đỏ, vì không có mốc để so. Đó là chủ ý — nó nhắc rằng nợ vẫn còn, và không có merge nào để nó chặn nhầm.

`fail-on-confirmed: false` vẫn còn đó cho trường hợp muốn tắt hẳn cổng, nhưng với baseline thì hiếm khi cần tới.

`semgrep-packs` kéo bộ rule từ registry của Semgrep **lúc chạy**, nên luôn là bản mới nhất mà cộng đồng đang duy trì — không phải bản chép cứng vào repo này từ lúc nào đó. Đổi lại, hai lần chạy cách nhau vài tháng có thể ra kết quả khác nhau dù mã nguồn không đổi: rule mới được thêm vào thì lần sau bắt thêm lỗi. Với một cổng chặn thì đó là điều đúng đắn — rule mới bắt được lỗi mới, sửa xong là qua. Chỉ khi cần tái lập chính xác một con số đã công bố (ví dụ bảng kết quả trong báo cáo) mới nên ghim: đặt `semgrep-packs: ''` để chạy riêng rule của dự án.

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
  kiem-thu-rule/        fixture tự kiểm chứng bộ rule (mã có lỗi cố ý)

.github/workflows/
  devsecops-reusable.yml  pipeline dùng chung, repo khác gọi tới
  devsecops.yml           repo này tự gọi pipeline của chính mình

vi-du-repo-khac.yml     mẫu dán vào repo khác
kiem_tra_moi_truong.py  chẩn đoán 9 điều kiện trong một lần chạy
HUONG_DAN.md            hướng dẫn vận hành + kịch bản kiểm thử 8 bước
HUONG_DAN_DONG_DOI.md   hướng dẫn cho người viết code — chỉ cần Git
```

Hai bộ rule tồn tại vì chúng trả lời hai câu hỏi ngược nhau: một tìm dấu hiệu nguy hiểm, một tìm bằng chứng an toàn. Thiếu bộ thứ hai thì nhãn `FILTERED` không bao giờ xuất hiện, và một phần ba lược đồ ba nhãn biến mất.

### Bộ rule phủ tới đâu, và vì sao dừng ở đó

Rule của dự án **cố ý không phủ hết mọi loại lỗ hổng**. Nó chỉ phủ 12 mã CWE mà ZAP có active scan rule tương ứng — tức là những mã có đường đi tiếp tới nhãn `CONFIRMED`:

| Nhóm | CWE |
|---|---|
| Tiêm lệnh | 89 SQL · 78 OS command · 94 mã nguồn · 90 LDAP · 643 XPath · 91 XML/XSLT |
| Xử lý input | 79 XSS · 22 path traversal · 113 response splitting |
| Gọi ra ngoài | 918 SSRF · 601 open redirect · 611 XXE |

31 rule phát hiện, 9 rule kiểm sanitizer.

Phần bề rộng — mã hoá yếu, mật khẩu cứng trong mã nguồn, deserialization không an toàn, cấu hình sai — để `p/csharp` và `p/security-audit` lo. Viết lại ở đây chỉ tạo báo trùng và nợ bảo trì, trong khi hai bộ đó được cập nhật hằng ngày bởi người làm việc đó toàn thời gian.

Phân vai: **rule cộng đồng lo bề rộng và luôn mới; rule dự án lo bề sâu và sinh được nhãn CONFIRMED.**

### Chỉ 7 trong 12 CWE có thể nhận nhãn FILTERED

Rule sanitizer chỉ được viết khi tồn tại **một API thật sự vô hiệu hoá** được lỗ hổng đó: tham số hoá truy vấn, mã hoá HTML, `ArgumentList`, `Path.GetFileName`, tắt DTD, `LocalRedirect`, `SecurityElement.Escape`.

Năm mã còn lại — SSRF, LDAP, XPath, response splitting, code injection — **không có** API chuẩn nào như vậy trong .NET, nên chúng không có rule sanitizer và **không bao giờ nhận được nhãn FILTERED**. Chúng chỉ có hai kết cục: `CONFIRMED` nếu ZAP khai thác được, hoặc `UNCONFIRMED`.

Đó là câu trả lời đúng. Một rule sanitizer sai không làm báo cáo ồn hơn — nó đẩy một lỗ hổng thật sang nhãn "đã có bằng chứng an toàn". Dương tính giả tốn thời gian; **âm tính giả là thứ đi ra sản xuất.**

### Tự kiểm chứng bộ rule

```bash
python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py
```

Kiểm tra ba điều kiện: mỗi rule phát hiện bắt được case của nó, không rule nào báo nhầm mã đã khử độc, mỗi rule sanitizer tìm được bằng chứng. Rule chưa chạy thử thì chưa phải rule — nó chỉ là một ý định viết bằng YAML, và một rule mù im lặng y hệt một tệp sạch.

---

## Giới hạn đã biết

Những điều dưới đây được đo và công bố, không phải giấu đi.

**Bộ rule là C#.** Repo ngôn ngữ khác thì tầng 1 và 2 không dùng được.

**Bộ rule không đầy đủ, và sẽ bỏ sót.** Rule bắt theo dấu hiệu bề mặt, không truy vết luồng dữ liệu. Đưa chuỗi qua một hàm trung gian, gán vào một trường của lớp, hay ghép bằng `StringBuilder` là thoát. Không bộ rule tĩnh nào phủ hết được, và bộ này cũng vậy.

**Năm lớp CWE không kiểm chứng động được.** Deserialization (CWE-502), lỗi xác thực (CWE-287), IDOR (CWE-639), lộ thông tin (CWE-200), mã hoá yếu (CWE-327) — ZAP không có active scan rule cho chúng. Rule cộng đồng vẫn bắt và vẫn hiện trong báo cáo, nhưng dừng ở `UNCONFIRMED` và được tách thành mục riêng *"ngoài tầm kiểm thử động"*. Chúng **không tính vào cổng chặn**, vì không có hành động nào làm chúng thành `CONFIRMED` được — gộp vào sẽ tạo ra một cổng không bao giờ qua nổi, và kết cục là người ta tắt hẳn nó đi.

**Lược đồ ba nhãn không cứu được lỗ hổng chưa tìm thấy.** Nó bảo vệ chống lại cảnh báo *chưa được kiểm chứng*, chứ không chống được lỗ hổng *chưa được phát hiện*. Semgrep không báo thì `correlate.py` không có gì để hỏi ZAP, nên một lỗ hổng lọt ở tầng 2 sẽ không nhận nhãn `UNCONFIRMED` — nó đơn giản là không xuất hiện ở đâu cả.

**Tầng 5 chỉ chạy với ứng dụng tự chứa.** App cần SQL Server, Redis hay dịch vụ ngoài thì phải thêm service container vào CI, hoặc đặt `run-dast: false` và chấp nhận bốn tầng tĩnh.

**Tầng 5 chỉ phủ endpoint có tham số GET kiểu đơn giản.** Đo trên hai bộ dữ liệu: 43% với ứng dụng mẫu, 9% với eShopOnWeb của Microsoft. Chênh lệch đó là ranh giới áp dụng thật.

**Semgrep không phân tích cú pháp Razor.** Rule cho `.cshtml` chạy ở chế độ generic — khớp văn bản thuần — nên `Html.Raw` trong một dòng chú thích cũng bị báo.

**Hook pre-commit không đi theo git.** Nó nằm trong `.git/hooks/`, nên mỗi người trong nhóm phải tự cài trên máy mình. Chỉ có CI mới là cổng thật sự bắt buộc.

**Cổng quét toàn bộ ứng dụng, không phải phần diff.** Khác với Code Scanning của GitHub vốn chỉ soi phần thay đổi. Hai phạm vi này cho hai kết luận khác nhau trên cùng một pull request, và cả hai đều đúng theo phạm vi của mình.

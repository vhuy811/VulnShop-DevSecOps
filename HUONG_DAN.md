# Hướng dẫn sử dụng

Quy trình DevSecOps năm tầng — dùng hằng ngày, cài lên máy mới, và áp cho dự án khác.

---

## 1. Ba chốt kiểm tra, không phải hai

Điều hay bị hiểu nhầm: **bạn không tự chạy quét trước mỗi lần push.** Hai chốt đầu chạy tự động, bạn không bấm gì cả.

| Chốt | Chạy khi nào | Ai kích hoạt | Mất bao lâu | Chặn gì |
|---|---|---|---|---|
| **Hook pre-commit** | `git commit` | tự động | 5–20 giây | commit không thành |
| **CI trên GitHub** | `git push`, mở PR | tự động | 20 giây – 3 phút | job đỏ, nút Merge xám |
| **Dashboard** | khi bạn muốn nhìn toàn cảnh | **bạn bấm** | 1–4 phút | không chặn gì |

Dashboard không nằm trong luồng làm việc hằng ngày. Nó để điều tra, để so sánh hai repo, và để trình diễn. Hook và CI mới là thứ gác cổng.

---

## 2. Tham gia một dự án có sẵn

### Làm một lần

```bash
git clone <repo-cua-du-an>
cd <ten-du-an>
python C:\path\to\VulnShop\tools\pre_commit_scan.py --install
```

Lệnh thứ ba cài hook vào **repo bạn đang đứng**, trỏ ngược về bộ công cụ. Mỗi repo cài một lần. Hook nằm trong `.git/hooks/` nên không đi theo git — người khác trong nhóm phải tự cài trên máy họ.

### Hằng ngày

```bash
# sửa code như bình thường
git add .
git commit -m "..."      # <- hook tự quét các tệp đang commit
git push                 # <- CI tự chạy đủ năm tầng
```

Chỉ vậy. Không mở dashboard, không chạy lệnh quét nào.

Hook in ra một trong ba kết quả:

| Hook nói gì | Nghĩa là | Làm gì |
|---|---|---|
| `da quet, khong co loi muc ERROR` | đã quét, sạch | commit đi tiếp |
| `COMMIT BI CHAN - N loi muc ERROR` | tìm thấy lỗi trong phần bạn vừa sửa | sửa rồi commit lại |
| `KHONG QUET DUOC` | Docker tắt hoặc thiếu semgrep | commit vẫn qua, nhưng **chưa ai kiểm tra gì** — CI sẽ quét lại |

Dòng thứ ba quan trọng. Nó **không** nói mã nguồn sạch, nó nói chưa kiểm tra được. Hai chuyện đó khác nhau.

### Khi bị hook chặn mà bạn chắc là dương tính giả

```csharp
// nosemgrep: vulnshop-sqli-commandtext-concat
```

Đặt ngay trên dòng bị báo. Cách này để lại dấu vết trong mã nguồn, người review thấy được.

Đừng dùng `git commit --no-verify` — nó bỏ qua âm thầm, không ai biết.

---

## 3. Cài lên một máy khác

### Cần có sẵn

| Phần mềm | Dùng cho | Bắt buộc? |
|---|---|---|
| Docker Desktop | Semgrep, Trivy, ZAP, Gitleaks | có |
| Python 3.9+ | toàn bộ script | có |
| .NET SDK | tầng thư viện và build app | chỉ khi quét dự án .NET |
| Git | hook pre-commit | có |

### Các bước

```bash
git clone https://github.com/vhuy811/VulnShop-DevSecOps.git
cd VulnShop-DevSecOps
pip install requests
python kiem_tra_moi_truong.py
```

Lệnh cuối kiểm tra 9 điều kiện cùng lúc và in ra bảng kèm lệnh sửa cho từng mục còn thiếu. Chạy nó trước khi nghi ngờ bất cứ thứ gì khác.

Muốn dùng tầng động thì bật thêm ZAP:

```bash
docker run -d --name zap -p 8090:8090 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true
```

ZAP cần 20–40 giây mới sẵn sàng.

---

## 4. Cách 1 — Dashboard

Dùng khi muốn nhìn toàn cảnh một repo, so sánh hai dự án, hoặc trình diễn.

### Bước 1

```bash
cd C:\path\to\VulnShop
python tools\webui.py
```

Trình duyệt tự mở `http://localhost:8000`.

### Bước 2 — Tab Tổng quan

Xem bảng điều kiện. Mọi dòng phải xanh trước khi quét. Dòng nào đỏ thì bảng đã ghi sẵn cách sửa.

### Bước 3 — Tab Chạy quét

| Ô | Điền gì |
|---|---|
| Đường dẫn thư mục mã nguồn | đường dẫn tuyệt đối tới repo cần quét — **repo nào cũng được**, không cần là VulnShop |
| Tên hiển thị | tên đặt trên báo cáo |
| URL ứng dụng | `http://host.docker.internal:5000` — hoặc **để trống** nếu app không chạy |

Ô URL là địa chỉ **ZAP nhìn thấy**, không phải địa chỉ trên trình duyệt bạn. ZAP nằm trong container nên `localhost` với nó là chính nó.

App vẫn chạy bình thường ở `localhost:5000`, chỉ ô này điền khác.

Để trống ô URL thì tầng 5 bị bỏ qua — đó là lựa chọn hợp lệ khi app cần cơ sở dữ liệu mà bạn không dựng.

### Bước 4 — Tab Kết quả

Đọc nhãn ở tầng 5:

| Nhãn | Nghĩa |
|---|---|
| **CONFIRMED** | ZAP khai thác được thật trên app đang chạy |
| **FILTERED** | tìm thấy hàm khử độc nằm trên đúng luồng dữ liệu đó |
| **UNCONFIRMED** | chưa có bằng chứng theo chiều nào — **nợ kiểm thử, không phải an toàn** |

Trạng thái `cổng chặn` ở tầng 5 nghĩa là quét chạy đúng và tìm ra lỗ hổng. Khác hẳn `hỏng`, vốn chỉ dùng cho lỗi kỹ thuật.

---

## 5. Cách 2 — CI trên GitHub

Dùng cho mọi dự án thật. Tự động, không cần ai nhớ bấm gì.

### Bước 1 — Tạo tệp gọi

Trong repo cần bảo vệ, tạo `.github/workflows/bao-mat.yml`:

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

Chỉ vậy. Không copy `tools/`, không copy `semgrep-rules/` — pipeline tự kéo về lúc chạy.

### Bước 2 — Chọn tham số cho đúng dự án

| Tham số | Khi nào đổi |
|---|---|
| `project-file` | đường dẫn `.csproj`. Để `''` nếu không phải .NET |
| `run-dast` | `false` nếu app cần CSDL, không khởi động được trong CI |
| `health-path` | đường dẫn kiểm tra app đã lên chưa, ví dụ `/Product/List` |
| `fail-on-confirmed` | `false` cho repo đã có sẵn lỗ hổng cũ — quét và báo cáo đủ, nhưng chưa chặn merge |
| `dockerfile` | tên Dockerfile dùng cho bước quét image |

`run-dast: false` là tham số hay cần nhất. Không có nó, repo cần CSDL sẽ đỏ ở bước khởi động app — đỏ vì thiếu SQL Server, không phải vì tìm ra lỗ hổng. Sai hoàn toàn về ý nghĩa.

### Bước 3 — Push và xem

Vào tab **Actions** của repo. Job sẽ chạy.

| Kết quả | Nghĩa |
|---|---|
| Xanh | không có CONFIRMED nào — cổng cho qua |
| Đỏ ở `Doi sanh SAST-DAST va quality gate` | **đúng** — tìm ra lỗ hổng xác nhận khai thác được |
| Đỏ ở bước khác | lỗi thật, xem log bước đó |

### Bước 4 — Bật chặn merge

Settings → Branches → Add rule cho `main`:

- tick **Require status checks to pass before merging**
- thêm check **`security / scan`**

Tên có dấu gạch chéo vì workflow gọi workflow khác. GitHub đặt tên theo `<job gọi> / <job được gọi>`. Ghi sai tên thì PR treo vĩnh viễn ở *"Expected — waiting for status to be reported"* và không merge được nữa.

Thêm check này **sau khi** đã push một lần, để tên check xuất hiện trong danh sách gợi ý.

### Bước 5 — Telegram (tuỳ chọn)

1. Nhắn `/newbot` cho **@BotFather**, lấy token
2. Nhắn cho bot vừa tạo, mở `https://api.telegram.org/bot<TOKEN>/getUpdates`, lấy `chat.id`
3. Settings → Secrets and variables → Actions → thêm `TELEGRAM_BOT_TOKEN` và `TELEGRAM_CHAT_ID`

Không khai báo thì bước gửi tin tự bỏ qua, không làm hỏng pipeline.

---

## 6. Commit chỉ sửa tài liệu

Sửa `.md`, `.txt`, ảnh, `docs/`, `LICENSE` thì CI bỏ qua các tầng cần build và chạy app — xong trong khoảng 20 giây.

Gitleaks **vẫn chạy**, vì một tệp `.md` hoàn toàn có thể chứa token bị dán nhầm.

Kẹp một tệp `.cs` vào chung commit thì quét đầy đủ trở lại. Sửa chính tệp workflow cũng vậy.

---

## 7. Xử lý sự cố

| Triệu chứng | Nguyên nhân | Cách sửa |
|---|---|---|
| Tầng 5 báo `khong ket noi duoc ZAP o cong 8090` | ZAP chưa chạy hoặc sai cổng | `docker ps`, rồi chạy lại lệnh ZAP ở mục 3 |
| Tầng 5 báo ZAP trả về 500 | ô URL điền `localhost` | đổi thành `host.docker.internal` |
| Tầng 2 ra `CWE UNKNOWN`, 0 FILTERED | đang chạy rule cộng đồng | kiểm tra `semgrep-rules/` có tồn tại không |
| Báo cáo thiếu một tầng | tầng đó bị bỏ qua | xem log để biết lý do — thiếu tệp nghĩa là **không có kết quả mới**, không phải sạch |
| PR treo ở *"waiting for status to be reported"* | tên required check sai | sửa thành `security / scan` |
| Kết quả không phản ánh bản sửa vừa nhận | tiến trình `webui.py` cũ vẫn chạy code cũ | **tắt hẳn** rồi chạy lại — Python nạp module một lần lúc khởi động |
| `UnicodeDecodeError` trên Windows | bảng mã console | đã vá — cập nhật `tools/` lên bản mới nhất |

Nghi ngờ bất cứ thứ gì thì chạy trước:

```bash
python kiem_tra_moi_truong.py
```

---

## 8. Giới hạn cần biết

- Bộ rule là **C#**. Repo ngôn ngữ khác thì tầng 1 và 2 không dùng được.
- Tầng 5 chỉ chạy với **ứng dụng tự chứa** — app cần SQL Server, Redis hay dịch vụ ngoài thì phải thêm service container vào CI.
- Tầng 5 chỉ phủ được endpoint có **tham số GET kiểu đơn giản**. VulnShop phủ 43%, eShopOnWeb phủ 9%. Tầng 3 đo và công bố con số này thay vì giấu.
- **UNCONFIRMED không phải kết luận an toàn.** Nó là phần chưa có bằng chứng theo chiều nào.

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
git clone https://github.com/vhuy811/DevSecOps_VHNAT.git
cd DevSecOps_VHNAT
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
    uses: vhuy811/DevSecOps_VHNAT/.github/workflows/devsecops-reusable.yml@main
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
| `fail-on-unverified` | `false` nếu muốn tắt tầng động mà job vẫn xanh. Mặc định `true`: tắt DAST trong khi vẫn có cảnh báo tĩnh trên endpoint kiểm thử được thì job đỏ |
| `semgrep-packs` | mặc định `p/csharp p/security-audit`. Thêm pack khác cho ngôn ngữ khác, hoặc để `''` khi cần tái lập đúng một con số đã công bố |
| `dockerfile` | tên Dockerfile dùng cho bước quét image |

`run-dast: false` là tham số hay cần nhất. Không có nó, repo cần CSDL sẽ đỏ ở bước khởi động app — đỏ vì thiếu SQL Server, không phải vì tìm ra lỗ hổng. Sai hoàn toàn về ý nghĩa.

### Bước 3 — Push và xem

Vào tab **Actions** của repo. Job sẽ chạy.

| Kết quả | Nghĩa |
|---|---|
| Xanh | không có CONFIRMED **mới** — cổng cho qua. Nợ cũ (nếu có) vẫn hiện trong tóm tắt với nhãn *nợ cũ* |
| Đỏ ở `Doi sanh SAST-DAST va quality gate` | **đúng** — lần thay đổi này đưa vào lỗ hổng xác nhận khai thác được |
| Đỏ ở lần quét định kỳ | không có mốc baseline nên mọi cảnh báo tính là mới — nhắc rằng nợ vẫn còn |
| Đỏ ở bước khác | lỗi thật, xem log bước đó |

Trang tóm tắt của lần chạy (tab Actions → bấm vào lần chạy) ghi rõ: bao nhiêu CONFIRMED mới, bao nhiêu nợ cũ, và bao nhiêu cảnh báo ZAP không có scanner để kiểm chứng.

### Bước 4 — Bật chặn merge

Settings → Branches → Add rule cho `main`:

- tick **Require a pull request before merging** → **Require approvals: 1**
- tick **Require status checks to pass before merging** → thêm check **`security / scan`**
- tick **Require branches to be up to date before merging**
- tick **Do not allow bypassing the above settings** — áp cả cho admin, tức cả bạn. Không có dòng này thì bước 8 của kịch bản kiểm thử (mục 8) không chứng minh được gì.

Tên check có dấu gạch chéo vì workflow gọi workflow khác. GitHub đặt tên theo `<job gọi> / <job được gọi>`. Ghi sai tên thì PR treo vĩnh viễn ở *"Expected — waiting for status to be reported"* và không merge được nữa.

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
| Tầng 2 ra 0 FILTERED | `sanitizer-check.yaml` không tìm thấy | kiểm tra `semgrep-rules/` có tồn tại không — chỉ rule dự án mới sinh nhãn FILTERED |
| Tầng 2 ra nhiều cảnh báo hơn lần trước dù không sửa code | rule cộng đồng kéo bản mới lúc chạy | đúng như thiết kế — sửa lỗi mới hoặc đặt `semgrep-packs: ''` nếu cần tái lập |
| Báo cáo thiếu một tầng | tầng đó bị bỏ qua | xem log để biết lý do — thiếu tệp nghĩa là **không có kết quả mới**, không phải sạch |
| PR treo ở *"waiting for status to be reported"* | tên required check sai | sửa thành `security / scan` |
| Kết quả không phản ánh bản sửa vừa nhận | tiến trình `webui.py` cũ vẫn chạy code cũ | **tắt hẳn** rồi chạy lại — Python nạp module một lần lúc khởi động |
| `UnicodeDecodeError` trên Windows | bảng mã console | đã vá — cập nhật `tools/` lên bản mới nhất |

Nghi ngờ bất cứ thứ gì thì chạy trước:

```bash
python kiem_tra_moi_truong.py
```

Nghi ngờ **bộ rule** thì chạy:

```bash
python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py
```

Lệnh này bắn từng rule vào một tệp mã có lỗi cố ý và một tệp đã khử độc, rồi báo rule nào mù, rule nào báo nhầm. Sửa rule xong luôn chạy lại — rule hỏng im lặng y hệt tệp sạch.

---

## 8. Kịch bản kiểm thử hệ thống — 8 bước

Dùng cho chương Thực nghiệm và cho buổi bảo vệ. Cần 3 người và một repo ứng dụng đã gắn pipeline (xem `HUONG_DAN_DONG_DOI.md` để đồng đội cài). Mỗi bước là một bằng chứng; chụp màn hình kết quả từng bước.

Điều kiện trước: `main` của repo app **sạch** (0 CONFIRMED — bản có lỗ hổng nằm ở tag `ground-truth`), branch protection đã bật với check `security / scan` và tắt bypass cho admin.

| # | Ai | Làm gì | Kỳ vọng | Chứng minh |
|---|---|---|---|---|
| 1 | B | `git push origin main` trực tiếp | GitHub từ chối `GH006` | Không có đường tắt vào main |
| 2 | A | Nhánh `tinh-nang/loc`, thêm action mới `Product/Filter?category=` nối chuỗi vào SQL, push, mở PR | `security / scan` **đỏ**. Summary ghi `1 lỗ hổng mới`. Chú thích hiện đúng dòng trong tab Files changed. Nút Merge khoá | Cổng chặn theo **bằng chứng khai thác** — ZAP đã bắn payload và khai thác được — không theo phỏng đoán của SAST |
| 3 | A | Thêm `// nosemgrep: vulnshop-sqli-commandtext-concat` không lý do, push | Check **xanh** — cảnh báo bị tắt nên không có gì để hỏi ZAP | Suppress qua được máy nhưng… |
| 4 | B | Review, thấy `nosemgrep` không lý do → **Request changes** | Merge vẫn khoá | …không qua được người. Quy ước có răng |
| 5 | A | Bỏ `nosemgrep`, vá thật bằng tham số hoá, push | Check **xanh**. Summary: `0 lỗ hổng mới`. Merge vẫn xám vì chưa approve | Sửa đúng thì qua. Vá được nhận diện bằng bằng chứng sanitizer (FILTERED) hoặc ZAP không khai thác được nữa |
| 6 | B | Approve | Merge mở → A merge | Hai chốt độc lập: máy và người |
| 7 | C | PR sạch trên nhánh khác, cùng lúc với bước 5 | Hai pipeline chạy song song, kết quả độc lập | Không chặn nhầm người khác |
| 8 | Minh | Thử merge một PR đỏ bằng quyền admin | Không được | Tắt bypass áp cả chủ repo |

Bước 2 và 5 là hai bước quan trọng nhất: cổng chặn được lỗ hổng **trước khi** nó vào `main`, và phân biệt được **sửa thật** với **tắt cảnh báo**.

Muốn trình diễn thêm tình huống *repo có sẵn nợ cũ* — hay gặp nhất khi áp pipeline lên dự án thật — thì mở PR từ tag `ground-truth`: Summary ghi `4 nợ cũ`, cổng không chặn vì PR không thêm lỗi mới. Đó là baseline hoạt động, đã thấy ở lần chạy `#3` của repo app.

Lưu ý khi chọn action cho bước 2: phải là action có **tham số GET** (`?category=`), vì tầng 5 chỉ bắn payload qua tham số GET. Đặt lỗi vào action POST thì SAST vẫn bắt nhưng ZAP không kiểm chứng được, kết quả là UNCONFIRMED và không chặn — đó là giới hạn thật, được ghi ở mục 9.

---

## 9. Giới hạn cần biết

- Bộ rule của dự án là **C#** và phủ **12 mã CWE** mà ZAP xác nhận động được. Repo ngôn ngữ khác thì chỉ còn rule cộng đồng chạy.
- **7/12 CWE có thể nhận nhãn FILTERED.** Năm mã còn lại (SSRF, LDAP, XPath, response splitting, code injection) không có API khử độc chuẩn trong .NET nên chỉ có hai kết cục: `CONFIRMED` hoặc `UNCONFIRMED`.
- Cảnh báo thuộc CWE **ngoài bảng ánh xạ** (deserialization, IDOR, mã hoá yếu…) hiện trong báo cáo ở mục riêng và **không tính vào cổng chặn** — không có công cụ nào kiểm chứng chúng được.
- Tầng 5 chỉ chạy với **ứng dụng tự chứa** — app cần SQL Server, Redis hay dịch vụ ngoài thì phải thêm service container vào CI.
- Tầng 5 chỉ phủ được endpoint có **tham số GET kiểu đơn giản**. VulnShop phủ 43%, eShopOnWeb phủ 9%. Tầng 3 đo và công bố con số này thay vì giấu.
- **UNCONFIRMED không phải kết luận an toàn.** Nó là phần chưa có bằng chứng theo chiều nào.

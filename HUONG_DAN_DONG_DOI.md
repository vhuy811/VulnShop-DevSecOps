# Hướng dẫn cho đồng đội — Windows

Bản này dành cho người **viết code**, không phải người vận hành pipeline. Bạn không cài Docker, không cài Semgrep, không cài Python. Chỉ cần Git và tài khoản GitHub.

Việc kiểm tra bảo mật nằm **trên GitHub**, không nằm trên máy bạn. Bạn không phải bấm gì để nó chạy, và cũng không có cách nào né nó.

---

## 1. Cài một lần

1. Tải Git for Windows: https://git-scm.com/download/win — cài với mọi lựa chọn mặc định.
2. Mở **Command Prompt** (gõ `cmd` vào Start), khai tên và email dùng cho commit:

```
git config --global user.name "Ten Cua Ban"
git config --global user.email "email-ban-dung-tren-github@example.com"
git config --global core.editor notepad
```

Dòng cuối để Git mở Notepad thay vì Vim khi cần soạn nội dung — Vim không thoát được nếu chưa quen.

3. Nhận lời mời Collaborator trong email từ GitHub.

4. Kéo repo về:

```
cd C:\Users\<ten-ban>\Documents
git clone https://github.com/vhuy811/<TEN-REPO-APP>.git
cd <TEN-REPO-APP>
```

Lần đầu push, Windows sẽ mở cửa sổ đăng nhập GitHub. Đăng nhập một lần, những lần sau tự nhớ.

---

## 2. Quy trình hằng ngày — 5 lệnh

Không bao giờ làm việc trực tiếp trên `main`. Mỗi việc một nhánh.

```
git checkout main
git pull
git checkout -b tinh-nang/ten-viec-ban-lam
```

Sửa code. Rồi:

```
git add .
git commit -m "Mo ta ngan gon viec vua lam"
git push -u origin tinh-nang/ten-viec-ban-lam
```

Git sẽ in ra một đường link dạng `https://github.com/vhuy811/<repo>/pull/new/...` — mở link đó trong trình duyệt, bấm **Create pull request**.

**Mở PR là lúc pipeline chạy.** Push lên nhánh của bạn không tự quét — nên đừng chờ, mở PR ngay (chọn *Draft* nếu chưa xong). Từ đây bạn không làm gì nữa.

---

## 3. Đọc kết quả

Ở cuối trang Pull Request có ô kiểm tra tên **`security / scan`**.

| Bạn thấy | Nghĩa là | Làm gì |
|---|---|---|
| Vòng tròn vàng đang quay | đang quét, 1–4 phút | chờ |
| Dấu tick xanh | không có lỗ hổng **mới** nào được xác nhận | chờ người review approve rồi bấm Merge |
| Dấu X đỏ ở `security / scan` | code bạn vừa đẩy lên **có lỗ hổng đã được chứng minh khai thác được** | xem mục 4 |
| Nút Merge xám dù tick xanh | chưa có ai approve | nhờ một người trong nhóm review |

Pipeline quét **toàn bộ** ứng dụng nhưng chỉ chặn phần **bạn vừa thêm**. Lỗi có sẵn từ trước không đổ lên đầu bạn — chúng hiện trong báo cáo với nhãn *nợ cũ* và không chặn PR của bạn.

---

## 4. Khi bị đỏ

1. Bấm vào chữ **Details** cạnh dấu X.
2. Bấm **Summary** ở cột trái. Trang này ghi rõ: tệp nào, dòng nào, loại lỗ hổng gì, và địa chỉ URL mà nó bị khai thác.
3. Sửa đúng chỗ đó. Ví dụ hay gặp nhất — SQL Injection:

```csharp
// SAI: nối chuỗi
cmd.CommandText = "SELECT * FROM SanPham WHERE Ten = '" + ten + "'";

// ĐÚNG: tham số hoá
cmd.CommandText = "SELECT * FROM SanPham WHERE Ten = @ten";
cmd.Parameters.AddWithValue("@ten", ten);
```

4. Commit và push lại lên **cùng nhánh đó**. Pipeline tự chạy lại, không cần mở PR mới:

```
git add .
git commit -m "Sua SQL Injection o SanPham/Tim"
git push
```

Đỏ nghĩa là pipeline **đã bắn thử payload vào ứng dụng đang chạy và khai thác được**. Không phải phỏng đoán. Không có chuyện "chắc nó báo nhầm".

---

## 5. Ba quy ước

**Không push lên `main`.** GitHub sẽ từ chối với lỗi `GH006`. Nếu thấy lỗi đó, bạn đang ở sai nhánh — chạy `git checkout -b ten-nhanh-moi` rồi push lại.

**Không tự approve PR của mình.** Nhờ người khác trong nhóm.

**Muốn bỏ qua một cảnh báo thì phải ghi lý do.** Đặt ngay trên dòng bị báo:

```csharp
// nosemgrep: vulnshop-sqli-commandtext-concat -- chuoi nay la hang, khong co input nguoi dung. 26/09/2026
```

Không có lý do thì người review **có quyền từ chối**. Đừng dùng `git commit --no-verify` hay bất kỳ cách bỏ qua âm thầm nào — người review sẽ thấy, và nó vô nghĩa vì kiểm tra nằm trên GitHub chứ không nằm trên máy bạn.

---

## 6. Khi được nhờ review

1. Mở PR, tab **Files changed**. Đọc phần đổi.
2. Kiểm tra ba thứ: `security / scan` xanh chưa; có dòng `nosemgrep` nào không, và nếu có thì lý do có thuyết phục không; code có làm đúng việc mô tả không.
3. Bấm **Review changes** → **Approve** hoặc **Request changes** kèm nhận xét.

Một PR xanh vẫn có thể bị từ chối. Cổng kiểm tra bảo mật; người review kiểm tra phần còn lại.

---

## 7. Lỗi hay gặp

| Lỗi | Nguyên nhân | Sửa |
|---|---|---|
| `GH006: Protected branch update failed` | push thẳng lên main | `git checkout -b nhanh-moi` rồi push lại |
| PR treo ở *"Expected — waiting for status"* | cấu hình phía repo, không phải lỗi bạn | báo người quản lý repo |
| `fatal: not a git repository` | đang đứng sai thư mục | `cd` vào thư mục repo |
| Vim mở ra, không thoát được | chưa đặt `core.editor` | gõ `Esc` rồi `:q!` Enter; sau đó chạy lệnh `git config` ở mục 1 |
| `Your branch is behind` | main đã có commit mới | `git pull origin main` rồi giải quyết xung đột nếu có |

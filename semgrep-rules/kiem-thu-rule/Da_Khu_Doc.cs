// =============================================================================
// FIXTURE KIEM THU RULE - KHONG DUOC BI BAT
// =============================================================================
//
// Doi trong cua Co_Loi.cs. Moi phuong thuc o day lam DUNG mot viec ma
// Co_Loi.cs lam sai. Hai dieu kien phai dung cung luc:
//
//   1. KHONG rule phat hien nao duoc bat o tep nay.  <- kiem tra duong tinh gia
//   2. Rule sanitizer PHAI bat duoc bang chung khu doc. <- kiem tra nhan FILTERED
//
// Dieu kien 2 quan trong khong kem dieu kien 1. Khong co bang chung sanitizer
// thi khong canh bao nao duoc phep mang nhan FILTERED, va moi thu don het vao
// UNCONFIRMED - co che ba nhan sup con mot nhan.
// =============================================================================

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace KiemThuRule
{
    public class DaKhuDocController : Controller
    {
        // ------------------------------------------------------------------
        // CWE-89 : tham so hoa
        // sanitizer: vulnshop-sanitizer-sql-parameterized
        // ------------------------------------------------------------------
        public void Sql_ThamSoHoa(SqlCommand cmd, string ten)
        {
            cmd.CommandText = "SELECT * FROM SanPham WHERE Ten = @ten";
            cmd.Parameters.AddWithValue("@ten", ten);
            cmd.ExecuteNonQuery();
        }

        // sanitizer: vulnshop-sanitizer-sql-ef-interpolated
        public void Sql_EfInterpolated(AppDbContext ctx, string ten)
        {
            ctx.Database.ExecuteSqlInterpolated($"DELETE FROM SanPham WHERE Ten = {ten}");
        }

        // sanitizer: vulnshop-sanitizer-sql-dapper-params
        public void Sql_DapperThamSo(SqlConnection conn, int id)
        {
            conn.Execute("UPDATE DonHang SET TrangThai = 1 WHERE Id = @id", new { id });
        }

        // ------------------------------------------------------------------
        // CWE-79 : ma hoa HTML
        // sanitizer: vulnshop-sanitizer-html-encode
        // ------------------------------------------------------------------
        public string Xss_MaHoa(string tuKhoa)
        {
            var daMaHoa = WebUtility.HtmlEncode(tuKhoa);
            return daMaHoa;
        }

        // ------------------------------------------------------------------
        // CWE-78 : tach doi so
        // sanitizer: vulnshop-sanitizer-cmd-argumentlist
        // ------------------------------------------------------------------
        public void Cmd_ArgumentList(string tenTep)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = "/usr/bin/convert";
            psi.ArgumentList.Add("-resize");
            psi.ArgumentList.Add("100x100");
            psi.ArgumentList.Add(tenTep);
            Process.Start(psi);
        }

        // ------------------------------------------------------------------
        // CWE-22 : cat bo thanh phan thu muc
        // sanitizer: vulnshop-sanitizer-path-getfilename
        // ------------------------------------------------------------------
        public string Path_ChiTenTep(string tenTep)
        {
            var an = Path.GetFileName(tenTep);
            var day = Path.Combine("/var/data", an);
            return File.ReadAllText(day);
        }

        // ------------------------------------------------------------------
        // CWE-611 : dong DTD
        // sanitizer: vulnshop-sanitizer-xxe-dtd-off
        // ------------------------------------------------------------------
        public void Xml_DongDtd()
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
        }

        // ------------------------------------------------------------------
        // CWE-601 : chi cho dia chi noi bo
        // sanitizer: vulnshop-sanitizer-local-redirect
        // ------------------------------------------------------------------
        public IActionResult Redirect_NoiBo(string returnUrl)
        {
            return LocalRedirect(returnUrl);
        }

        // ------------------------------------------------------------------
        // CWE-91 : ma hoa noi dung XML
        // sanitizer: vulnshop-sanitizer-xml-escape
        // ------------------------------------------------------------------
        public void Xml_MaHoa(XmlWriter writer, string ten)
        {
            var an = SecurityElement.Escape(ten);
            writer.WriteElementString("Ten", ten);
        }
    }
}

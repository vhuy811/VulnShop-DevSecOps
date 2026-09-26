// =============================================================================
// FIXTURE KIEM THU RULE - PHAI BI BAT
// =============================================================================
//
// KHONG PHAI MA NGUON UNG DUNG. Day la du lieu kiem thu cho bo rule Semgrep.
// Moi phuong thuc trong tep nay chua dung MOT dang lo hong, va rule tuong ung
// PHAI bat duoc no. Neu mot rule khong bat duoc case cua no, rule do hong -
// chu khong phai ma nguon nay an toan.
//
// Tep nay bi loai tru khoi ca ba cho quet (hook pre-commit, CI, dashboard).
// Neu ban thay canh bao tu tep nay trong bao cao cua mot du an that, nghia la
// mot trong ba cau hinh loai tru bi sai.
//
// Chay kiem thu: python semgrep-rules/kiem-thu-rule/chay_kiem_thu.py
// =============================================================================

using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Xml;
using System.Xml.Xsl;
using Microsoft.AspNetCore.Mvc;

namespace KiemThuRule
{
    public class CoLoiController : Controller
    {
        private readonly HttpClient _http = new HttpClient();
        private readonly WebClient _wc = new WebClient();

        // ------------------------------------------------------------------
        // CWE-89 : SQL Injection
        // ------------------------------------------------------------------

        // rule: vulnshop-sqli-commandtext-concat
        public void Sqli_CommandTextConcat(SqlCommand cmd, string ten)
        {
            cmd.CommandText = "SELECT * FROM SanPham WHERE Ten = '" + ten + "'";
        }

        // rule: vulnshop-sqli-commandtext-interpolated
        public void Sqli_CommandTextInterpolated(SqlCommand cmd, string ten)
        {
            cmd.CommandText = $"SELECT * FROM SanPham WHERE Ten = '{ten}'";
        }

        // rule: vulnshop-sqli-query-string-concat
        public void Sqli_BienTrungGian(string ten)
        {
            var sqlLenh = "SELECT * FROM SanPham WHERE Ten = '" + ten + "'";
            Console.WriteLine(sqlLenh);
        }

        // rule: vulnshop-sqli-sqlcommand-ctor-concat
        public void Sqli_HamDung(SqlConnection conn, string id)
        {
            var cmd = new SqlCommand("SELECT * FROM DonHang WHERE Id = " + id, conn);
            cmd.ExecuteNonQuery();
        }

        // rule: vulnshop-sqli-efcore-raw
        public void Sqli_EfCoreRaw(AppDbContext ctx, string ten)
        {
            ctx.Database.ExecuteSqlRaw("DELETE FROM SanPham WHERE Ten = '" + ten + "'");
        }

        // rule: vulnshop-sqli-dapper-concat
        public void Sqli_Dapper(SqlConnection conn, string id)
        {
            conn.Execute("UPDATE DonHang SET TrangThai = 1 WHERE Id = " + id);
        }

        // ------------------------------------------------------------------
        // CWE-79 : Cross-Site Scripting
        // ------------------------------------------------------------------

        // rule: vulnshop-xss-html-string-concat
        public void Xss_BienHtml(string tuKhoa)
        {
            var htmlKetQua = "<p>Ban vua tim: " + tuKhoa + "</p>";
            Console.WriteLine(htmlKetQua);
        }

        // rule: vulnshop-xss-response-write
        public void Xss_ResponseWrite(string tuKhoa)
        {
            Response.Write("<div>" + tuKhoa + "</div>");
        }

        // rule: vulnshop-xss-htmlstring-ctor
        public object Xss_HtmlString(string binhLuan)
        {
            return new HtmlString("<span>" + binhLuan + "</span>");
        }

        // rule: vulnshop-xss-content-result-html
        public IActionResult Xss_ContentResult(string ten)
        {
            return Content("<h1>Xin chao " + ten + "</h1>", "text/html");
        }

        // ------------------------------------------------------------------
        // CWE-78 : OS Command Injection
        // ------------------------------------------------------------------

        // rule: vulnshop-cmdi-process-start-concat
        public void Cmdi_ProcessStart(string tenTep)
        {
            Process.Start("convert " + tenTep + " out.png");
        }

        // rule: vulnshop-cmdi-processstartinfo-arguments
        public void Cmdi_Arguments(string tenTep)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = "/usr/bin/convert";
            psi.Arguments = "-resize 100x100 " + tenTep;
            Process.Start(psi);
        }

        // rule: vulnshop-cmdi-shell-execute
        public void Cmdi_QuaShell(string thamSo)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = "/bin/sh";
            Process.Start(psi);
        }

        // ------------------------------------------------------------------
        // CWE-22 : Path Traversal
        // ------------------------------------------------------------------

        // rule: vulnshop-pathtraversal-file-api-concat
        public string PathTraversal_ReadAllText(string tenTep)
        {
            return File.ReadAllText("/var/data/" + tenTep);
        }

        // rule: vulnshop-pathtraversal-physicalfile
        public IActionResult PathTraversal_PhysicalFile(string tenTep)
        {
            return PhysicalFile("/var/data/" + tenTep, "application/octet-stream");
        }

        // rule: vulnshop-pathtraversal-path-combine-request
        public string PathTraversal_PathCombine()
        {
            var duongDan = Path.Combine("/var/data", Request.Query["ten"]);
            return duongDan;
        }

        // ------------------------------------------------------------------
        // CWE-643 : XPath Injection
        // ------------------------------------------------------------------

        // rule: vulnshop-xpathi-select-concat
        public XmlNode XPathi_SelectSingleNode(XmlDocument doc, string ten)
        {
            return doc.SelectSingleNode("//NguoiDung[@ten='" + ten + "']");
        }

        // ------------------------------------------------------------------
        // CWE-611 : XXE
        // ------------------------------------------------------------------

        // rule: vulnshop-xxe-dtd-processing-parse
        public void Xxe_ChoPhepDtd()
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
        }

        // rule: vulnshop-xxe-xmlresolver-enabled
        public void Xxe_XmlResolver()
        {
            var settings = new XmlReaderSettings();
            settings.XmlResolver = new XmlUrlResolver();
        }

        // rule: vulnshop-xxe-xmltextreader-default
        public void Xxe_XmlTextReader(string duongDan)
        {
            var reader = new XmlTextReader(duongDan);
            reader.Read();
        }

        // ------------------------------------------------------------------
        // CWE-918 : SSRF
        // ------------------------------------------------------------------

        // rule: vulnshop-ssrf-http-client-concat
        public void Ssrf_HttpClient(string may)
        {
            _http.GetStringAsync("http://" + may + "/api/trangthai");
        }

        // rule: vulnshop-ssrf-webrequest-concat
        public void Ssrf_WebClient(string may)
        {
            _wc.DownloadString("http://" + may + "/api/trangthai");
        }

        // ------------------------------------------------------------------
        // CWE-601 : Open Redirect
        // ------------------------------------------------------------------

        // rule: vulnshop-openredirect-from-request
        public IActionResult OpenRedirect_TuRequest()
        {
            return Redirect(Request.Query["dich"]);
        }

        // rule: vulnshop-openredirect-parameter
        public IActionResult OpenRedirect_ThamSo(string returnUrl)
        {
            return Redirect(returnUrl);
        }

        // ------------------------------------------------------------------
        // CWE-90 : LDAP Injection
        // ------------------------------------------------------------------

        // rule: vulnshop-ldapi-filter-concat
        public void Ldapi_Filter(DirectorySearcher s, string ten)
        {
            s.Filter = "(&(objectClass=user)(cn=" + ten + "))";
        }

        // ------------------------------------------------------------------
        // CWE-91 : XML / XSLT Injection
        // ------------------------------------------------------------------

        // rule: vulnshop-xmli-innerxml-concat
        public void Xmli_LoadXml(XmlDocument doc, string ten)
        {
            doc.LoadXml("<NguoiDung><Ten>" + ten + "</Ten></NguoiDung>");
        }

        // rule: vulnshop-xslti-enable-script
        public void Xslti_EnableScript()
        {
            var cauHinh = new XsltSettings();
            cauHinh.EnableScript = true;
        }

        // ------------------------------------------------------------------
        // CWE-113 : HTTP Response Splitting
        // ------------------------------------------------------------------

        // rule: vulnshop-responsesplit-header-concat
        public void ResponseSplit_Header(string ngonNgu)
        {
            Response.Headers.Add("X-Ngon-Ngu", "vi-" + ngonNgu);
        }

        // ------------------------------------------------------------------
        // CWE-94 : Server-Side Code Injection
        // ------------------------------------------------------------------

        // rule: vulnshop-codei-dynamic-compile
        public void CodeI_ChayMa(string bieuThuc)
        {
            CSharpScript.EvaluateAsync(bieuThuc);
        }
    }
}

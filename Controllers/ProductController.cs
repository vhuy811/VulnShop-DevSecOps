using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using System.Text.Encodings.Web;
using VulnShop.Data;

namespace VulnShop.Controllers;

// Cac action duoc gieo loi co chu dich phuc vu do an.
// Doi chieu day du trong ground_truth.csv o thu muc goc.
public class ProductController : Controller
{
    // ===== C1 | CWE-89 | CONFIRMED =====
    // Noi chuoi truc tiep tu tham so q vao cau SELECT.
    public IActionResult Search(string q)
    {
        var rows = new List<string>();
        using var conn = new SqliteConnection(Db.ConnectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, Name, Category, Price FROM Products WHERE Name LIKE '%" + q + "%'";
        try
        {
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                rows.Add($"{reader.GetValue(0)} | {reader.GetValue(1)} | {reader.GetValue(2)} | {reader.GetValue(3)}");
        }
        catch (SqliteException ex)
        {
            rows.Add("SQL error: " + ex.Message);
        }
        ViewBag.Query = q;
        return View(rows);
    }

    // ===== C2 | CWE-89 | CONFIRMED =====
    // Tham so id khong ep kieu, noi thang vao menh de WHERE.
    public IActionResult Detail(string id)
    {
        var rows = new List<string>();
        using var conn = new SqliteConnection(Db.ConnectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, Name, Category, Price FROM Products WHERE Id = " + id;
        try
        {
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                rows.Add($"{reader.GetValue(0)} | {reader.GetValue(1)} | {reader.GetValue(2)} | {reader.GetValue(3)}");
        }
        catch (SqliteException ex)
        {
            rows.Add("SQL error: " + ex.Message);
        }
        ViewBag.Query = id;
        return View("Search", rows);
    }

    // ===== C3 | CWE-79 | CONFIRMED =====
    // Gia tri msg di thang ra view va duoc in bang Html.Raw.
    public IActionResult Echo(string msg)
    {
        ViewBag.Msg = msg;
        return View();
    }

    // ===== C4 | CWE-79 | CONFIRMED =====
    // Dung HTML tu chuoi noi truc tiep roi tra ve voi content-type text/html.
    public IActionResult Greet(string name)
    {
        var html = "<h3>Xin chao " + name + "</h3><p>Chuc ban mua sam vui ve.</p>";
        return Content(html, "text/html");
    }

    // ===== C5 | CWE-89 | FILTERED =====
    // An toan that su: WHERE da tham so hoa.
    // Van noi chuoi nhung chi noi ten cot cung, khong lay tu input.
    public IActionResult SafeSearch(string q)
    {
        var sortColumn = "Name";
        var sql = "SELECT Id, Name, Category, Price FROM Products WHERE Name LIKE @q ORDER BY " + sortColumn;

        var rows = new List<string>();
        using var conn = new SqliteConnection(Db.ConnectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("@q", "%" + (q ?? "") + "%");
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            rows.Add($"{reader.GetValue(0)} | {reader.GetValue(1)} | {reader.GetValue(2)} | {reader.GetValue(3)}");

        ViewBag.Query = q;
        return View("Search", rows);
    }

    // ===== C6 | CWE-79 | FILTERED =====
    // An toan that su: da HtmlEncode truoc khi noi vao chuoi HTML.
    public IActionResult SafeGreet(string name)
    {
        var safe = HtmlEncoder.Default.Encode(name ?? "");
        var html = "<h3>Xin chao " + safe + "</h3><p>Chuc ban mua sam vui ve.</p>";
        return Content(html, "text/html");
    }

    // ===== Cac endpoint vo hai, dung de tang be mat tan cong =====
    public IActionResult List()
    {
        var rows = new List<string>();
        using var conn = new SqliteConnection(Db.ConnectionString);
        conn.Open();
        var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, Name, Category, Price FROM Products ORDER BY Id";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            rows.Add($"{reader.GetValue(0)} | {reader.GetValue(1)} | {reader.GetValue(2)} | {reader.GetValue(3)}");

        ViewBag.Query = "(tat ca)";
        return View("Search", rows);
    }

    public IActionResult About() => Content("<h3>Gioi thieu VulnShop</h3>", "text/html");

    public IActionResult Contact() => Content("<h3>Lien he: support@vulnshop.local</h3>", "text/html");

    public IActionResult Help() => Content("<h3>Trung tam tro giup</h3>", "text/html");

    public IActionResult Pricing() => Content("<h3>Bang gia va chinh sach giao hang</h3>", "text/html");
}

using VulnShop.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// Co y KHONG dung app.UseHttpsRedirection() de OWASP ZAP quet duoc qua HTTP thuan.
app.UseRouting();
app.UseAuthorization();
app.MapStaticAssets();

app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

// Tao lai CSDL SQLite voi du lieu mau moi lan khoi dong.
Db.Init();

app.Run();

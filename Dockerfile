# Ban NGAY THO - viet theo cach mac dinh ma phan lon nguoi moi se viet.
# Khong co gi "sai cu phap", app chay binh thuong. Nhung no mac 3 loi cau hinh
# pho bien, va do la muc dich: de Trivy phat hien ra, roi so voi Dockerfile.hardened.
#
# Cac van de co y giu lai:
#   1. Dung image SDK lam runtime - nang gap nhieu lan va keo theo rat nhieu goi
#      he dieu hanh khong can thiet, moi goi la mot be mat tan cong.
#   2. Chay bang root - mac dinh neu khong khai bao USER.
#   3. Khong co HEALTHCHECK.

FROM mcr.microsoft.com/dotnet/sdk:9.0

WORKDIR /app
COPY . .
RUN dotnet publish -c Release -o /out

WORKDIR /out
EXPOSE 5000
ENV ASPNETCORE_URLS=http://0.0.0.0:5000
ENTRYPOINT ["dotnet", "VulnShop.dll"]

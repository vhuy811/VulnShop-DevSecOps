using Microsoft.Data.Sqlite;

namespace VulnShop.Data;

public static class Db
{
    public const string ConnectionString = "Data Source=vulnshop.db";

    public static void Init()
    {
        using var conn = new SqliteConnection(ConnectionString);
        conn.Open();

        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            DROP TABLE IF EXISTS Products;
            CREATE TABLE Products (
                Id       INTEGER PRIMARY KEY,
                Name     TEXT NOT NULL,
                Category TEXT NOT NULL,
                Price    REAL NOT NULL
            );
            INSERT INTO Products (Id, Name, Category, Price) VALUES
                (1, 'Ban phim co',       'Phu kien',  1200000),
                (2, 'Chuot khong day',   'Phu kien',   450000),
                (3, 'Man hinh 27 inch',  'Man hinh',  5600000),
                (4, 'Tai nghe chong on', 'Am thanh',  2300000),
                (5, 'Webcam Full HD',    'Phu kien',   890000);

            DROP TABLE IF EXISTS Users;
            CREATE TABLE Users (
                Id       INTEGER PRIMARY KEY,
                Username TEXT,
                Secret   TEXT
            );
            INSERT INTO Users (Id, Username, Secret) VALUES
                (1, 'admin', 'FLAG{sqli_thanh_cong}'),
                (2, 'tung',  'khong-phai-flag');
        ";
        cmd.ExecuteNonQuery();
    }
}

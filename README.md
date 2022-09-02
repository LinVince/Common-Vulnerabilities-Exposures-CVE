# Common-Vulnerability-Exposure-CVE

CVE Database Guidelines
1. 1999-2018的 CVE公開漏洞已彙整成數據庫，可至此位置下載 https://drive.google.com/file/d/1rI70Rt66t4wzHFo9x-x_i_LV1zQodi2Z/view?usp=sharing 因目前尚未開發User Interface，因此暫時使用 SQLite來進行查詢、過濾、統計及分析。 可至以下網站下載 SQLite。http://sqlitebrowser.org/
2. 此資料庫 Database.sqlite匯入資料來源有兩處，第一處是 CVE - Common Vulnerabilities and Exposures (CVE) 公佈漏洞編號、內容、公佈日期、修改日期，漏洞類型 (所有分類 )、 受影響之廠商和產品 (全部皆以小寫 、 空白鍵以 ”_”以底線呈現)
3. 可於可於Filter輸入關鍵字，縮小搜尋範圍。詳細敘述於右上方視窗輸入關鍵字，縮小搜尋範圍。
4. 此表格暫時供給大家查詢，往後會開發使用者介面和更多統計工此表格暫時供給大家查詢，往後會開發使用者介面和更多統計工具及表單。具及表單。
5. sql_command.py 為爬取數據到資料庫的指令，可參考。

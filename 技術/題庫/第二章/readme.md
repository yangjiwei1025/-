# 2.作業系統與應用程式安全

### 2.1作業系統安全

### 2.1作業系統安全
```
作業系統安全機制
攻擊作業系統:模式
強化作業系統安全
```
```
windows security
Windows Server 2019 Automation with Powershell Cookbook - Third Edition
英文/Lee, Thomas/Packt Publishing出版日期：2019-02-28

Windows Server 2019 Active Directory 建置實務
繁體中文/戴有煒/碁峰資訊出版日期：2019-12-25

Windows Server 2019 系統與網站建置實務
繁體中文/戴有煒/碁峰資訊出版日期：2019-09-03
```
```
https://www.microsoft.com/zh-tw/windows-server/trial
Mastering Windows Security and Hardening
Secure and protect your Windows environment from intruders, 
malware attacks, and other cyber threats
By Mark Dunkerley , Matt Tumbarello
Packt Publishing
2020-07-08
```
```
https://www.packtpub.com/product/mastering-windows-security-and-hardening/9781839216411
Microsoft Defender 防毒軟體
Microsoft Defender 防毒軟體提供全面、持續不斷且即時的保護，
對抗電子郵件、應用程式、雲端和網站上的軟體威脅，
例如病毒、惡意程式碼和間諜軟體。
Microsoft 安全掃描工具
2020/03/20
https://docs.microsoft.com/zh-tw/windows/security/threat-protection/intelligence/safety-scanner-download
linux Security
惡意網絡環境下的Linux防御之道 
Linux Hardening in Hostile Networks: 
Server Security from TLS to Tor (Pearson Open Source Software Development Series)
Kyle Rankin 李楓譯
人民郵電  2020-10-01
https://www.tenlong.com.tw/products/9787115544384?list_name=srh
雙因認證(Two-Way Factor)
```
```
[114]雙因認證(Two-Way Factor)可以防止下列何者攻擊?
(A)阻斷式服務攻擊    (B)SQL 資料隱碼攻擊
(C)密碼側錄攻擊      (D)中間人攻擊
```
C
```
作業系統理論
[14]當某一作業系統中的兩個程式因互相搶用資源而造成兩個程式均無法完成既定工作之結果，請問此現象稱為？ 
(A) 碰撞（Collision） (B) 死結（Deadlock） (C) 佇列（Queue） (D) 欺騙（Spoof） 
```
B
```
死結的四個條件是：
1.禁止搶占（no preemption）：系統資源不能被強制從一個行程中退出。
2.持有和等待（hold and wait）：一個行程可以在等待時持有系統資源。
3.互斥（mutual exclusion）：資源只能同時分配給一個行程，無法多個行程共享。
4.循環等待（circular waiting）：一系列行程互相持有其他行程所需要的資源。
```

```
[15]請問 ssh 公私鑰存在 Linux 哪個目錄？ 
(A) /.ssh (B) /home (C) /etc (D) user 
```
A
```
[66]公司某部門有台 Windows 10 的電腦，允許所有部門員工登入使用，但 基於安全性考量，
除了管理員之外，希望能夠禁止一般員工在此電腦 上使用 USB 行動碟，
請問管理員應利用何種工具完成此項安全性需求 作業？ 
(E) 本機群組原則 (F) 磁碟重組工具 (G) 行動裝置管理員 (H) 具有進階安全性的 Windows 防火牆 
```
A
```
群組原則 Group Policy
群組原則是微軟Windows NT家族作業系統的一個特性，它可以控制使用者帳戶和電腦帳戶的工作環境。
群組原則提供了作業系統、應用程式和Active Directory中使用者設定的集中化管理和組態。

群組原則的其中一個版本名為 本機群組原則 ，這可以在獨立且非域(Domain)的電腦上管理群組原則物件

6 Ways to Open Local Group Policy Editor in Windows 10
https://www.top-password.com/blog/open-local-group-policy-editor-in-windows-10/
GroupPolicyEditor.png
```
```
[16]下列何項 Windows 功能可以封鎖未經授權之應用程式的自動安裝，
並防止不小心變更系統的設定。即使系統管理員執行系統管理過程亦須
要由管理員主動同意或提供認證資訊才能執行？  
(A) 具有進階安全性的 Windows 防火牆 (B) 使用者帳戶控制（User Account Control；UAC） 
(C) 資源監視器（Resource Monitor） (D) Windows Secondary Logon
```
B
```
使用 UserAccountControl 旗標來操縱使用者帳戶屬性 2020/09/08
https://docs.microsoft.com/zh-tw/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
網路身分驗證服務
[17]下列何者非登入作業系統可使用的網路身分驗證服務？ 
(A) Windows AD（Active Directory）服務 
(B) LDAP（Lightweight Directory Access Protocol）服務 
(C) NIS（Network Information Service）服務 
(D) DHCP（Dynamic Host Configuration Protocol）服務
```
D
```
Windows AD（Active Directory）

LDAP（Lightweight Directory Access Protocol）
https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol

1.輕型目錄存取協定（英文：Lightweight Directory Access Protocol，縮寫：LDAP）
2.是一個開放的，中立的，工業標準的應用協定，
3.通過IP協定提供存取控制和維護分散式資訊的目錄資訊。
4.LDAP的一個常用用途是  單一登入(SSO Single sign on)，
用戶可以在多個服務中使用同一個密碼，通常用於公司內部網路站的登錄中
（這樣他們可以在公司電腦上登入一次，便可以自動在公司內部網路上登入）。
5.LDAP基於X.500標準的子集。因為這個關係，LDAP有時被稱為X.500-lite。
6.標準通訊埠： 389， 636
```
```
[63]基於系統安全的基礎，系統管理者對所管理的伺服器（包含：應用程 式、平台、資料庫等）
應進行相關安全性設定，下列敘述何者正確？ 
(A) 系統上線後仍保留預設帳戶 
(B) 使用系統預設開啟的連接埠 
(C) 錯誤訊息應開放詳細資訊以便問題修正 
(D) 過期的 OS、Web / App Server、DBMS、API、函式庫等，應評估並進行更新 
```
D
```
[67]下列何者不是微軟 Windows 作業系統中，具特權權限之帳號？ 
(A) Administrator (B) root (C) 在 Administrators 群組中之一般使用者帳號 (D) Local System 
```
```
root --> linux 的最高權限
```
B
```
[64]當作業系統安裝好之後，為了避免因為安全因素導致作業系統遭受駭客入侵，應採取下列何項措施較佳？ 
(A) 更新病毒碼 (B) 更新修補程式 (C) 更新防火牆設定 (D) 更新入侵偵測系統 
```
B
```
Windows patch修補程式
查詢你的Windows裝了哪些的Patch
```
```
[119]請問下列何者「並非」作業系統中毒的可能徵狀?
(A) 檔案無故遭加密
(B) 上網速度變慢或無法連線
(C) 無故出現對話框,且無法關閉
(D) 資料讀取速度變快
```
D
```
[116]下列何者實務做法對於強化作業系統本身保護,降低被攻擊風險並沒有太大的效益?
(A) 定期自動更新
(B) 啟用預設拒絶政策的系統防火牆
(C) 啟用 IPSec 服務
(D) 安裝並更新防毒軟體
```
C
```
IPSec
https://zh.wikipedia.org/zh-tw/IPsec

1.網際網路安全協定（英語：Internet Protocol Security，縮寫：IPsec）
2.是一個協定套件，透過對IP協定的封包進行 加密 和 認證 來保護IP協定的網路傳輸協定族（一些相互關聯的協定的集合）
3.IPsec主要由以下協定組成：
一、認證頭（AH），為IP資料報提供無連接資料 完整性、訊息認證以及 防重放攻擊保護；
二、封裝安全載荷（ESP），提供機密性、資料來源認證、無連接完整性、防重放和有限的傳輸流（traffic-flow）機密性；
三、安全關聯（SA），提供演算法和封包，提供AH、ESP操作所需的參數。

https://kkc.github.io/2018/03/21/IPSEC-note/
```
```
[117]下列何者不屬於作業系統安全預防(Preventive)機制?
(A) 實施密碼原則       (B) 安裝防毒軟體
(C) 定期套用安全性更新  (D) 定期檢視安全記錄檔(Log)
```
D
```
作業系統 資訊安全策略:
[21]請問針對作業系統訂定的資訊安全策略中，
下列何種安全模式中「檔案持有者」可授權決定「其他使用者」存取該檔案的權限？ 
(A) 自由存取控制（Discretionary Access Control，DAC） 
(B) 強制性存取控制（Mandatory Access Control，MAC） 
(C) 角色存取控制（Role-based Access Control，RBAC） 
(D) 屬性存取控制（Attribute-based Access Control，ABAC）
```
A
```
自由存取控制（Discretionary Access Control，DAC）

它是根據主體（如用戶、進程或 I/O 設備等）的身份和他所屬的組限制對客體的訪問。所謂的自主，是因為擁有訪問權限的主體，可以直接（或間接）地將訪問權限賦予其他主體（除非受到強制存取控制的限制）。

強制性存取控制（Mandatory Access Control，MAC） 

在電腦安全領域指一種由作業系統約束的存取控制，目標是限制主體或發起者存取或對物件或目標執行某種操作的能力。

角色存取控制（Role-based Access Control，RBAC） 

一種較新且廣為使用的存取控制機制，其不同於強制存取控制以及自由選定存取控制[3]直接賦予使用者權限，而是將權限賦予角色。

屬性存取控制（Attribute-based Access Control，ABAC） 

用戶現在可以在AWS對話（Session）中傳遞使用者屬性，把外部身份系統中定義的屬性，用作AWS內部ABAC的一部分。
```
```
[71]請問針對作業系統訂定的資訊安全策略中，下列何種安全模式是統一由管理者進行檔案存取授權後，
使用者才可以進行檔案存取？ 
(A) 自由存取控制（Discretionary Access Control，DAC） (B) 強制存取控制（Mandatory Access Control，MAC） 
(C) 角色存取控制（Role-based Access Control，RBAC） (D) 屬性存取控制（Attribute-based Access Control，ABAC） 
```
B
```
作業系統: 常用指令 nslookup netstat
[115]請問此 cat ~/.bash_history 指令的目的為?
(A) 列出使用者目錄
(B) 列出系統目錄
(C) 列出使用者曾經下過的指令
(D) 列出系統安裝歷史
```
C
```
[118]黑帽駭客(Black Hats)入侵前,收集資訊常用的指令 nslookup,下列何者不是其目的?
(A) 可以用來掃描已開啟的 TCP/UDP Port   (B) 可以用來診斷 DNS 的架構
(C) 可以用來查詢網路網域名稱伺服器       (D) 如果以 DNS 的名稱,尋找主機 IP 位址
```
A
```
[65]下列何者並非攻擊者入侵主機後，常見使用來下載外部後門的指令？ 
(A) PING (B) WGET (C) CURL (D) FTP
```
A
```
攻擊作業系統 Rootkit
[22]用在入侵和攻擊他人的電腦系統上，取得系統管理員的權限，具有隱藏和遠端操控的能力；
電腦病毒、間諜軟體等也常使用來隱藏蹤跡。 
該工具軟體為？ (A) Cookie (B) Rootkit (C) Backdoor (D) Phishing 
```
B
```
[80]下列哪些是 rootkits 的主要特性？ 
(1)讓駭客取得最高權限 (2)具隱藏性 (3)在系統內大量自我複製 (4)讓駭客執行遠端控制 
(E) (1)(2)(3) (F) (1)(2)(4) (G) (2)(3)(4) (H) (1)(2)(3)(4) 
```
B
```
[28]請問 2017 流行的 wannacry 攻擊是攻擊哪個服務？ (A) SMB (B) SMTP (C) HTTP (D) FTP
```
A
```
2.2作業系統與應用程式 (含資料庫與網頁)攻擊手法
網站安全之網站攻擊手法分析
[18]關於資安組織 OWASP（開放 Web 軟體安全計畫—Open Web Application Security Project），下列敘述何者不正確？ 
(A)是一個開放社群、營利性組織 (B)主要目標是研議協助解決 Web 軟體安全之標準、工具與技術文件 
(C)長期協助政府或企業暸解並改善網頁應用程式與網頁服務的安全性 
(D)美國聯邦貿易委員會（FTC）強烈建議所有企業需遵循 OWASP 所發佈的十大 Web 弱點防護守則 
```
A
```
[70]下列何者不是網頁攻擊手法？ 
(A) Cross-Site Scripting (B) SQL Injection (C) Parameterized Query (D) Cross-Site Request Forgery 
```
C
```
[68]有一種資安風險的描述為： 「因為開發者暴露了內部檔案、檔案夾、金鑰、或資料庫的紀錄，來作為 URL 或是 Form 的參數，
使攻擊者可藉 由操作這些參數擅自進入其他 Objects 中」。此為下列何項風險的描述？ 
(A) 跨站腳本攻擊（Cross-Site Scripting） (B) API 未受防護（Underprotected APIs） 
(C) 注入攻擊（Injection） (D) 無效的存取控制（Broken Access Control）
```
D
```
[75]HTTP Cookie 的用途是？ 
(A) 在瀏覽器中儲存資訊（如 Session ID 等） (B) 瀏覽器的設定檔 
(C) 幫助防禦 XSS 攻擊 (D) 幫助防禦 XML Injection 攻擊
```
A
```
[中級16.(複選題)] 
網頁瀏覽器的 Cookies 並未使用加密保護機制,因此網站設計者為圖下次登入方便性,
如果將使用者帳密儲存在 Cookie 之中,此種安全漏洞可以讓駭客使用哪些網頁攻擊手法取得Cookie中機敏資料?
(A)SQL Injection    (B)XSS(Cross-Site Scripting)
(C)Google-hacking    (D)CookieSpy
```
BD
```
[中級17.(複選題)] 
透過安全設定 HTTP Header 標頭,能夠使瀏覽器進行相關的限制,
讓網站與使用者瀏覽器之間有更多的安全防護。下列哪些 HTTPHeader 標頭可達上述功能?
(A)HTTP Strict Transport Security    (B)X-Frame-Options
(C)Access-Control-Max-Age            (D)Accept-Encoding
```
AB
```
資料隱碼攻擊(SQL Injection)
[19]下列何者不是常見的 SQL Injection 自動化工具？ 
(A) BEEF Framework (B) SQLMAP (C) BSQL (D) Bobcat 
```
A
```
[24]請問防禦 SQL Injection 的最佳方式為下列何者？ 
(A) 黑名單過濾 (B) 參數長度過濾 (C) 輸出過濾 (D) Prepared Statement
```
D
```
[121]SQL 資料隱碼攻擊(SQL Injection)的攻擊技術主要會發生的原因,是利用下列何者?
(A) 利用系統漏洞對系統造成危害
(B) 程式開發者的疏忽,未對使用者的輸入進行過濾與檢查
(C) 資料庫存取權限設定錯誤所造成
(D) 遭受到駭客運用社交工程及惡意程式攻擊
```
B
```
[69]下列何者不是 Blind SQL Injection 的特性？ 
(A) SQL 錯誤資訊會顯示在頁面中 (B) SQL 錯誤資訊不會顯示在頁面中 
(C) 常利用 wait for delay 語法來測試 (D)常與 Time base SQL injection 一起發生 
```
A
```
[25]下列哪種方法可讓開發人員發現其撰寫的網頁程式碼是否存有輸入驗證漏洞（Input Validation Weaknesses）？ 
 (A) 反組譯應用程式執行碼 (B) 迴歸測試（Regression Testing） 
 (C) 模糊測試（Fuzz Testing） (D) 使用除錯器（Debugger）逐步執行檢視 
 ```
C
```
[中級10.(單選題)] 
在日常檢查時發現 10.10.1.1 (web),10.10.1.2 (db)發現入侵警訊風險如附圖內容所示時,請問第一步應該做?
2018/07/07 src:199.199.199.1 dst:10.10.1.1 oooo.php?id=’ or 1=1—xp_cmd_shell(...)?
(A)檢查 10.10.1.2 是否有被加入額外帳號    (B)檢查 10.10.1.1 是否有其他的備份資料
(C)立即通報 N-ICST                       (D)立即進行系統還原
```
A
```
跨站腳本攻擊（Cross-Site Scripting, XSS）
[120]請問下列何者不是 XSS(Cross-Site Scripting)攻擊語法?
(A)<script>alert(‘xss’);</script>
(B) +alert(‘xss’)+
(C) ’ or 1=1--
(D)<IMG SRC=javascript:alert('XSS')>
```
C
```
[10]關於跨站腳本攻擊（Cross-Site Scripting, XSS），下列敘述何者正確？  
(A) 過濾雙引號之符號 (B) 使用 URL Encode (C) 使用正規表達式 (D) 使用 HTML Encode 
```
D
```
[20]下列何者不是 Server-side Injection 攻擊手法？ 
(A) Blind SQL Injection (B) Hibernate Injection (C) Command Injection (D) XSS Injection
```
D
```
[74]下列何者為防禦（Cross-Site Scripting, XSS）的最佳方式？ 
(A) 輸入參數黑名單過濾 (B) 輸入參數白名單過濾 (C) 輸入參數長度過濾 (D) 輸出頁面過濾
```
B
```
[23]我們都知道要防止 XSS 跨網站指令碼攻擊必須過濾特殊字元，請問下 列何者不是我們應該過濾的特殊字元？ 
(A) # (B) & (C) “ (D) || 
```
D
```
[72]攻擊者針對網站應用程式漏洞，將 HTML 或 Script 指令插入網頁中， 造成使用者瀏覽網頁時，執行攻擊者惡意製造的網頁程式。
以上是說明哪一種攻擊手法？ (A) 資料隱碼攻擊（SQL injection） (B) 跨站請求偽照（Cross-Site Request Forgery, CSRF） 
(C) 跨網站腳本攻擊（Cross-Site Scripting, XSS） (D) 搜尋引擎攻擊（Google Hacking） 
```
C
```
[中級9.(單選題)] 
在網站弱點檢測報告中,發現系統本身有存在 XSS 及 OpenRedirect 問題,
可以採取下列何者方案進行修補?
(A)XSS 可以透過過濾此符號”<”,即可根治
(B)Open Redirect 可以採用圖像式驗證即可根治
(C)HTML.Encode 是可以解決 XSS 的一種方法
(D)採用 Prepared Statement 可以解決 XSS
```
C
```
跨站請求偽照（Cross-Site Request Forgery, CSRF）
[73]關於跨站請求偽造（Cross-Site Request Forgery, CSRF），下列何者是最佳的解決辦法？ 
(A)加入HttpOnly  (B)過濾不必要特殊字元   (C)加入圖形驗證碼  (D)使用 HTTPS
```
C
```
[26]網頁中使用驗證碼(CAPTCHA)主要可防禦下列何種攻擊？ 
(A) SQL 注入攻擊(Injection)。 (B) 跨站腳本攻擊(XSS)。 
(C) 緩衝區易位攻擊(Buffer Overflow)。 (D) 跨站偽造請求攻擊(CSRF)
```
D
```
OWASP TOP 10漏洞
[中級7.(單選題)] 
關於 XML External Entity(XXE)Injection 的防護,下列防護機制何者較佳?
(A)使用 HTTPS 安全連線
(B) 使用合法憑證進行雙向(伺服器端與使用者端)之身分驗證
(C) 禁止 DTD(Document Type Define)引用外部實體
(D)使用 SHA-3(Secure Hash Algorithm 3)進行計算
```
C
```
[中級15.(單選題)]  
在 OWASP Top 10 2017 中,其 A9 項目說明使用含有已知漏洞的元件。
而在軟體開發時,為減少 A9 項目的發生,下列何種作法為佳?
(A)限制可以使用的元件   (B)使用強的加密演算法
(C)使用入侵防禦系統     (D)限制使用的網路埠
```
A
```
webshell 網站木馬
[中級1.(單選題)] 
在駭客工具中,常見到中國菜刀(China Chopper)或相似工具其主要手法為?
(A)通過向網站提交一句簡短的程式碼,來達到向伺服器插入木馬,並最後獲取 webshell
(B)針對網站,建立一個連接,以很低的速度發包,並保持住這個連接不斷開,最後將可用的連線佔滿
(C)客戶使用主機 M 訪問並登錄合法網站 webA 後,再去訪問惡意網站 webB,
然後惡意網站 webB 冒充該客戶透過使用者主機 M 去向網站 webA 發起請求
(D)使用不安全的反序列化漏洞,利用遠端執行任意程式碼進行注入攻擊
九年後「中國菜刀」依然鋒利：China Chopper三起攻擊案例分析
https://kknews.cc/zh-tw/news/kl4gj5q.html
這五款工具被全球黑客廣泛使用，中國菜刀入榜
2018-11-27 由 新無止競 發表于資訊

近期，由美國、英國、澳大利亞、加拿大和紐西蘭的情報機構組成的五眼聯盟(Five Eyes)發布了一份報告，
該報告針對全球發生的網絡安全事件進行研究之後發現有五款公開的黑客工具被惡意利用地最頻繁，
並同時給企業和國家發出警告，提醒做好防範措施。

1.遠程訪問木馬: JBiFrost
2.Webshell: China Chopper
3.憑證竊取工具: Mimikatz
4.橫向移動工具: PowerShell Empire
5.命令和控制混淆及滲透工具: HUC 數據發包器


原文網址：https://kknews.cc/news/q6kvbgr.html
A
```
```
資料庫安全[Database Security]
[122]針對資料庫要進行事前告警、及時發現,以及事後分析追查可能的異常存取資安事件,該導入哪種資料庫安全防護措施?
(A) 資料庫加密    (B) 資料庫叢集    (C) 資料庫稽核   (D) 資料庫掃描
```
C
```
2.3 程式與開發安全
[77]下列何者不是 Windows 安全開發必須注意的地方？ 
(A) Socket 設計 (B) 多執行緒設計 (C) 常駐程式設計 (D) 封包流量設計 
```
D
```
[125]程式碼簽署(Code Signing)無法提供以下哪一項功能?
(A) 確認軟體開發者的身份
(B) 防止程式碼被篡改
(C) 用戶端認證
(D) 程式碼執行時期的合法性識別
```
C
```
[128]關於原始碼漏洞修補,下列敘述何者不正確?
(A) 所有類型的原始碼漏洞,均可找到對應的弱點掃描方法
(B) 未經驗證的使用者參數,均應加以驗證
(C) SQL Injection 的源頭可能來自於 Web 頁面,亦可能來自資料庫本身資料
(D) XSS 的源頭可能來自於瀏覽器的 Document Object Model
```
A
```
通用漏洞評分系統(Common Vulnerability Scoring System,CVSS)
[中級2.(單選題)] 
通用漏洞評分系統(Common Vulnerability Scoring System,CVSS)
是一個可衡量漏洞嚴重程度的公開標準。
CVSSv3 以基本指標群(Base metric group)、暫時指標群(Temporal metric group)及
環境指標群(Environmental metric group)等 3 個群組來進行判斷。
```
```
關於基本指標群,下列何者「不」是其考量因素?
(A)機密性衝擊(Confidentiality Impact)
(B)攻擊途徑(Attack Vector)
(C)攻擊複雜度(Attack Complexity)
(D)可靠性衝擊(Reliability Impact)
```
D
```
漏洞評鑑系統(Common Vulnerability Scoring System；CVSS) 由美國國家基礎建設諮詢委員會 (NIAC) 委託製作，是一套公開的評鑑標準，經常被用來評比企業資訊科技系統的安全性，並受到eBay、賽門鐵克(Symantec)、思科(Cisco)、甲古文(Oracle)等眾多軟體廠商支援。
由於CVSS是運用數學方程式來判定某特定網路的安全性是否存在弱點，普遍被認為較具中立性。CVSS的判定標準，不但包含威脅的嚴重性，遠端網路是否能遙控資安漏洞、利用網路弱點，攻擊者是否需要登入才會產生威脅等等，都被列入評比。
CVSS的評分分數從0分到10分，0代表沒有發現弱點，而10則代表最高風險。
https://www.digitimes.com.tw/tech/dt/n/shwnws.asp?cnlid=10&id=0000100727_WBC8XRHR1Y3H1O8HWCHDQ

官方網址  https://www.first.org/cvss/
```
```
逆向工程（Reverse Engineering）
[76]安全性測試人員可以使用反組譯器（Disassemblers）、除錯器 （Debuggers）
和反編譯器（Decompilers）來判斷與檢查，是否存在何種程式碼的弱點？ 
(A) 缺乏逆向工程（Reverse Engineering）保護 (B) 注入缺失（注射缺陷） 
(C) 跨網站指令碼（Cross-Site Scripting） (D) 不安全的物件參考（Insecure Direct Object Reference） 
```
A
```
[127]關於逆向工程,下列敘述何者正確?
(A) 從組合語言恢復高階語言的結構與語法過程
(B) 從機器語言恢復高階語言的結構與語法過程
(C) 從高階語言恢復組合語言的結構與語法過程
(D) 從高階語言恢復機器語言的結構與語法過程
```
B
```
行動程式開發安全性
[130]下列對行動碼(Mobile code),下列敘述何者不正確?
(A) 通常不具傷害性
(B) 可在不同作業系統之間執行
(C) 可在不同瀏覽器上順利執行
(D) 無法從遠端系統傳到本地端執行
```
D
```
[124]Android 系統的核心層級應用程式沙箱(Sandbox)是以何種方式來提供安全性?
(A) 每個應用程序指定唯一的使用者識別碼(UID),並執行於獨立的處理程序中
(B) 於非特權群組識別碼(GID)下執行所有應用程式
(C) 限制核心處理程序進行非法讀取
(D) 防止任何未經授權的核心處理程序執行
```
A
```
程式開發安全性 SSDLC
[126]下列何者為目前撰寫安全程式碼的知名的業界參考指引?
(A) NIST SP 800 系列
(B) OWASP 指南
(C) FIPS 系列
(D) ISO22301 相關標準
```
B
```
[27]下列何者屬於開發安全方面需注意的問題？ 
(A) 部署時必須考量伺服器效能，避免導致應用程式效能低 
(B) 應用程式設計必須設計多線程，用戶能對服務隨時存取 
(C) 應用程式必須考量是否有 SQL 注入漏洞 
(D) 應用程式必須考量 License 限制，避免出現無法部署其他伺服器
```
C
```
[123]安全的系統發展生命週期(Secure Software Development Life Cycle,SSDLC)意指發展一套安全系統的順序,
用以開發完善安全的資訊系統。以下哪個不是安全的系統發展生命週期階段?
(A) 設計
(B) 需求
(C) 估價
(D) 開發
```
C
```
[中級3.(單選題)] 
關於安全軟體發展生命週期(Security Software DevelopmentLifecycle, SSDLC),
下列敘述何者正確?
(A)可區分為需求階段、設計階段、開發實作階段、測試階段以及部署維運階段
(B)可區分為 UI/UX 階段、設計階段、開發實作階段、測試階段以及部署維運階段
(C)可區分為需求階段、設計階段、測試階段、以及部署維運階段
(D)可區分為 UI/UX、設計階段、測試階段以及部署維運階段
```
A









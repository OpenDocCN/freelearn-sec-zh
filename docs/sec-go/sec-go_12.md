# 第十二章：社会工程学

社会工程学是指攻击者操纵或欺骗受害者执行某些操作或提供私人信息。这通常通过冒充受信任的人、制造紧迫感或构造虚假理由迫使受害者行动。受害者的行动可能是简单的信息泄露，也可能是更复杂的操作，如下载并执行恶意软件。

本章讨论了蜜罐，尽管它们有时是为了欺骗机器人而非人类。其目标是故意进行欺骗，这正是社会工程学的核心。我们提供了基本的蜜罐示例，包括 TCP 和 HTTP 蜜罐。

本书未涉及许多其他类型的社会工程学。这包括一些现场或面对面的情况，比如尾随进入和冒充维修人员，以及其他数字和远程方法，如电话、短信和社交媒体消息。

社会工程学在法律上可能是一个灰色地带。例如，即使公司授权你对其员工进行社会工程学攻击，也不代表你有权限进行网络钓鱼攻击以窃取员工个人邮件的凭证。要注意法律和道德的边界。

在本章中，我们将特别讨论以下主题：

+   使用 Reddit 的 JSON REST API 收集关于个人的信息

+   使用 SMTP 发送网络钓鱼邮件

+   生成二维码和将图像进行 base64 编码

+   蜜罐

# 通过 JSON REST API 收集信息

带有 JSON 的 REST 已成为 Web API 的事实标准接口。每个 API 都不同，因此本示例的主要目的是展示如何处理来自 REST 端点的 JSON 数据。

本示例将 Reddit 用户名作为参数，并打印该用户的最新帖子和评论，以了解他们讨论的话题。选择 Reddit 作为示例是因为某些端点不需要认证，便于测试。其他提供 REST API 的服务，如 Twitter 和 LinkedIn，也可以用于收集信息。

请记住，本示例的重点是提供一个解析来自 REST 端点的 JSON 示例。由于每个 API 都不同，因此此示例应作为编写自己的程序与 JSON API 交互时的参考。必须定义一个数据结构来匹配 JSON 端点的响应。在本例中，创建的数据结构与 Reddit 的响应匹配。

在 Go 中处理 JSON 时，你首先需要定义数据结构，然后使用 `Marshal` 和 `Unmarshal` 函数在原始字符串和结构化数据格式之间进行编码和解码。以下示例创建了一个与 Reddit 返回的 JSON 结构匹配的数据结构。然后使用 `Unmarshal` 函数将字符串转换为 Go 数据对象。你不需要为 JSON 中的每一项数据创建变量，可以省略不需要的字段。

JSON 响应中的数据嵌套了许多层级，因此我们将使用匿名结构体。这可以避免我们为每个嵌套层级创建一个单独命名的类型。这个示例创建了一个命名结构体，所有嵌套层级都作为嵌入的匿名结构体存储。

Go 数据结构中的变量名与 JSON 响应中提供的变量名不匹配，因此在结构体定义的数据类型后面提供了 JSON 变量名。这允许将变量从 JSON 数据正确映射到 Go 结构体中。这通常是必要的，因为 Go 数据结构中的变量名是区分大小写的。

请注意，每个网站服务都有自己的服务条款，这些条款可能限制或约束你访问其网站的方式。有些网站禁止抓取，其他网站则有访问频率限制。虽然这可能不是刑事犯罪，但服务提供商可能会因违反服务条款而封锁你的账户或 IP 地址。在与任何网站或 API 互动之前，一定要阅读其服务条款。

这个示例的代码如下：

```
package main

import (
   "encoding/json"
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "time"
)

// Define the structure of the JSON response
// The json variable names are specified on
// the right since they do not match the
// struct variable names exactly
type redditUserJsonResponse struct {
   Data struct {
      Posts []struct { // Posts & comments
         Data struct {
            Subreddit  string  `json:"subreddit"`
            Title      string  `json:"link_title"`
            PostedTime float32 `json:"created_utc"`
            Body       string  `json:"body"`
         } `json:"data"`
      } `json:"children"`
   } `json:"data"`
}

func printUsage() {
   fmt.Println(os.Args[0] + ` - Print recent Reddit posts by a user

Usage: ` + os.Args[0] + ` <username>
Example: ` + os.Args[0] + ` nanodano
`)
}

func main() {
   if len(os.Args) != 2 {
      printUsage()
      os.Exit(1)
   }
   url := "https://www.reddit.com/user/" + os.Args[1] + ".json"

   // Make HTTP request and read response
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error making HTTP request. ", err)
   }
   defer response.Body.Close()
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading HTTP response body. ", err)
   }

   // Decode response into data struct
   var redditUserInfo redditUserJsonResponse
   err = json.Unmarshal(body, &redditUserInfo)
   if err != nil {
      log.Fatal("Error parson JSON. ", err)
   }

   if len(redditUserInfo.Data.Posts) == 0 {
      fmt.Println("No posts found.")
      fmt.Printf("Response Body: %s\n", body)
   }

   // Iterate through all posts found
   for _, post := range redditUserInfo.Data.Posts {
      fmt.Println("Subreddit:", post.Data.Subreddit)
      fmt.Println("Title:", post.Data.Title)
      fmt.Println("Posted:", time.Unix(int64(post.Data.PostedTime), 
         0))
      fmt.Println("Body:", post.Data.Body)
      fmt.Println("========================================")
   }
} 
```

# 通过 SMTP 发送钓鱼邮件

钓鱼攻击是指攻击者通过伪造的电子邮件或其他旨在看起来像来自可信来源的合法电子邮件的通讯方式，试图获取敏感信息的过程。

钓鱼攻击通常通过电子邮件进行，但也可以通过电话、社交媒体或短信进行。我们将重点讨论电子邮件方法。钓鱼攻击可以大规模进行，通常会向大量收件人发送一封通用的电子邮件，希望有人会上当。*尼日利亚王子*邮件骗局曾是一个流行的钓鱼攻击。其他提供奖励的邮件也很常见且相对有效，例如提供 iPhone 赠品或礼品卡，只要他们参与并点击你提供的链接并使用他们的凭据登录。钓鱼邮件还常常模仿合法发件人，使用真实的签名和公司徽标。通常会制造紧迫感，以说服受害者迅速行动，而不按标准程序操作。

你可以使用第十章中*网页抓取*的程序来收集电子邮件，该程序可以从网页中提取电子邮件。将电子邮件提取功能与提供的网页爬虫示例结合起来，你就可以得到一个强大的工具，用于从域名中抓取电子邮件。

**定向钓鱼攻击**是指针对少数目标，甚至可能是某个特定目标的钓鱼攻击。定向钓鱼需要更多的研究和定位，定制一封针对个人的电子邮件，创造一个可信的借口，或许还会冒充他们认识的人。定向钓鱼需要更多的工作，但它提高了欺骗用户的可能性，并降低了被垃圾邮件过滤器拦截的风险。

在进行网络钓鱼攻击时，你应该在制作邮件之前首先收集尽可能多的目标信息。本章早些时候提到过，使用 JSON REST API 来收集目标数据。如果你的目标个人或组织有网站，你还可以使用第十章中提到的词频计数程序和标题抓取程序，*网页抓取*。收集一个网站最常见的词汇和标题是快速了解目标所属行业或他们可能提供的产品和服务的方式。

Go 标准库包含一个用于发送邮件的 SMTP 包。Go 还提供了一个`net/mail`包用于解析邮件（[`golang.org/pkg/net/mail/`](https://golang.org/pkg/net/mail/)）。`mail`包相对较小，本书中未涉及，但它允许你将邮件的完整文本解析为一个消息类型，从而可以单独提取正文和头部信息。这个示例专注于如何使用 SMTP 包发送邮件。

配置变量都在源代码的顶部定义。请确保设置正确的 SMTP 主机、端口、发件人和密码。常见的 SMTP 端口是 `25` 用于未加密访问，端口 `465` 和 `587` 常用于加密访问。具体设置取决于你的 SMTP 服务器配置。此示例在没有先设置正确的服务器和凭据时无法正常运行。如果你有 Gmail 账户，可以重用大部分自动填充的值，只需要替换发件人和密码即可。

如果你使用 Gmail 发送邮件并启用了两步验证，你需要在[`security.google.com/settings/security/apppasswords`](https://security.google.com/settings/security/apppasswords) 创建一个特定的应用密码。如果你没有使用两步验证，那么请在[`myaccount.google.com/lesssecureapps`](https://myaccount.google.com/lesssecureapps) 启用不太安全的应用程序。

这个程序会创建并发送两封示例邮件，一封是文本邮件，另一封是 HTML 邮件。还可以发送一个合并的文本和 HTML 邮件，在这种情况下，邮件客户端会选择渲染哪个版本。可以使用`Content-Type`头设置为`multipart/alternative`，并设置边界来区分文本邮件和 HTML 邮件的起始和结束。发送合并的文本和 HTML 邮件不在此处讨论，但值得一提。你可以在[`www.w3.org/Protocols/rfc1341/7_2_Multipart.html`](https://www.w3.org/Protocols/rfc1341/7_2_Multipart.html)了解更多关于`multipart`内容类型的知识，*RFC 1341*。

Go 还提供了一个 `template` 包，允许你创建一个包含变量占位符的模板文件，然后用结构体中的数据填充这些占位符。如果你希望将模板文件与源代码分离，模板就非常有用，这样你可以在不重新编译应用程序的情况下修改模板。以下示例没有使用模板，但你可以在 [`golang.org/pkg/text/template/`](https://golang.org/pkg/text/template/) 阅读更多关于模板的内容：

```
package main

import (
   "log"
   "net/smtp"
   "strings"
)

var (
   smtpHost   = "smtp.gmail.com"
   smtpPort   = "587"
   sender     = "sender@gmail.com"
   password   = "SecretPassword"
   recipients = []string{
      "recipient1@example.com",
      "recipient2@example.com",
   }
   subject = "Subject Line"
)

func main() {
   auth := smtp.PlainAuth("", sender, password, smtpHost)

   textEmail := []byte(
      `To: ` + strings.Join(recipients, ", ") + `
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8";
Subject: ` + subject + `

Hello,

This is a plain text email.
`)

   htmlEmail := []byte(
      `To: ` + strings.Join(recipients, ", ") + `
Mime-Version: 1.0
Content-Type: text/html; charset="UTF-8";
Subject: ` + subject + `

<html>
<h1>Hello</h1>
<hr />
<p>This is an <strong>HTML</strong> email.</p>
</html>
`)

   // Send text version of email
   err := smtp.SendMail(
      smtpHost+":"+smtpPort,
      auth,
      sender,
      recipients,
      textEmail,
   )
   if err != nil {
      log.Fatal(err)
   }

   // Send HTML version
   err = smtp.SendMail(
      smtpHost+":"+smtpPort,
      auth,
      sender,
      recipients,
      htmlEmail,
   )
   if err != nil {
      log.Fatal(err)
   }
}
```

# 生成二维码

**快速响应**（**QR**）码是一种二维条形码。它存储的信息比传统的一维条形码要多。二维码最初是由日本汽车工业开发的，但已经被其他行业采纳。二维码于 2000 年被 ISO 批准为国际标准。最新的规范可以在 [`www.iso.org/standard/62021.html`](https://www.iso.org/standard/62021.html) 找到。

二维码可以在一些广告牌、海报、传单和其他广告材料上找到。二维码也常常用于交易中。你可能会在火车票上看到二维码，或者在发送和接收加密货币（如比特币）时使用二维码。一些身份验证服务，如双因素身份验证，也使用二维码以便于操作。

二维码对社交工程非常有用，因为人类无法仅凭外观判断二维码是否恶意。二维码通常包含一个立即加载的网址，这让用户面临风险。如果你创建一个可信的前提，可能会说服用户信任这个二维码。

本示例中使用的包叫做 `go-qrcode`，可以在 [`github.com/skip2/go-qrcode`](https://github.com/skip2/go-qrcode) 上找到。它是一个第三方库，托管在 GitHub 上，并非由 Google 或 Go 团队提供支持。`go-qrcode` 包利用了标准库的图像包：`image`、`image/color` 和 `image/png`。

使用以下命令安装 `go-qrcode` 包：

```
go get github.com/skip2/go-qrcode/...
```

`go get` 中的省略号（`...`）是一个通配符，它会安装所有子包。

根据包作者的说法，二维码的最大容量取决于编码的内容和错误恢复级别。最大容量为 2,953 字节、4,296 个字母数字字符、7,089 个数字字符，或它们的组合。

本程序展示了两个主要的内容。首先是如何生成二维码，以原始 PNG 字节的形式，然后将要嵌入 HTML 页面的数据进行 Base64 编码。生成完整的 HTML `img` 标签，并作为输出传递到标准输出，可以直接复制粘贴到 HTML 页面中。第二部分展示了如何简单地生成二维码并将其直接写入文件。

这个示例生成一个 PNG 图像格式的二维码。让我们提供你想要编码的文本和输出文件名作为命令行参数，程序将输出带有编码数据的二维码图像：

```
package main 

import (
   "encoding/base64"
   "fmt"
   "github.com/skip2/go-qrcode"
   "log"
   "os"
)

var (
   pngData        []byte
   imageSize      = 256 // Length and width in pixels
   err            error
   outputFilename string
   dataToEncode   string
)

// Check command line arguments. Print usage
// if expected arguments are not present
func checkArgs() {
   if len(os.Args) != 3 {
      fmt.Println(os.Args[0] + `

Generate a QR code. Outputs a PNG file in <outputFilename>.
Also outputs an HTML img tag with the image base64 encoded to STDOUT.

 Usage: ` + os.Args[0] + ` <outputFilename> <data>
 Example: ` + os.Args[0] + ` qrcode.png https://www.devdungeon.com`)
      os.Exit(1)
   }
   // Because these variables were above, at the package level
   // we don't have to return them. The same variables are
   // already accessible in the main() function
   outputFilename = os.Args[1]
   dataToEncode = os.Args[2]
}

func main() {
   checkArgs()

   // Generate raw binary data for PNG
   pngData, err = qrcode.Encode(dataToEncode, qrcode.Medium, 
      imageSize)
   if err != nil {
      log.Fatal("Error generating QR code. ", err)
   }

   // Encode the PNG data with base64 encoding
   encodedPngData := base64.StdEncoding.EncodeToString(pngData)

   // Output base64 encoded image as HTML image tag to STDOUT
   // This img tag can be embedded in an HTML page
   imgTag := "<img src=\"data:image/png;base64," + 
      encodedPngData + "\"/>"
   fmt.Println(imgTag) // For use in HTML

   // Generate and write to file with one function
   // This is a standalone function. It can be used by itself
   // without any of the above code
   err = qrcode.WriteFile(
      dataToEncode,
      qrcode.Medium,
      imageSize,
      outputFilename,
   )
   if err != nil {
      log.Fatal("Error generating QR code to file. ", err)
   }
} 
```

# Base64 编码数据

在前面的示例中，二维码是经过 base64 编码的。由于这是一个常见任务，因此值得介绍如何进行编码和解码。每当需要将二进制数据作为字符串存储或传输时，base64 编码非常有用。

这个示例展示了一个非常简单的用例，演示如何对字节切片进行编码和解码。进行 base64 编码和解码的两个重要函数是 `EncodeToString()` 和 `DecodeString()`：

```
package main

import (
   "encoding/base64"
   "fmt"
   "log"
)

func main() {
   data := []byte("Test data")

   // Encode bytes to base64 encoded string.
   encodedString := base64.StdEncoding.EncodeToString(data)
   fmt.Printf("%s\n", encodedString)

   // Decode base64 encoded string to bytes.
   decodedData, err := base64.StdEncoding.DecodeString(encodedString)
   if err != nil {
      log.Fatal("Error decoding data. ", err)
   }
   fmt.Printf("%s\n", decodedData)
} 
```

# Honeypots

Honeypots 是你设置的假服务，用来捕捉攻击者。你故意设置一个服务，目的是引诱攻击者，让他们误以为这个服务是真实的，并且包含某种敏感信息。通常，honeypot 会伪装成一个旧的、过时的且容易受到攻击的服务器。可以将日志记录或警报附加到 honeypot 上，以便快速识别潜在攻击者。在你的内部网络上设置 honeypot，可能会在任何系统被攻破之前就发现攻击者。

当攻击者攻破一台机器时，他们通常会利用这台被攻破的机器继续枚举、攻击和跳转。如果你的网络中的 honeypot 检测到来自网络中其他机器的异常行为，如端口扫描或登录尝试，这台表现异常的机器可能已经被攻破。

Honeypot 有许多不同种类。它可以是任何东西，从一个简单的 TCP 监听器，用来记录任何连接，一个带有登录表单字段的假 HTML 页面，或者一个完整的 Web 应用程序，看起来像是一个真实的员工门户。如果攻击者认为他们已经找到了一个关键应用程序，他们更可能花时间试图获取访问权限。如果你设置了诱人的 honeypot，可能会让攻击者花费大部分时间在一个无用的 honeypot 上。如果记录了详细的日志，你可以了解攻击者使用了哪些方法、他们拥有哪些工具，甚至可能知道他们的位置。

还有几种其他类型的 honeypot 值得一提，但在本书中没有演示：

+   **SMTP honeypot**：这模拟了一个开放的电子邮件中继，垃圾邮件发送者滥用它来捕捉试图使用你的邮件系统的垃圾邮件发送者。

+   **Web 爬虫 honeypot**：这些是隐藏的网页，通常不打算被人访问，但它们的链接隐藏在你网站的公共区域，如 HTML 注释中，用来捕捉蜘蛛、爬虫和抓取器。

+   **数据库 honeypot**：这是一个假数据库或真实数据库，通过详细的日志记录来检测攻击者，也可能包含假数据，以便观察攻击者对哪些信息感兴趣。

+   **Honeynet**：这是一个充满 honeypot 的整个网络，看起来像一个真实的网络，甚至可以自动化或伪造客户端流量到 honeypot 服务，以模拟真实用户。

攻击者可能能够识别出明显的蜜罐服务并避开它们。我建议你选择两个极端中的一个：让蜜罐尽可能模拟真实服务，或者让服务成为一个完全的黑箱，不向攻击者透露任何信息。

本节我们介绍一些非常基础的示例，帮助你理解蜜罐的概念，并为你提供创建自己定制蜜罐的模板。首先，展示了一个基础的 TCP 套接字蜜罐。它将监听一个端口，并记录任何连接和接收到的数据。为了配合这个示例，提供了一个 TCP 测试工具。它像一个原始版本的 Netcat，允许你通过标准输入向服务器发送单个消息。这可以用来测试 TCP 蜜罐，或者扩展并用于其他应用程序。最后一个示例是一个 HTTP 蜜罐。它提供一个登录表单，记录身份验证尝试，但总是返回错误。

确保你理解在网络中使用蜜罐的风险。如果你让蜜罐继续运行而没有保持底层操作系统的更新，那么你可能会给你的网络带来真正的风险。

# TCP 蜜罐

我们将开始的最简单的蜜罐是一个 TCP 蜜罐。它将记录收到的任何 TCP 连接和从客户端接收到的任何数据。

它会返回一个身份验证失败的消息。由于它会记录从客户端接收到的任何数据，因此会记录他们尝试使用的任何用户名和密码。通过检查他们尝试的身份验证方法，你可以了解他们的攻击方式，因为它就像一个黑箱，无法给出可能使用的身份验证机制的任何线索。你可以通过查看日志来判断他们是否将其当作 SMTP 服务器使用，这可能意味着他们是垃圾邮件发送者，或者他们可能尝试用数据库进行身份验证，表明他们在寻找信息。研究攻击者的行为可以为你提供很多见解，甚至能揭示你未曾意识到的漏洞。攻击者可能会在蜜罐上使用服务指纹工具，你可能能够识别出他们攻击方法中的模式，并找到阻止他们的方式。如果攻击者尝试使用真实用户凭证登录，那么该用户很可能已经被攻破。

这个示例将记录高层请求，如 HTTP 请求，以及低层连接，如 TCP 端口扫描器。TCP 连接扫描将被记录，但仅有 TCP `SYN`（隐匿）扫描不会被检测到：

```
package main

import (
   "bytes"
   "log"
   "net"
)

func handleConnection(conn net.Conn) {
   log.Printf("Received connection from %s.\n", conn.RemoteAddr())
   buff := make([]byte, 1024)
   nbytes, err := conn.Read(buff)
   if err != nil {
      log.Println("Error reading from connection. ", err)
   }
   // Always reply with a fake auth failed message
   conn.Write([]byte("Authentication failed."))
   trimmedOutput := bytes.TrimRight(buff, "\x00")
   log.Printf("Read %d bytes from %s.\n%s\n",
      nbytes, conn.RemoteAddr(), trimmedOutput)
   conn.Close()
}

func main() {
   portNumber := "9001" // or os.Args[1]
   ln, err := net.Listen("tcp", "localhost:"+portNumber)
   if err != nil {
       log.Fatalf("Error listening on port %s.\n%s\n",
          portNumber, err.Error())
   }
   log.Printf("Listening on port %s.\n", portNumber)
   for {
      conn, err := ln.Accept()
      if err != nil {
         log.Println("Error accepting connection.", err)
      }
      go handleConnection(conn)
   }
}
```

# TCP 测试工具

为了测试我们的 TCP 蜜罐，我们需要向它发送一些 TCP 流量。我们可以使用任何现有的网络工具，包括 Web 浏览器或 FTP 客户端来访问蜜罐。一个很好的工具是 Netcat，它是 TCP/IP 的瑞士军刀。不过，我们不使用 Netcat，而是创建我们自己的简单克隆。它将简单地通过 TCP 读取和写入数据。输入和输出将通过标准输入和标准输出进行，允许你使用键盘和终端，或者将数据管道输入或输出到文件和其他应用程序。

该工具可以作为一个通用的网络测试工具，如果你有任何入侵检测系统或其他需要测试的监控工具，它可能会很有用。这个程序将从标准输入中获取数据，并通过 TCP 连接发送，然后读取服务器返回的任何数据并将其打印到标准输出。当运行这个示例时，必须将主机和端口作为一个包含冒号分隔符的字符串传递，像这样：`localhost:9001`。以下是这个简单 TCP 测试工具的代码：

```
package main

import (
   "bytes"
   "fmt"
   "log"
   "net"
   "os"
)

func checkArgs() string {
   if len(os.Args) != 2 {
      fmt.Println("Usage: " + os.Args[0] + " <targetAddress>")
      fmt.Println("Example: " + os.Args[0] + " localhost:9001")
      os.Exit(0)
   }
   return os.Args[1]
}

func main() {
   var err error
   targetAddress := checkArgs()
   conn, err := net.Dial("tcp", targetAddress)
   if err != nil {
      log.Fatal(err)
   }
   buf := make([]byte, 1024)

   _, err = os.Stdin.Read(buf)
   trimmedInput := bytes.TrimRight(buf, "\x00")
   log.Printf("%s\n", trimmedInput)

   _, writeErr := conn.Write(trimmedInput)
   if writeErr != nil {
      log.Fatal("Error sending data to remote host. ", writeErr)
   }

   _, readErr := conn.Read(buf)
   if readErr != nil {
      log.Fatal("Error when reading from remote host. ", readErr)
   }
   trimmedOutput := bytes.TrimRight(buf, "\x00")
   log.Printf("%s\n", trimmedOutput)
} 
```

# HTTP POST 表单蜜罐

当你将这个程序部署到网络上时，除非进行有意的测试，否则任何表单提交都是一个警示信号。这意味着有人正在尝试登录到你的假服务器。由于没有合法的目的，只有攻击者才会有理由尝试获取访问权限。这里不会进行实际的身份验证或授权，只是一个伪装，让攻击者认为他们正在尝试登录。Go 的 HTTP 包在 Go 1.6 及以上版本中默认支持 HTTP 2。你可以在[`golang.org/pkg/net/http/`](https://golang.org/pkg/net/http/) 阅读有关 `net/http` 包的更多信息。

以下程序将充当一个具有登录页面的 Web 服务器，旨在将表单提交记录到标准输出。你可以运行此服务器，然后尝试通过浏览器登录，登录尝试将会打印到运行该服务器的终端中：

```
package main 

import (
   "fmt"
   "log"
   "net/http"
)

// Correctly formatted function declaration to satisfy the
// Go http.Handler interface. Any function that has the proper
// request/response parameters can be used to process an HTTP request.
// Inside the request struct we have access to the info about
// the HTTP request and the remote client.
func logRequest(response http.ResponseWriter, request *http.Request) {
   // Write output to file or just redirect output of this 
   // program to file
   log.Println(request.Method + " request from " +  
      request.RemoteAddr + ". " + request.RequestURI)
   // If POST not empty, log attempt.
   username := request.PostFormValue("username")
   password := request.PostFormValue("pass")
   if username != "" || password != "" {
      log.Println("Username: " + username)
      log.Println("Password: " + password)
   }

   fmt.Fprint(response, "<html><body>")
   fmt.Fprint(response, "<h1>Login</h1>")
   if request.Method == http.MethodPost {
      fmt.Fprint(response, "<p>Invalid credentials.</p>")
   }
   fmt.Fprint(response, "<form method=\"POST\">")
   fmt.Fprint(response, 
      "User:<input type=\"text\" name=\"username\"><br>")
   fmt.Fprint(response, 
      "Pass:<input type=\"password\" name=\"pass\"><br>")
   fmt.Fprint(response, "<input type=\"submit\"></form><br>")
   fmt.Fprint(response, "</body></html>")
}

func main() {
   // Tell the default server multiplexer to map the landing URL to
   // a function called logRequest
   http.HandleFunc("/", logRequest)

   // Kick off the listener using that will run forever
   err := http.ListenAndServe(":8080", nil)
   if err != nil {
      log.Fatal("Error starting listener. ", err)
   }
} 
```

# HTTP 表单字段蜜罐

在之前的示例中，我们讨论了创建一个假的登录表单来检测有人尝试登录。如果我们想要识别它是否是一个机器人呢？检测一个机器人是否试图登录的能力在生产站点中也很有用，可以用来阻止机器人。一种识别自动化机器人的方法是使用蜜罐表单字段。蜜罐表单字段是一个 HTML 表单中的输入字段，用户看不到它，并且在表单由人类提交时，应该是空的。机器人仍然会找到表单中的蜜罐字段并试图填写它们。

目标是让机器人认为表单字段是真实的，同时将其隐藏于用户之外。一些机器人会使用正则表达式查找诸如 `user` 或 `email` 这样的关键词，并只填写那些字段；因此，蜜罐字段通常使用诸如 `email_address` 或 `user_name` 的名称，看起来像一个正常的字段。如果服务器在这些字段中接收到数据，它可以认为表单是由机器人提交的。

如果我们在上一个示例中的登录表单中添加了一个名为`email`的隐藏表单字段，机器人可能会尝试填写它，而人类则看不到它。可以使用 CSS 或`input`元素上的`hidden`属性隐藏表单字段。我建议您使用单独的样式表中的 CSS 来隐藏蜜罐表单字段，因为机器人可以轻松确定表单字段是否具有`hidden`属性，但要检测输入是否使用样式表隐藏则更困难。

# 沙盒技术

本章未展示的相关技术之一但值得一提的是沙盒技术。沙盒技术与蜜罐有不同的目的，但它们都致力于创建一个看起来合法但实际上是严格控制和监控的环境。一个沙盒的例子是创建一个没有网络连接的虚拟机，记录所有文件更改和尝试的网络连接，以查看是否发生了可疑事件。

有时，可以通过查看 CPU 数量和内存来检测沙盒环境。如果恶意应用程序检测到系统资源很少，比如 1 个 CPU 和 1GB RAM，那么它很可能不是现代台式机，可能是沙盒。恶意软件作者已经学会了指纹识别沙盒环境，并编程使应用程序在怀疑在沙盒中运行时绕过任何恶意操作。

# 总结

阅读完本章后，你现在应该理解社会工程学的一般概念，并能提供一些示例。你应该理解如何使用 JSON 与 REST API 交互，生成 QR 码和 Base64 编码数据，以及使用 SMTP 发送电子邮件。你还应该能够解释蜜罐的概念，并理解如何为自己的需求实现或扩展这些示例。

你能想到哪些其他类型的蜜罐？哪些常见服务经常受到暴力破解或频繁攻击？你如何自定义或扩展社会工程学的示例？你能想到任何其他可以用于信息收集的服务吗？

在下一章中，我们将涵盖后渗透主题，如部署绑定 shell、反向绑定 shell 或 web shell；交叉编译；查找可写文件；以及修改文件时间戳、权限和所有权。

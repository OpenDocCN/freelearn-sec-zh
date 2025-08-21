# 第十章：网络抓取

从网络收集信息在许多场合下都非常有用。网站可以提供大量信息，这些信息可以用来帮助进行社会工程学攻击或钓鱼攻击。你可以找到潜在目标的姓名和电子邮件，或者收集关键词和标题，帮助快速理解网站的主题或业务。你还可以通过网页抓取技术，了解业务的地理位置，找到图片和文档，分析网站的其他方面。

了解目标有助于你创建一个可信的借口。借口（Pretexting）是攻击者用来欺骗毫无防备的受害者，诱使他们按照请求操作，从而损害用户、其账户或计算机的一种常见技巧。例如，有人研究了一家公司，发现它是一家大型公司，且在某个特定城市设有集中的 IT 支持部门。他们可以打电话或发邮件给公司的人，假装自己是技术支持人员，要求他们执行某些操作或提供密码。从公司的公共网站上获得的信息可能包含许多可以用来设立借口的细节。

网络爬虫是抓取的另一个方面，它涉及跟随超链接到其他页面。广度优先爬取指的是尽可能找到更多不同的网站并跟随它们，寻找更多的网站。深度优先爬取指的是爬取一个网站，找到所有可能的页面，然后再移动到下一个网站。

在本章中，我们将介绍网页抓取和网页爬取。我们将通过一些基本任务的示例，帮助你完成诸如查找链接、文档和图片，寻找隐藏文件和信息，使用一个强大的第三方包 `goquery`。我们还将讨论减少自己网站抓取的技巧。

在本章中，我们将特别介绍以下主题：

+   网络抓取基础

    +   字符串匹配

    +   正则表达式

    +   从响应中提取 HTTP 头部

    +   使用 cookies

    +   从页面中提取 HTML 注释

    +   搜索网页服务器上未列出的文件

    +   修改用户代理

    +   对网页应用程序和服务器进行指纹识别

+   使用 goquery 包

    +   列出页面中的所有链接

    +   列出页面中的所有文档链接

    +   列出页面的标题和标题标签

    +   计算页面中最常用的单词

    +   列出页面中的所有外部 JavaScript 源

    +   深度优先爬取

    +   广度优先爬取

+   防止网页抓取

# 网络抓取基础

本书中所说的网页抓取，是指从 HTML 结构化页面中提取信息的过程，这些页面是供人类查看的，而非供程序消费。一些服务提供了适合程序化使用的 API，但有些网站只提供 HTML 页面中的信息。这些网页抓取示例展示了从 HTML 中提取信息的不同方法。我们将从基本的字符串匹配开始，然后是正则表达式，最后是一个强大的名为`goquery`的网页抓取包。

# 使用 strings 包在 HTTP 响应中查找字符串

为了开始，我们先看一下如何使用标准库发起一个基本的 HTTP 请求，并查找字符串。首先，我们将创建`http.Client`并设置任何自定义变量；例如，客户端是否应该跟随重定向，应该使用哪些 cookie，或者使用什么传输。

`http.Transport`类型实现了执行 HTTP 请求并获取响应的网络请求操作。默认情况下，使用`http.RoundTripper`，它执行单个 HTTP 请求。对于大多数使用场景，默认的传输就足够了。默认情况下，环境中的 HTTP 代理会被使用，但代理也可以在传输中指定。如果你想使用多个代理，这可能会很有用。此示例未使用自定义的`http.Transport`类型，但我想强调的是，`http.Transport`是`http.Client`中的一个嵌入类型。

我们正在创建一个自定义的`http.Client`类型，但仅仅是为了重写`Timeout`字段。默认情况下，没有超时设置，应用程序可能会永远挂起。

另一个可以在`http.Client`中重写的嵌入类型是`http.CookieJar`类型。`http.CookieJar`接口要求的两个函数是：`SetCookies()`和`Cookies()`。标准库中包含了`net/http/cookiejar`包，并且它包含了`CookieJar`的默认实现。多个 cookie jar 的一个使用场景是登录并存储与网站的多个会话。你可以登录多个用户，将每个会话存储在一个 cookie jar 中，并按需使用它们。此示例未使用自定义 cookie jar。

HTTP 响应包含一个作为读取器接口的主体。我们可以使用任何接受读取器接口的函数从读取器中提取数据。这些函数包括`io.Copy()`、`io.ReadAtLeast()`、`io.ReadAll()`以及`bufio`缓冲读取器。在此示例中，使用`ioutil.ReadAll()`快速将 HTTP 响应的完整内容存储到字节切片变量中。

以下是此示例的代码实现：

```
// Perform an HTTP request to load a page and search for a string
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "strings"
   "time"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 3 {
      fmt.Println("Search for a keyword in the contents of a URL")
      fmt.Println("Usage: " + os.Args[0] + " <url> <keyword>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com NanoDano")
      os.Exit(1)
   }
   url := os.Args[1]
   needle := os.Args[2] // Like searching for a needle in a haystack

   // Create a custom http client to override default settings. Optional
   // Use http.Get() instead of client.Get() to use default client.
   client := &http.Client{
      Timeout: 30 * time.Second, // Default is forever!
      // CheckRedirect - Policy for following HTTP redirects
      // Jar - Cookie jar holding cookies
      // Transport - Change default method for making request
   }

   response, err := client.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Read response body
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading HTTP body. ", err)
   }

   // Search for string
   if strings.Contains(string(body), needle) {
      fmt.Println("Match found for " + needle + " in URL " + url)
   } else {
      fmt.Println("No match found for " + needle + " in URL " + url)
   }
} 
```

# 使用正则表达式在页面中查找电子邮件地址

正则表达式（regex）实际上是一种语言形式。本质上，它是一种表示文本搜索模式的特殊字符串。你可能熟悉在使用 shell 时的星号（`*`）。例如，命令`ls *.txt`使用了一个简单的正则表达式。在这种情况下，星号代表*任何东西*；所以只要字符串以`.txt`结尾，都会匹配。正则表达式除了星号外，还有其他符号，比如句点（`.`），它代表匹配任何单个字符，而星号则匹配任何长度的字符串。利用这些符号，还可以构建更强大的表达式。

正则表达式因其运行速度较慢而广为人知。所使用的实现方式保证了基于输入长度的线性时间运行，而非指数时间运行。这意味着它将比许多没有提供这种保证的正则表达式实现（如 Perl）运行得更快。Go 的作者之一 Russ Cox 在 2007 年发表了一篇深入比较这两种方法的文章，文章链接为[`swtch.com/~rsc/regexp/regexp1.html`](https://swtch.com/~rsc/regexp/regexp1.html)。这对于我们在 HTML 页面中搜索内容的应用场景至关重要。如果正则表达式以指数时间运行，基于输入长度，某些表达式的搜索可能字面上需要几年时间才能完成。

了解更多关于正则表达式的一般信息，请访问[`en.wikipedia.org/wiki/Regular_expression`](https://en.wikipedia.org/wiki/Regular_expression) 和相关的 Go 文档：[`golang.org/pkg/regexp/`](https://golang.org/pkg/regexp/)。

本示例使用了一个正则表达式，用于搜索嵌入在 HTML 中的电子邮件地址链接。它会搜索任何`mailto`链接并提取电子邮件地址。我们将使用默认的 HTTP 客户端，并调用`http.Get()`，而不是创建自定义客户端来修改超时设置。

一个典型的电子邮件链接看起来像这样：

```
<a href="mailto:nanodano@devdungeon.com">
<a href="mailto:nanodano@devdungeon.com?subject=Hello">
```

本示例中使用的正则表达式是：

`"mailto:.*?["?]`

让我们逐一分析并检查每个部分：

+   `"mailto:`：这一部分只是一个字符串字面量。第一个字符是一个引号（`" `），在正则表达式中没有特殊含义。它被当作普通字符对待。这意味着正则表达式将首先搜索一个引号字符。在引号后面是文本`mailto`和一个冒号（`:`），冒号也没有特殊含义。

+   `.*?`：句点（`.`）表示匹配除换行符之外的任何字符。星号表示根据前一个符号（句点）继续匹配零个或多个字符。星号后紧跟着一个问号（`?`）。这个问号告诉星号进行非贪婪匹配，它会匹配最短的字符串。如果没有问号，星号会尽可能匹配更长的字符串，同时仍然满足整个正则表达式。我们只想要电子邮件地址本身，而不是任何查询参数，比如`?subject`，所以我们让它进行非贪婪或短匹配。

+   `["?]`：正则表达式的最后一部分是`["?]`集合。方括号告诉正则表达式匹配方括号内的任何字符。我们这里只有两个字符：引号和问号。这里的问号没有特殊意义，视为普通字符。方括号内的两个字符是限定电子邮件地址结尾的两个可能字符。默认情况下，正则表达式会选择最后出现的字符，并返回最长的字符串，因为之前的星号会使其贪婪匹配。然而，由于我们在前一部分的星号后面紧接着添加了另一个问号，它会执行非贪婪匹配，并在找到第一个匹配方括号内字符的地方停止。

使用这种技术意味着我们只会找到通过 HTML 中的`<a>`标签显式链接的电子邮件地址。它不会找到页面中仅作为纯文本书写的电子邮件地址。创建一个基于模式如`<word>@<word>.<word>`的正则表达式来查找电子邮件字符串看似简单，但不同正则表达式实现之间的细微差别和电子邮件地址可能出现的复杂变化使得编写一个能捕获所有有效电子邮件组合的正则表达式变得困难。如果你在网上快速搜索一个例子，你会看到有多少种变化，以及它们是多么复杂。

如果你正在创建某种网络服务，验证用户的电子邮件账户非常重要，可以通过发送邮件让用户回复或通过某种方式验证链接来完成验证。我不建议你仅仅依靠正则表达式来判断电子邮件是否有效，我还建议你在使用正则表达式进行客户端电子邮件验证时要格外小心。用户可能有一个在技术上有效但很奇怪的电子邮件地址，而你可能会阻止他们注册你的服务。

这里有一些根据 1982 年发布的*RFC 822*标准实际上有效的电子邮件地址示例：

+   `*.*@example.com`

+   `$what^the.#!$%@example.com`

+   `!#$%^&*=()@example.com`

+   `"!@#$%{}^&~*()|/="@example.com`

+   `"hello@example.com"@example.com`

在 2001 年，*RFC 2822* 替代了 *RFC 822*。在所有前面的示例中，只有最后两个包含 `@` 符号的被新的 *RFC 2822* 视为无效。所有其他示例仍然有效。阅读原始 RFC 文档：[`www.ietf.org/rfc/rfc822.txt`](https://www.ietf.org/rfc/rfc822.txt) 和 [`www.ietf.org/rfc/rfc2822.txt`](https://www.ietf.org/rfc/rfc2822.txt)。

以下是该示例的代码实现：

```
// Search through a URL and find mailto links with email addresses
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "regexp"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Search for emails in a URL")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Read the response
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading HTTP body. ", err)
   }

   // Look for mailto: links using a regular expression
   re := regexp.MustCompile("\"mailto:.*?[?\"]")
   matches := re.FindAllString(string(body), -1)
   if matches == nil {
      // Clean exit if no matches found
      fmt.Println("No emails found.")
      os.Exit(0)
   }

   // Print all emails found
   for _, match := range matches {
      // Remove "mailto prefix and the trailing quote or question mark
      // by performing a slice operation to extract the substring
      cleanedMatch := match[8 : len(match)-1]
      fmt.Println(cleanedMatch)
   }
} 
```

# 从 HTTP 响应中提取 HTTP 头部

HTTP 头部包含有关请求和响应的元数据和描述性信息。通过检查服务器返回的 HTTP 头部，您可以潜在地了解有关服务器的很多信息。您可以从头部中了解以下内容：

+   缓存系统

+   认证

+   操作系统

+   Web 服务器

+   响应类型

+   框架或内容管理系统

+   编程语言

+   口语语言

+   安全头部

+   Cookie

不是每个 web 服务器都会返回所有这些头部，但了解尽可能多的头部信息是有帮助的。像 WordPress 和 Drupal 这样的流行框架会返回一个 `X-Powered-By` 头部，告诉您是 WordPress 还是 Drupal，并且会显示版本号。

会话 Cookie 也能泄露很多信息。一个名为 `PHPSESSID` 的 Cookie 表明它很可能是一个 PHP 应用程序。Django 的默认会话 Cookie 名为 `sessionid`，Java 的为 `JSESSIONID`，Ruby on Rail 的会话 Cookie 遵循 `_APPNAME_session` 模式。您可以利用这些线索对 web 服务器进行指纹识别。如果您只需要头部信息，而不需要页面的整个正文，您可以使用 HTTP `HEAD` 方法代替 HTTP `GET`。`HEAD` 方法将只返回头部信息。

这个示例向一个 URL 发出一个 `HEAD` 请求，并打印出所有的头部。`http.Response` 类型包含一个名为 `Header` 的字符串到字符串的映射，里面包含每个 HTTP 头部的键值对：

```
// Perform an HTTP HEAD request on a URL and print out headers
package main

import (
   "fmt"
   "log"
   "net/http"
   "os"
)

func main() {
   // Load URL from command line arguments
   if len(os.Args) != 2 {
      fmt.Println(os.Args[0] + " - Perform an HTTP HEAD request to a URL")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Perform HTTP HEAD
   response, err := http.Head(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Print out each header key and value pair
   for key, value := range response.Header {
      fmt.Printf("%s: %s\n", key, value[0])
   }
} 
```

# 使用 HTTP 客户端设置 Cookie

Cookie 是现代 web 应用程序的重要组成部分。Cookie 在客户端和服务器之间作为 HTTP 头部来回传递。Cookie 只是由浏览器客户端存储的文本键值对。它们用于在客户端存储持久化数据。Cookie 可以存储任何文本值，但通常用于存储偏好设置、令牌和会话信息。

会话 Cookie 通常存储一个与服务器中的令牌匹配的令牌。当用户登录时，服务器会创建一个与该用户相关的标识令牌的会话。服务器随后以 Cookie 形式将令牌发送回用户。当客户端以 Cookie 形式发送会话令牌时，服务器会查找并在会话存储中找到匹配的令牌，存储可能是数据库、文件或内存。会话令牌需要足够的熵，以确保它是唯一的，攻击者无法猜测。

如果用户在公共 Wi-Fi 网络上，并访问一个没有使用 SSL 的网站，附近的任何人都可以看到明文的 HTTP 请求。攻击者可能会窃取会话 cookie，并在自己的请求中使用它。当 cookie 以这种方式被侧面劫持时，攻击者可以冒充受害者。服务器会将其视为已经登录的用户。攻击者可能永远无法知道密码，而且也不需要知道。

因此，偶尔退出网站并销毁所有活动会话是有用的。有些网站允许你手动销毁所有活动会话。如果你运行一个网络服务，我建议你为会话设置合理的过期时间。银行网站通常会做得很好，强制执行短时间（10-15 分钟）的过期时间。

服务器在创建新 cookie 时，会发送一个`Set-Cookie`头部到客户端。客户端随后会使用`Cookie`头部将 cookie 发送回服务器。

这是服务器发送的一个简单的 cookie 头部示例：

```
Set-Cookie: preferred_background=blue
Set-Cookie: session_id=PZRNVYAMDFECHBGDSSRLH
```

这是来自客户的一个示例标题：

```
Cookie: preferred_background=blue; session_id=PZRNVYAMDFECHBGDSSRLH
```

cookie 还可以包含其他属性，例如在第九章《Web 应用程序》中讨论的`Secure`和`HttpOnly`标志。其他属性包括过期日期、域名和路径。这个示例仅展示了最简单的应用。

在这个示例中，发起了一个带有自定义会话 cookie 的简单请求。会话 cookie 使你在访问网站时能够保持*登录状态*。这个示例应该作为如何使用 cookie 发起请求的参考，而不是一个独立的工具。首先，在`main`函数之前定义 URL。然后，创建 HTTP 请求，首先指定 HTTP `GET` 方法。由于`GET`请求通常不需要正文，所以提供一个空正文。接着，更新新请求，添加新的头部信息——cookie。在这个示例中，`session_id` 是会话 cookie 的名称，但这会根据所交互的 web 应用而有所不同。

一旦请求准备好，就创建一个 HTTP 客户端来实际发起请求并处理响应。请注意，HTTP 请求和 HTTP 客户端是独立的实体。例如，你可以多次重用一个请求，使用不同的客户端发送请求，或者使用一个客户端发起多个请求。这使得你可以在需要管理多个客户端会话时创建多个带有不同会话 cookie 的请求对象。

以下是该示例的代码实现：

```
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
)

var url = "https://www.example.com"

func main() {
   // Create the HTTP request
   request, err := http.NewRequest("GET", url, nil)
   if err != nil {
      log.Fatal("Error creating HTTP request. ", err)
   }

   // Set cookie
   request.Header.Set("Cookie", "session_id=<SESSION_TOKEN>")

   // Create the HTTP client, make request and print response
   httpClient := &http.Client{}
   response, err := httpClient.Do(request)
   data, err := ioutil.ReadAll(response.Body)
   fmt.Printf("%s\n", data)
} 
```

# 在网页中查找 HTML 注释

HTML 注释有时包含一些惊人的信息。我曾亲眼见过一些网站在 HTML 注释中暴露了管理员的用户名和密码。我也曾见过整个菜单被注释掉，但链接仍然有效并且可以直接访问。你永远不知道一个粗心的开发者可能会留下什么信息。

如果你打算在代码中留下注释，最好将它们留在服务器端代码中，而不是客户端的 HTML 和 JavaScript 中。可以在 PHP、Ruby、Python 或任何后端代码中进行注释。你永远不希望在代码中向客户端提供超过他们需要的信息。

该程序中使用的正则表达式包含一些特殊的序列。这里是完整的正则表达式。它本质上表示“匹配`<!--`和`-->`字符串之间的任何内容”。让我们逐部分分析：

+   `<!--(.|\n)*?-->`：开始和结束都是`<!--`和`-->`，这分别是 HTML 注释的开头和结尾标记。它们是普通字符，不是正则表达式中的特殊字符。

+   `(.|\n)*?`：这可以分解成两部分：

+   +   `(.|\n)`：第一部分有一些特殊字符。括号`()`包裹了一组选项。管道符号`|`分隔这些选项。选项本身是点号`.`和换行符`\n`。点号表示匹配任何字符，除了换行符。由于 HTML 注释可能跨越多行，我们希望匹配包括换行符在内的任何字符。整个部分`(.|\n)`表示匹配点号或换行符。

+   +   `*?`：星号表示继续匹配前一个字符或表达式零次或多次。紧接星号的是一组括号，因此它会继续尝试匹配`(.|\n)`。问号告诉星号以非贪婪模式工作，即返回最小的匹配项。如果没有问号来指定非贪婪模式，它会匹配尽可能大的内容，这意味着它会从页面上第一个注释的开始处开始匹配，直到最后一个注释的结束位置，涵盖其中的所有内容。

尝试在一些网站上运行这个程序，看看你能找到什么样的 HTML 注释。你可能会对能揭示出的信息感到惊讶。例如，MailChimp 的注册表单包含一个 HTML 注释，实际上给你提供了绕过机器人防止注册的技巧。MailChimp 的注册表单使用了一个蜜罐字段，如果这个字段被填充，系统就会认为是机器人提交的表单。看看你能找到什么。

这个例子首先会获取提供的 URL，然后使用我们之前讲解过的正则表达式来搜索 HTML 注释。每找到一个匹配项，就会打印到标准输出：

```
// Search through a URL and find HTML comments
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "regexp"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Search for HTML comments in a URL")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL and get response
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading HTTP body. ", err)
   }

   // Look for HTML comments using a regular expression
   re := regexp.MustCompile("<!--(.|\n)*?-->")
   matches := re.FindAllString(string(body), -1)
   if matches == nil {
      // Clean exit if no matches found
      fmt.Println("No HTML comments found.")
      os.Exit(0)
   }

   // Print all HTML comments found
   for _, match := range matches {
      fmt.Println(match)
   }
} 
```

# 在 Web 服务器上查找未列出的文件

有一个流行的程序叫做 DirBuster，渗透测试人员用它来查找未列出的文件。DirBuster 是一个 OWASP 项目，预装在 Kali 上，Kali 是流行的渗透测试 Linux 发行版。仅凭标准库，我们就能用几行代码快速、并发且简单地克隆 DirBuster。有关 DirBuster 的更多信息，请访问[`www.owasp.org/index.php/Category:OWASP_DirBuster_Project`](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)。

该程序是一个简单的 DirBuster 克隆，基于单词列表搜索未列出的文件。你需要自己创建单词列表。这里会提供一个小的示例文件名列表，以便给你一些想法并作为起始列表。根据你的经验和源代码来构建文件列表。某些 Web 应用程序具有特定名称的文件，能让你指纹识别使用的框架。此外，还要查找备份文件、配置文件、版本控制文件、更新日志文件、私钥、应用程序日志以及任何不应公开的文件。你也可以在互联网上找到现成的单词列表，包括 DirBuster 的列表。

这是一个你可以搜索的文件示例列表：

+   `.gitignore`

+   `.git/HEAD`

+   `id_rsa`

+   `debug.log`

+   `database.sql`

+   `index-old.html`

+   `backup.zip`

+   `config.ini`

+   `settings.ini`

+   `settings.php.bak`

+   `CHANGELOG.txt`

该程序将使用提供的单词列表搜索域名，并报告任何没有返回 404 NOT FOUND 响应的文件。单词列表应该以换行符分隔文件名，每行一个文件名。提供域名作为参数时，尾部的斜杠是可选的，程序无论有无尾部斜杠都会正确运行。然而，协议必须被指定，这样请求才能知道是使用 HTTP 还是 HTTPS。

`url.Parse()`函数用于创建一个正确的 URL 对象。使用 URL 类型，你可以独立地修改`Path`，而无需修改`Host`或`Scheme`。这提供了一种便捷的方式来更新 URL，而无需手动处理字符串。

要逐行读取文件，使用了扫描器。默认情况下，扫描器按换行符拆分，但可以通过调用`scanner.Split()`并提供自定义拆分函数来覆盖此行为。由于预计单词将单独一行提供，因此我们使用默认行为：

```
// Look for unlisted files on a domain
package main

import (
   "bufio"
   "fmt"
   "log"
   "net/http"
   "net/url"
   "os"
   "strconv"
)

// Given a base URL (protocol+hostname) and a filepath (relative URL)
// perform an HTTP HEAD and see if the path exists.
// If the path returns a 200 OK print out the path
func checkIfUrlExists(baseUrl, filePath string, doneChannel chan bool) {
   // Create URL object from raw string
   targetUrl, err := url.Parse(baseUrl)
   if err != nil {
      log.Println("Error parsing base URL. ", err)
   }
   // Set the part of the URL after the host name
   targetUrl.Path = filePath

   // Perform a HEAD only, checking status without
   // downloading the entire file
   response, err := http.Head(targetUrl.String())
   if err != nil {
      log.Println("Error fetching ", targetUrl.String())
   }

   // If server returns 200 OK file can be downloaded
   if response.StatusCode == 200 {
      log.Println(targetUrl.String())
   }

   // Signal completion so next thread can start
   doneChannel <- true
}

func main() {
   // Load command line arguments
   if len(os.Args) != 4 {
      fmt.Println(os.Args[0] + " - Perform an HTTP HEAD request to a URL")
      fmt.Println("Usage: " + os.Args[0] + 
         " <wordlist_file> <url> <maxThreads>")
      fmt.Println("Example: " + os.Args[0] + 
         " wordlist.txt https://www.devdungeon.com 10")
      os.Exit(1)
   }
   wordlistFilename := os.Args[1]
   baseUrl := os.Args[2]
   maxThreads, err := strconv.Atoi(os.Args[3])
   if err != nil {
      log.Fatal("Error converting maxThread value to integer. ", err)
   }

   // Track how many threads are active to avoid
   // flooding a web server
   activeThreads := 0
   doneChannel := make(chan bool)

   // Open word list file for reading
   wordlistFile, err := os.Open(wordlistFilename)
   if err != nil {
      log.Fatal("Error opening wordlist file. ", err)
   }

   // Read each line and do an HTTP HEAD
   scanner := bufio.NewScanner(wordlistFile)
   for scanner.Scan() {
      go checkIfUrlExists(baseUrl, scanner.Text(), doneChannel)
      activeThreads++

      // Wait until a done signal before next if max threads reached
      if activeThreads >= maxThreads {
         <-doneChannel
         activeThreads -= 1
      }
   }

   // Wait for all threads before repeating and fetching a new batch
   for activeThreads > 0 {
      <-doneChannel
      activeThreads -= 1
   }

   // Scanner errors must be checked manually
   if err := scanner.Err(); err != nil {
      log.Fatal("Error reading wordlist file. ", err)
   }
} 
```

# 更改请求的用户代理

一种常见的阻止爬虫和抓取器的技术是阻止特定的用户代理。一些服务会将包含如`curl`和`python`等关键词的用户代理列入黑名单。你可以通过简单地将用户代理更改为`firefox`来绕过大多数这些限制。

要设置用户代理，必须首先创建 HTTP 请求对象。该头部必须在发出实际请求之前设置。这意味着你不能使用像`http.Get()`这样的快捷便利函数。我们必须创建客户端，然后创建请求，再使用客户端通过`client.Do()`发出请求。

这个例子通过`http.NewRequest()`创建一个 HTTP 请求，然后修改请求头来覆盖`User-Agent`头。你可以用它来隐藏、伪造或保持真实。为了成为一个合格的网络公民，我建议你为爬虫创建一个唯一的用户代理，这样网站管理员就可以限制或屏蔽你的爬虫。我还建议你在用户代理中包含一个网站或电子邮件地址，这样网站管理员可以要求跳过你的抓取工具。

以下是此示例的代码实现：

```
// Change HTTP user agent
package main

import (
   "log"
   "net/http"
)

func main() {
   // Create the request for use later
   client := &http.Client{}
   request, err := http.NewRequest("GET", 
      "https://www.devdungeon.com", nil)
   if err != nil {
      log.Fatal("Error creating request. ", err)
   }

   // Override the user agent
   request.Header.Set("User-Agent", "_Custom User Agent_")

   // Perform the request, ignore response.
   _, err = client.Do(request)
   if err != nil {
      log.Fatal("Error making request. ", err)
   }
} 
```

# 网页应用程序技术栈的指纹识别

指纹识别网页应用程序是指你试图识别用于提供网页应用程序的技术。指纹识别可以在多个层面进行。在较低层面，HTTP 头部可以提供关于操作系统（如 Windows 或 Linux）和运行的网页服务器（如 Apache 或 nginx）的线索。头部还可能提供有关应用层使用的编程语言或框架的信息。在更高层面，网页应用程序可以通过指纹识别来识别使用的 JavaScript 库、是否包含任何分析平台、是否显示任何广告网络、使用的缓存层以及其他信息。我们将首先查看 HTTP 头部，然后介绍更复杂的指纹识别方法。

指纹识别是攻击或渗透测试中的关键步骤，因为它有助于缩小选择范围并确定要采取的路径。识别使用的技术还可以帮助你查找已知的漏洞。如果一个网页应用程序没有及时更新，简单的指纹识别和漏洞搜索可能就是找到并利用已知漏洞所需要的一切。如果没有别的，它至少能帮助你了解目标。

# 基于 HTTP 响应头的指纹识别

我建议你首先检查 HTTP 头部，因为它们是简单的键值对，而且每次请求返回的通常只有几个头部。手动浏览这些头部不会花费太长时间，因此可以在继续检查应用程序之前先查看它们。应用层的指纹识别更为复杂，我们稍后会讲到这一点。在本章的早些部分，有一节关于提取 HTTP 头并打印出来以供检查的内容（*从 HTTP 响应中提取 HTTP 头部*）。你可以使用该程序转储不同网页的头部，并查看你能发现什么。

基本的思路很简单。寻找关键词。特别是某些头信息包含最明显的线索，例如`X-Powered-By`、`Server`和`X-Generator`头。`X-Powered-By`头可以包含正在使用的框架或**内容管理系统**（**CMS**）的名称，例如 WordPress 或 Drupal。

检查头信息的基本步骤有两个。首先，你需要获取头信息。使用本章前面提供的示例来提取 HTTP 头。第二步是进行字符串搜索，寻找关键词。你可以使用`strings.ToUpper()`和`strings.Contains()`直接搜索关键词，或者使用正则表达式。参阅本章前面解释如何使用正则表达式的示例。一旦你能够在头信息中搜索，你只需要能够生成关键词列表来进行搜索。

你可以寻找许多关键词。你搜索什么取决于你想寻找什么。为了给你提供一些思路，我会尝试涵盖几个广泛的类别。你首先可以尝试识别主机运行的是哪种操作系统。下面是一个示例列表，列出了你可以在 HTTP 头中找到的，用来指示操作系统的关键词：

+   `Linux`

+   `Debian`

+   `Fedora`

+   `Red Hat`

+   `CentOS`

+   `Ubuntu`

+   `FreeBSD`

+   `Win32`

+   `Win64`

+   `Darwin`

下面是一些可以帮助你确定使用的是哪种 Web 服务器的关键词列表。这绝不是一个详尽无遗的列表，但涵盖了几个关键词，如果你在互联网上搜索，它们会产生结果：

+   `Apache`

+   `Nginx`

+   `Microsoft-IIS`

+   `Tomcat`

+   `WEBrick`

+   `Lighttpd`

+   `IBM HTTP Server`

确定正在使用的编程语言可以在你的攻击选择中产生重大影响。像 PHP 这样的脚本语言与 Java 服务器或 ASP.NET 应用程序在脆弱性上有所不同。以下是你可以在 HTTP 头中使用的一些关键词，帮助你识别应用程序使用的是哪种语言：

+   `Python`

+   `Ruby`

+   `Perl`

+   `PHP`

+   `ASP.NET`

会话 Cookie 也是确定正在使用的框架或语言的重要线索。例如，`PHPSESSID`表示 PHP，`JSESSIONID`表示 Java。以下是你可以搜索的几个会话 Cookie：

+   `PHPSESSID`

+   `JSESSIONID`

+   `session`

+   `sessionid`

+   `CFID/CFTOKEN`

+   `ASP.NET_SessionId`

# 指纹识别 Web 应用程序

总体来说，指纹识别 Web 应用程序的范围比仅查看 HTTP 头要广泛得多。你可以在 HTTP 头中进行基本的关键词搜索，正如之前所讨论的，学到很多信息，但在 HTML 源代码和内容中，以及服务器上其他文件的存在或内容中，也有丰富的信息。

在 HTML 源代码中，你可以查找一些线索，如页面结构本身以及 HTML 元素的类名和 ID。AngularJS 应用程序有独特的 HTML 属性，例如`ng-app`，可以作为指纹识别的关键词。Angular 通常也包含在一个`script`标签中，就像其他框架如 jQuery 一样。`script`标签还可以检查其他线索。查找诸如 Google Analytics、AdSense、Yahoo 广告、Facebook、Disqus、Twitter 和其他第三方嵌入的 JavaScript 等信息。

仅仅通过查看 URL 中的文件扩展名，你就能知道使用了什么语言。例如，`.php`、`.jsp`和`.asp`分别表示使用了 PHP、Java 和 ASP。

我们还查看了一个可以在网页中找到 HTML 注释的程序。一些框架和内容管理系统（CMS）会留下可识别的页脚或隐藏的 HTML 注释。有时，标记可能以小图像的形式存在。

目录结构也可能是另一个线索。这需要首先熟悉不同的框架。例如，Drupal 将站点信息存储在名为`/sites/default`的目录中。如果你尝试访问该 URL 并且得到的是 403 FORBIDDEN 响应，而不是 404 NOT FOUND 错误，那么你很可能发现了一个基于 Drupal 的网站。

查找像`wp-cron.php`这样的文件。在*寻找未列出的文件*部分，我们讨论了使用 DirBuster 克隆工具查找未列出的文件。找到一份可以用于指纹识别 Web 应用程序的唯一文件列表，并将它们添加到你的词表中。你可以通过检查不同 Web 框架的代码库来确定要查找哪些文件。例如，WordPress 和 Drupal 的源代码是公开可用的。使用本章早些时候讨论的程序来查找未列出的文件，进行文件搜索。你还可以查找与文档相关的其他未列出的文件，如`CHANGELOG.txt`、`readme.txt`、`readme.md`、`readme.html`、`LICENSE.txt`、`install.txt`或`install.php`。

通过指纹识别正在运行的应用程序的版本，你可以获得更多的 Web 应用程序详细信息。如果你能够访问源代码，这将更容易。我将使用 WordPress 作为示例，因为它非常普及，而且其源代码可以在 GitHub 上找到，[`github.com/WordPress/WordPress`](https://github.com/WordPress/WordPress)。

目标是找出不同版本之间的差异。WordPress 是一个很好的例子，因为它们都带有 `/wp-admin/` 目录，里面包含所有的管理接口。在 `/wp-admin/` 目录下，有 `css` 和 `js` 文件夹，分别存放样式表和脚本文件。当网站托管在服务器上时，这些文件是公开可访问的。你可以使用 `diff` 命令对这些文件夹进行比较，找出哪些版本新增了文件，哪些版本删除了文件，哪些版本修改了现有文件。通过将所有信息综合起来，你通常可以将应用程序缩小到某个特定版本，或者至少是一个小范围的版本。

举一个简单的例子，假设版本 1.0 只包含一个文件：`main.js`。版本 1.1 引入了第二个文件：`utility.js`。版本 1.3 删除了这两个文件，并用一个文件：`master.js` 替代了它们。你可以向 Web 服务器发起 HTTP 请求，获取这三个文件：`main.js`、`utility.js` 和 `master.js`。根据返回 200 OK 状态的文件和返回 404 NOT FOUND 状态的文件，你可以确定当前运行的版本。

如果相同的文件出现在多个版本中，你可以更深入地检查这些文件的内容。可以逐字节比较，或者对文件进行哈希并比较校验和。哈希和哈希示例在第六章，《加密学》中有详细讲解。

有时，识别版本比刚才描述的整个过程要简单得多。有时会有一个 `CHANGELOG.txt` 或 `readme.html` 文件，它可以直接告诉你当前运行的是哪个版本，而不需要进行任何工作。

# 如何防止应用程序被指纹识别

如前所述，指纹识别应用程序有多种方法，可以在技术栈的不同层级进行。你真正应该问自己的第一个问题是，“我需要防止指纹识别吗？”一般来说，试图防止指纹识别是一种混淆技术。混淆技术有些争议，但我认为大家都同意混淆并不是安全，就像编码并不是加密一样。它可能会暂时减缓攻击者、限制信息或造成困惑，但并不能真正阻止任何漏洞的利用。现在，我不是说混淆完全没有好处，但它永远不能单独依赖。混淆只是一个薄弱的掩盖层。

显然，你不希望泄露关于应用程序的过多信息，比如调试输出或配置设置，但当服务在网络上可用时，无论如何总会有一些信息是可用的。你需要决定投入多少时间和精力来隐藏这些信息。

有些人甚至通过输出虚假信息来误导攻击者。就个人而言，在加强服务器安全时，我不会把发布虚假头信息列入我的清单中。我建议你做的一件事是删除任何多余的文件，如前面所提到的。像更改日志文件、默认设置文件、安装文件和文档文件这样的文件，在部署之前应该全部删除。不要公开提供那些应用程序运行所不需要的文件。

混淆是一个值得单独成章，甚至是写书的主题。甚至有专门的混淆比赛，旨在奖励最具创意和奇特的混淆方式。有些工具可以帮助你混淆 JavaScript 代码，但另一方面，也有解混淆工具。

# 使用 goquery 包进行网页抓取

`goquery`包不是标准库的一部分，但可以在 GitHub 上找到。它的设计类似于 jQuery——一个流行的 JavaScript 框架，用于与 HTML DOM 进行交互。正如前面章节所示，使用字符串匹配和正则表达式进行搜索既繁琐又复杂。`goquery`包使得处理 HTML 内容和查找特定元素变得更加容易。我建议使用这个包，因为它是基于非常流行的 jQuery 框架的，许多人已经对此非常熟悉。

你可以使用`go get`命令获取`goquery`包：

```
go get https://github.com/PuerkitoBio/goquery  
```

文档可以在[`godoc.org/github.com/PuerkitoBio/goquery`](https://godoc.org/github.com/PuerkitoBio/goquery)上找到。

# 列出页面中的所有超链接

对于`goquery`包的介绍，我们将探讨一个常见且简单的任务。我们将查找页面中的所有超链接并将其打印出来。一个典型的链接看起来像这样：

```
<a href="https://www.devdungeon.com">DevDungeon</a>  
```

在 HTML 中，`a`标签代表**锚点**，`href`属性代表**超链接引用**。可以存在没有`href`属性但只有`name`属性的锚点标签，这些被称为书签或命名锚点，用于跳转到同一页面中的某个位置。我们将忽略这些，因为它们只在同一页面内链接。`target`属性只是一个可选的属性，用于指定在哪个窗口或标签页中打开链接。对于这个示例，我们只关心`href`值：

```
// Load a URL and list all links found
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Find all links in a web page")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Extract all links
   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Find and print all links
   doc.Find("a").Each(func(i int, s *goquery.Selection) {
      href, exists := s.Attr("href")
      if exists {
         fmt.Println(href)
      }
   })
} 
```

# 在网页中查找文档

文档也是感兴趣的内容。你可能会想抓取一个网页并查找文档。文字处理文档、电子表格、幻灯片、CSV、文本文件和其他文件可能包含有用的信息，用于各种目的。

以下示例将搜索一个 URL，并根据链接中的文件扩展名搜索文档。为了方便起见，在顶部定义了一个全局变量，列出了所有应该搜索的扩展名。自定义要搜索的扩展名列表，以便查找目标文件类型。考虑将该应用程序扩展为从文件中读取文件扩展名列表，而不是硬编码。你在寻找敏感信息时，还会查找哪些其他文件扩展名？

以下是此示例的代码实现：

```
// Load a URL and list all documents 
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
   "strings"
)

var documentExtensions = []string{"doc", "docx", "pdf", "csv", 
   "xls", "xlsx", "zip", "gz", "tar"}

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Find all links in a web page")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Extract all links
   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Find and print all links that contain a document
   doc.Find("a").Each(func(i int, s *goquery.Selection) {
      href, exists := s.Attr("href")
      if exists && linkContainsDocument(href) {
         fmt.Println(href)
      }
   })
} 

func linkContainsDocument(url string) bool {
   // Split URL into pieces
   urlPieces := strings.Split(url, ".")
   if len(urlPieces) < 2 {
      return false
   }

   // Check last item in the split string slice (the extension)
   for _, extension := range documentExtensions {
      if urlPieces[len(urlPieces)-1] == extension {
         return true
      }
   }
   return false
} 
```

# 列出页面标题和标题

标题是定义网页层次结构的主要结构元素，其中 `<h1>` 是最高层级，`<h6>` 是最低或最深的层级。HTML 页面的 `<title>` 标签定义了页面标题，显示在浏览器的标题栏中，它不属于渲染页面的一部分。

通过列出标题和标题，你可以快速了解页面的主题，前提是他们正确地格式化了 HTML。每个页面应该只有一个 `<title>` 和一个 `<h1>` 标签，但并非每个人都遵守标准。

该程序加载一个网页，然后将标题和所有标题打印到标准输出。尝试针对一些 URL 运行此程序，看看你是否能够仅通过查看标题就快速了解页面的内容：

```
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("List all headings (h1-h6) in a web page")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Print title before headings
   title := doc.Find("title").Text()
   fmt.Printf("== Title ==\n%s\n", title)

   // Find and list all headings h1-h6
   headingTags := [6]string{"h1", "h2", "h3", "h4", "h5", "h6"}
   for _, headingTag := range headingTags {
      fmt.Printf("== %s ==\n", headingTag)
      doc.Find(headingTag).Each(func(i int, heading *goquery.Selection) {
         fmt.Println(" * " + heading.Text())
      })
   }

} 
```

# 爬取网站页面，收集最常见的单词

该程序打印出网页上所有单词的列表，并计算每个单词在页面中出现的次数。它会搜索所有段落标签。如果你搜索整个正文，它会将所有 HTML 代码视为单词，这会使数据杂乱无章，且并不真正帮助你理解网站的内容。它会修剪字符串中的空格、逗号、句点、制表符和换行符。它还会将所有单词转换为小写，以便标准化数据。

对于每个找到的段落，它会将文本内容拆分开来。每个单词都会存储在一个映射中，该映射将字符串映射到整数计数。在最后，映射会被打印出来，列出每个单词以及它在页面上出现的次数：

```
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
   "strings"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("List all words by frequency from a web page")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Find and list all headings h1-h6
   wordCountMap := make(map[string]int)
   doc.Find("p").Each(func(i int, body *goquery.Selection) {
      fmt.Println(body.Text())
      words := strings.Split(body.Text(), " ")
      for _, word := range words {
         trimmedWord := strings.Trim(word, " \t\n\r,.?!")
         if trimmedWord == "" {
            continue
         }
         wordCountMap[strings.ToLower(trimmedWord)]++

      }
   })

   // Print all words along with the number of times the word was seen
   for word, count := range wordCountMap {
      fmt.Printf("%d | %s\n", count, word)
   }

} 
```

# 打印页面中外部 JavaScript 文件的列表

检查页面中包含的 JavaScript 文件的 URL 如果你想识别一个应用程序或确定加载了哪些第三方库，可能会有所帮助。该程序将列出网页中引用的外部 JavaScript 文件。外部 JavaScript 文件可能托管在相同的域名上，也可能从远程站点加载。它检查所有 `script` 标签的 `src` 属性。

例如，如果一个 HTML 页面有以下标签：

```
<script src="img/jquery.min.js"></script>  
```

`src` 属性的 URL 将被打印出来：

```
/ajax/libs/jquery/3.2.1/jquery.min.js
```

请注意，`src` 属性中的 URL 可以是完全限定的或相对 URL。

以下程序加载一个 URL，然后查找所有的`script`标签。它将打印出每个找到的脚本的`src`属性。该程序只会查找外部链接的脚本。如果要打印内联脚本，请参考文件底部关于`script.Text()`的注释。试着在你经常访问的网站上运行这个程序，看看它们嵌入了多少外部和第三方脚本：

```
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("List all JavaScript files in a webpage")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Find and list all external scripts in page
   fmt.Println("Scripts found in", url)
   fmt.Println("==========================")
   doc.Find("script").Each(func(i int, script *goquery.Selection) {

      // By looking only at the script src we are limiting
      // the search to only externally loaded JavaScript files.
      // External files might be hosted on the same domain
      // or hosted remotely
      src, exists := script.Attr("src")
      if exists {
         fmt.Println(src)
      }

      // script.Text() will contain the raw script text
      // if the JavaScript code is written directly in the
      // HTML source instead of loaded from a separate file
   })
} 
```

这个示例查找的是由`src`属性引用的外部脚本，但有些脚本直接写在 HTML 中，位于`script`标签的开头和结尾之间。这些内联脚本不会有引用的`src`属性。可以使用`goquery`对象上的`.Text()`函数获取内联脚本的文本。请参阅本示例底部关于`script.Text()`的说明。

该程序之所以不打印内联脚本，而是专注于外部加载的脚本，是因为外部 JavaScript 文件常常带来很多漏洞。加载远程 JavaScript 是有风险的，应该只从可信的来源加载。即便如此，我们也无法 100%确保远程内容提供商永远不会被攻破并提供恶意代码。考虑像雅虎这样的巨大企业，雅虎曾公开承认他们的系统在过去曾遭受过攻击。雅虎还有一个广告网络，托管着一个**内容分发网络**（**CDN**），为大量网站提供 JavaScript 文件。这是攻击者的主要目标之一。考虑到这些风险，在敏感客户门户中引入远程 JavaScript 文件时要格外小心。

# 深度优先爬取

深度优先爬取是指优先考虑同一域名内的链接，而不是指向其他域名的链接。在这个程序中，外部链接会被完全忽略，只跟随同一域名下的路径或相对链接。

在这个示例中，唯一的路径被存储在一个切片中，并在最后一起打印出来。在爬取过程中遇到的任何错误都会被忽略。由于链接格式错误，爬取过程中经常会遇到错误，我们不希望程序因这些错误而退出。

该程序不使用字符串函数手动解析 URL，而是使用了`url.Parse()`函数。它可以将主机和路径分开。

在爬取过程中，任何查询字符串和片段都被忽略，以减少重复。查询字符串通过 URL 中的问号标记，片段也称为书签，通过井号（#）标记。这个程序是单线程的，并没有使用 goroutines：

```
// Crawl a website, depth-first, listing all unique paths found
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "net/url"
   "os"
   "time"
)

var (
   foundPaths  []string
   startingUrl *url.URL
   timeout     = time.Duration(8 * time.Second)
)

func crawlUrl(path string) {
   // Create a temporary URL object for this request
   var targetUrl url.URL
   targetUrl.Scheme = startingUrl.Scheme
   targetUrl.Host = startingUrl.Host
   targetUrl.Path = path

   // Fetch the URL with a timeout and parse to goquery doc
   httpClient := http.Client{Timeout: timeout}
   response, err := httpClient.Get(targetUrl.String())
   if err != nil {
      return
   }
   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      return
   }

   // Find all links and crawl if new path on same host
   doc.Find("a").Each(func(i int, s *goquery.Selection) {
      href, exists := s.Attr("href")
      if !exists {
         return
      }

      parsedUrl, err := url.Parse(href)
      if err != nil { // Err parsing URL. Ignore
         return
      }

      if urlIsInScope(parsedUrl) {
         foundPaths = append(foundPaths, parsedUrl.Path)
         log.Println("Found new path to crawl: " +
            parsedUrl.String())
         crawlUrl(parsedUrl.Path)
      }
   })
}

// Determine if path has already been found
// and if it points to the same host
func urlIsInScope(tempUrl *url.URL) bool {
   // Relative url, same host
   if tempUrl.Host != "" && tempUrl.Host != startingUrl.Host {
      return false // Link points to different host
   }

   if tempUrl.Path == "" {
      return false
   }

   // Already found?
   for _, existingPath := range foundPaths {
      if existingPath == tempUrl.Path {
         return false // Match
      }
   }
   return true // No match found
}

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Crawl a website, depth-first")
      fmt.Println("Usage: " + os.Args[0] + " <startingUrl>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   foundPaths = make([]string, 0)

   // Parse starting URL
   startingUrl, err := url.Parse(os.Args[1])
   if err != nil {
      log.Fatal("Error parsing starting URL. ", err)
   }
   log.Println("Crawling: " + startingUrl.String())

   crawlUrl(startingUrl.Path)

   for _, path := range foundPaths {
      fmt.Println(path)
   }
   log.Printf("Total unique paths crawled: %d\n", len(foundPaths))
} 
```

# 广度优先爬取

广度优先爬取是指优先寻找新的域名并尽可能地扩展，而不是继续以深度优先的方式遍历单一域名。

写一个广度优先的爬虫将留给读者作为本章提供的信息基础上的练习。它与前面章节的深度优先爬虫没有太大区别，只不过它应该优先考虑那些指向尚未访问过的域名的 URL。

有几点需要注意。如果不小心且没有设置最大限制，你可能最终会爬取到数 PB 的数据！你可能会选择忽略子域名，或者进入一个拥有无限子域名的网站，你将永远也爬不完。

# 如何防止网页抓取

完全防止网页爬虫是困难的，甚至可以说是不可能的。如果你从网页服务器提供信息，就总会有某种方法可以以编程方式提取数据。你只能设置障碍物。归根结底，这只是一种模糊化手段，你可以说这种做法并不值得付出太多努力。

JavaScript 增加了难度，但并非不可能，因为 Selenium 可以驱动真实的网页浏览器，像 PhantomJS 这样的框架也可以用来执行 JavaScript。

要求身份验证可以帮助限制爬虫的抓取量。速率限制也能提供一些缓解。速率限制可以使用如 iptables 等工具来实现，也可以在应用层基于 IP 地址或用户会话来实现。

检查客户端提供的用户代理是一种浅显的措施，但可以稍微起到一些作用。丢弃包含如`curl`、`wget`、`go`、`python`、`ruby`和`perl`等关键字的用户代理的请求。阻止或忽略这些请求可以防止简单的爬虫抓取你的网站，但客户端可以伪造或省略其用户代理，绕过这一限制。

如果你想更进一步，你可以使 HTML 的 ID 和类名动态化，以便无法用于查找特定信息。频繁更改你的 HTML 结构和命名，进行*猫鼠游戏*，让爬虫抓取变得比值得做的工作更繁琐。这不是一个真正的解决方案，我不推荐这么做，但值得一提，因为它在爬虫眼中是令人烦恼的。

你可以使用 JavaScript 在展示数据之前检查客户端的信息，例如屏幕大小。如果屏幕大小为 1 x 1 或 0 x 0，或者其他奇怪的尺寸，你可以假设它是爬虫，并拒绝渲染内容。

蜂蜜罐表单是另一种检测爬虫行为的方法。通过 CSS 或 `hidden` 属性隐藏表单字段，检查这些字段中是否有值。如果这些字段中有数据，假设是爬虫填写了所有字段并忽略该请求。

另一种选择是使用图像而非文本来存储信息。例如，如果你只输出一个饼状图的图像，那么相比输出数据作为 JSON 对象并让 JavaScript 渲染饼状图，别人抓取数据要困难得多。抓取程序可以直接抓取 JSON 数据。文本也可以放入图像中，以防止文本被抓取，并防止关键词文本搜索，但**光学字符识别**（**OCR**）可以通过一些额外的努力绕过这一点。

根据应用的不同，前述的一些技术可能会很有用。

# 总结

读完本章后，你应该已经理解了网页抓取的基本原理，例如执行 HTTP `GET`请求，并使用字符串匹配或正则表达式搜索 HTML 评论、电子邮件和其他关键词。你还应该理解如何提取 HTTP 头部，并设置自定义头部以设置 Cookies 和自定义用户代理字符串。此外，你应该了解指纹识别的基本概念，并对如何根据提供的源代码收集 Web 应用程序的信息有一定的了解。

通过本章的学习，你应该已经理解了如何使用`goquery`包以 jQuery 风格查找 DOM 中的 HTML 元素。你应该能轻松找到网页中的链接，找到文档，列出标题和头部，找到 JavaScript 文件，并理解广度优先与深度优先爬虫的区别。

关于抓取公共网站的说明——请保持尊重。不要通过发送大量数据或让爬虫不受限制地运行，给网站带来不合理的流量。对你编写的程序设置合理的速率限制和最大页面数限制，以免给远程服务器带来过大负担。如果你是为了抓取数据，最好检查是否有 API 可以使用。API 通常更高效且是为了程序化使用而设计的。

你能想到本章中讨论的工具可以应用的其他方法吗？你能想到可以为示例添加的其他功能吗？

在下一章中，我们将介绍主机发现与枚举的方法。我们将涵盖 TCP 套接字、代理、端口扫描、横幅抓取和模糊测试等内容。

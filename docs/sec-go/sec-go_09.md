# 第九章：Web 应用程序

Go 语言在标准库中有一个强大的 HTTP 包。`net/http` 包的文档可以在[`golang.org/pkg/net/http/`](https://golang.org/pkg/net/http/)找到，它包含了 HTTP 和 HTTPS 的相关工具。一开始，我建议你远离社区的 HTTP 框架，专注于 Go 的标准库。标准 HTTP 包包括用于监听、路由和模板的函数。内置的 HTTP 服务器具有生产级质量，并且直接绑定到端口，省去了使用单独的 httpd（如 Apache、IIS 或 nginx）的需要。然而，通常会看到 nginx 监听公共端口 `80`，并将所有请求反向代理到 Go 服务器，该服务器监听的是其他本地端口。

在本章中，我们介绍了如何运行 HTTP 服务器，使用 HTTPS，设置安全的 cookies，并转义输出。我们还介绍了如何使用 Negroni 中间件包，以及如何实现自定义中间件来进行日志记录、添加安全的 HTTP 头信息和服务静态文件。Negroni 采用 Go 语言的惯用方法，并鼓励使用标准库 `net/http` 处理程序。它非常轻量，并且在现有的 Go 结构之上构建。此外，还提到了一些与运行 Web 应用程序相关的最佳实践。

也提供了 HTTP 客户端示例。从基本的 HTTP 请求开始，我们接着学习如何发起 HTTPS 请求，并使用客户端证书进行身份验证，以及使用代理转发流量。

在本章中，我们将涵盖以下主题：

+   HTTP 服务器

+   简单的 HTTP 服务器

+   TLS 加密的 HTTP（HTTPS）

+   使用安全的 cookies

+   HTML 输出转义

+   使用 Negroni 中间件

+   请求日志记录

+   添加安全的 HTTP 头信息

+   服务静态文件

+   其他最佳实践

+   跨站请求伪造（CSRF）令牌

+   防止用户枚举和滥用

+   避免本地和远程文件包含漏洞

+   HTTP 客户端

+   发起基本的 HTTP 请求

+   使用客户端 SSL 证书

+   使用代理

+   使用系统代理

+   使用 HTTP 代理

+   使用 SOCKS5 代理（Tor）

# HTTP 服务器

HTTP 是构建在 TCP 层之上的应用层协议。其概念相对简单；你可以使用纯文本来构造请求。在请求的第一行，你将提供方法（如 `GET` 或 `POST`），路径以及你遵循的 HTTP 版本。之后，你将提供一系列的键值对来描述你的请求。通常，你需要提供 `Host` 值，以便服务器知道你正在请求哪个网站。一个简单的 HTTP 请求可能如下所示：

```
GET /archive HTTP/1.1
Host: www.devdungeon.com  
```

你无需担心 HTTP 规范中的所有细节。Go 提供了 `net/http` 包，包含了多个工具，可以轻松创建生产就绪的 Web 服务器，包括对 HTTP/2.0（Go 1.6 及更新版本）的支持。本节涵盖了与运行和保护 HTTP 服务器相关的主题。

# 简单的 HTTP 服务器

在这个示例中，一个 HTTP 服务器展示了使用标准库创建一个监听服务器是多么简单。此时还没有路由或复用。在这个例子中，服务器通过特定目录提供服务。`http.FileServer()`具有内置的目录列出功能，因此，如果你向`/`发送 HTTP 请求，它会列出正在提供服务的目录中的文件：

```
package main

import (
   "fmt"
   "log"
   "net/http"
   "os"
)

func printUsage() {
   fmt.Println(os.Args[0] + ` - Serve a directory via HTTP

URL should include protocol IP or hostname and port separated by colon.

Usage:
  ` + os.Args[0] + ` <listenUrl> <directory>

Example:
  ` + os.Args[0] + ` localhost:8080 .
  ` + os.Args[0] + ` 0.0.0.0:9999 /home/nanodano
`)
}

func checkArgs() (string, string) {
   if len(os.Args) != 3 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1], os.Args[2]
}

func main() {
   listenUrl, directoryPath := checkArgs()
   err := http.ListenAndServe(listenUrl,      
     http.FileServer(http.Dir(directoryPath)))
   if err != nil {
      log.Fatal("Error running server. ", err)
   }
}
```

下一个示例展示了如何路由路径并创建一个处理传入请求的函数。这个示例不会接受任何命令行参数，因为它本身并不是一个特别有用的程序，但你可以将它作为一个基本模板：

```
package main

import (
   "fmt"
   "net/http"
   "log"
)

func indexHandler(writer http.ResponseWriter, request *http.Request) {
   // Write the contents of the response body to the writer interface
   // Request object contains information about and from the client
   fmt.Fprintf(writer, "You requested: " + request.URL.Path)
}

func main() {
   http.HandleFunc("/", indexHandler)
   err := http.ListenAndServe("localhost:8080", nil)
   if err != nil {
      log.Fatal("Error creating server. ", err)
   }
}
```

# HTTP 基本认证

HTTP 基本认证的工作方式是通过将用户名和密码组合，并用冒号分隔符连接，然后使用 base64 编码。这些用户名和密码通常作为 URL 的一部分传递，例如：`http://<用户名>:<密码>@www.example.com`。但实际发生的情况是，用户名和密码被组合、编码，并作为 HTTP 头部传递。

如果你使用这种认证方法，请记住它是没有加密的。用户名和密码在传输过程中没有保护。你始终希望在传输层使用加密，这意味着需要添加 TLS/SSL。

现在 HTTP 基本认证不再广泛使用，但它很容易实现。一个更常见的方法是构建或使用你自己的认证层，例如将用户名和密码与一个包含加盐哈希密码的用户数据库进行比较。

请参阅第八章，*暴力破解*，了解如何创建一个客户端并连接到需要 HTTP 基本认证的 HTTP 服务器。Go 标准库只提供了作为客户端的 HTTP 基本认证方法，并不提供在服务器端检查基本认证的方法。

我不再建议你在服务器上实现 HTTP 基本认证。如果你需要认证客户端，请使用 TLS 证书。

# 使用 HTTPS

在第六章，*密码学*中，我们带你了解了生成密钥的步骤，并创建了自己的自签名证书。我们还给了你一个如何运行 TCP 套接字级 TLS 服务器的示例。本节将展示如何创建一个 TLS 加密的 HTTP 服务器或 HTTPS 服务器。

TLS 是 SSL 的更新版本，Go 有一个标准包很好地支持它。你需要一个私钥和使用该密钥生成的签名证书。你可以使用自签名证书或由认可的证书颁发机构签名的证书。历史上，受信任的证书颁发机构签发的 SSL 证书通常是收费的，但[`letsencrypt.org/`](https://letsencrypt.org/)改变了这一格局，它们开始提供由广泛信任的证书颁发机构签发的免费自动化证书。

如果你需要此示例的证书（`cert.pem`），请参考 第六章，*密码学*，获取创建自签名证书的示例。

以下代码演示了如何运行一个基本的 HTTPS 服务器，该服务器提供单一的网页。有关各种 HTTP 欺骗陷阱示例和更多 HTTP 服务器参考代码，请参考 第十章，*网页抓取*。在源代码中初始化 HTTPS 服务器后，你可以像操作 HTTP 服务器对象一样操作它。请注意，这与 HTTP 服务器的唯一区别在于你调用的是 `http.ListenAndServeTLS()` 而非 `http.ListenAndServe()`。此外，你必须为服务器提供证书和密钥：

```
package main

import (
   "fmt"
   "net/http"
   "log"
)

func indexHandler(writer http.ResponseWriter, request *http.Request) {
   fmt.Fprintf(writer, "You requested: "+request.URL.Path)
}

func main() {
   http.HandleFunc("/", indexHandler)
   err := http.ListenAndServeTLS( 
      "localhost:8181", 
      "cert.pem", 
      "privateKey.pem", 
      nil, 
   )
   if err != nil {
      log.Fatal("Error creating server. ", err)
   }
}
```

# 创建安全的 cookie

Cookie 本身不应包含用户不应看到的敏感信息。攻击者可能会通过攻击 cookie 来尝试收集私人信息。最常见的目标是会话 cookie。如果会话 cookie 被盗取，攻击者可以利用该 cookie 冒充用户，服务器会允许这种行为。

`HttpOnly` 标志要求浏览器防止 JavaScript 访问 cookie，保护免受跨站脚本攻击。该 cookie 只会在进行 HTTP 请求时发送。如果你确实需要通过 JavaScript 访问某个 cookie，只需创建一个与会话 cookie 不同的 cookie。

`Secure` 标志要求浏览器仅使用 TLS/SSL 加密传输 cookie。这可以防止会话 **旁路攻击**，这类攻击通常通过嗅探公共的非加密 Wi-Fi 网络或中间人连接进行。一些网站只在登录页面上启用 SSL 来保护密码，但之后的每一个连接都使用明文 HTTP，这时会话 cookie 可能会被从网络中窃取，或者如果缺少 `HttpOnly` 标志，还可能通过 JavaScript 被盗取。

创建会话令牌时，请确保使用加密安全的伪随机数生成器生成它。会话令牌的最小长度应为 128 位。参考 第六章，*密码学*，获取生成安全随机字节的示例。

以下示例创建了一个简单的 HTTP 服务器，只有一个函数，即 `indexHandler()`。该函数会根据推荐的安全设置创建一个 cookie，然后调用 `http.SetCookie()`，在打印响应主体并返回之前。

```
package main

import (
   "fmt"
   "net/http"
   "log"
   "time"
)

func indexHandler(writer http.ResponseWriter, request *http.Request) {
   secureSessionCookie := http.Cookie {
      Name: "SessionID",
      Value: "<secure32ByteToken>",
      Domain: "yourdomain.com",
      Path: "/",
      Expires: time.Now().Add(60 * time.Minute),
      HttpOnly: true, // Prevents JavaScript from accessing
      Secure: true, // Requires HTTPS
   }   
   // Write cookie header to response
   http.SetCookie(writer, &secureSessionCookie)   
   fmt.Fprintln(writer, "Cookie has been set.")
}

func main() {
   http.HandleFunc("/", indexHandler)
   err := http.ListenAndServe("localhost:8080", nil)
   if err != nil {
      log.Fatal("Error creating server. ", err)
   }
}
```

# HTML 输出转义

Go 提供了一个标准函数，用于转义字符串并防止 HTML 字符被渲染。

在将用户接收到的任何数据输出到响应时，始终对其进行转义以防止跨站脚本攻击。无论用户提供的数据来自 URL 查询、POST 值、用户代理头、表单、cookie 还是数据库，这一规则都适用。以下代码片段展示了如何转义一个字符串：

```
package main

import (
   "fmt"
   "html"
)

func main() {
   rawString := `<script>alert("Test");</script>`
   safeString := html.EscapeString(rawString)

   fmt.Println("Unescaped: " + rawString)
   fmt.Println("Escaped: " + safeString)
}
```

# 使用 Negroni 的中间件

中间件是指可以绑定到请求/响应流程中的函数，这些函数可以在将请求传递给下一个中间件并最终返回给客户端之前进行操作或修改。

中间件是一系列按顺序运行的函数，针对每个请求。您可以向这个链中添加更多的函数。我们将通过一些实际示例来看看，比如 IP 地址黑名单、添加日志记录和添加授权检查。

中间件的顺序非常重要。例如，我们可能希望先放置日志记录中间件，然后是 IP 黑名单中间件。我们希望 IP 黑名单模块先运行，或者至少在前面运行，以免其他中间件浪费资源处理那些注定会被拒绝的请求。您可以在将请求传递给下一个中间件处理器之前操作请求和响应。

您可能还想为分析、日志记录、IP 黑名单、注入头部或拒绝某些用户代理（如 `curl`、`python` 或 `go`）构建自定义中间件。

这些示例使用了 Negroni 包。在编译并运行这些示例之前，您需要 `go get` 该包。这些示例调用了 `http.ListenAndServe()`，但您也可以轻松修改它们以使用 TLS，方法是使用 `http.ListenAndServeTLS()`：

```
go get github.com/urfave/negroni 
```

以下示例创建了一个 `customMiddlewareHandler()` 函数，我们将告诉 `negroniHandler` 接口使用它。自定义中间件仅记录传入的请求 URL 和用户代理，但您可以根据需要进行修改，包括在请求返回客户端之前修改请求：

```
package main

import (
   "fmt"
   "log"
   "net/http"

   "github.com/urfave/negroni"
)

// Custom middleware handler logs user agent
func customMiddlewareHandler(rw http.ResponseWriter, 
   r *http.Request, 
   next http.HandlerFunc, 
) {
   log.Println("Incoming request: " + r.URL.Path)
   log.Println("User agent: " + r.UserAgent())

   next(rw, r) // Pass on to next middleware handler
}

// Return response to client
func indexHandler(writer http.ResponseWriter, request *http.Request) {
   fmt.Fprintf(writer, "You requested: " + request.URL.Path)
}

func main() {
   multiplexer := http.NewServeMux()
   multiplexer.HandleFunc("/", indexHandler)

   negroniHandler := negroni.New()
   negroniHandler.Use(negroni.HandlerFunc(customMiddlewareHandler))
   negroniHandler.UseHandler(multiplexer)

   http.ListenAndServe("localhost:3000", negroniHandler)
}
```

# 记录请求

由于日志记录是一个非常常见的任务，Negroni 提供了一个日志记录中间件，您可以使用它，正如以下示例所示：

```
package main

import (
   "fmt"
   "net/http"

   "github.com/urfave/negroni"
)

// Return response to client
func indexHandler(writer http.ResponseWriter, request *http.Request) {
   fmt.Fprintf(writer, "You requested: " + request.URL.Path)
}

func main() {
   multiplexer := http.NewServeMux()
   multiplexer.HandleFunc("/", indexHandler)

   negroniHandler := negroni.New()
   negroniHandler.Use(negroni.NewLogger()) // Negroni's default logger
   negroniHandler.UseHandler(multiplexer)

   http.ListenAndServe("localhost:3000", negroniHandler)
}
```

# 添加安全的 HTTP 头部

利用 Negroni 包，我们可以轻松创建自定义中间件，注入一组 HTTP 头部，以帮助提高安全性。您需要评估每个头部，看看它是否适合您的应用程序。此外，并不是每个浏览器都支持这些头部中的每一个。这是一个良好的起点，您可以根据需要进行修改。

这个示例中使用了以下标题：

| **Header** | **Description** |
| --- | --- |
| `Content-Security-Policy` | 该头部定义哪些脚本或远程主机是受信任的，并且能够提供可执行的 JavaScript |
| `X-Frame-Options` | 该头部定义是否可以使用框架和内嵌框架，以及哪些域名可以出现在框架中 |
| `X-XSS-Protection` | 这告诉浏览器在检测到跨站脚本攻击时停止加载；如果定义了良好的 `Content-Security-Policy` 头部，这通常是不必要的 |
| `Strict-Transport-Security` | 这告诉浏览器仅使用 HTTPS，而不是 HTTP |
| `X-Content-Type-Options` | 这告诉浏览器使用服务器提供的 MIME 类型，而不是基于 MIME 嗅探猜测进行修改 |

最终是否使用这些头部或忽略它们取决于客户端的 Web 浏览器。如果没有一个能够正确应用头部值的浏览器，它们并不能保证任何安全性。

这个例子创建了一个名为 `addSecureHeaders()` 的函数，作为额外的中间件处理程序，在响应返回给客户端之前修改响应头。根据需要调整头部以适应你的应用程序：

```
package main

import (
   "fmt"
   "net/http"

   "github.com/urfave/negroni"
)

// Custom middleware handler logs user agent
func addSecureHeaders(rw http.ResponseWriter, r *http.Request, 
   next http.HandlerFunc) {
   rw.Header().Add("Content-Security-Policy", "default-src 'self'")
   rw.Header().Add("X-Frame-Options", "SAMEORIGIN")
   rw.Header().Add("X-XSS-Protection", "1; mode=block")
   rw.Header().Add("Strict-Transport-Security", 
      "max-age=10000, includeSubdomains; preload")
   rw.Header().Add("X-Content-Type-Options", "nosniff")

   next(rw, r) // Pass on to next middleware handler
}

// Return response to client
func indexHandler(writer http.ResponseWriter, request *http.Request) {
   fmt.Fprintf(writer, "You requested: " + request.URL.Path)
}

func main() {
   multiplexer := http.NewServeMux()
   multiplexer.HandleFunc("/", indexHandler)

   negroniHandler := negroni.New()

   // Set up as many middleware functions as you need, in order
   negroniHandler.Use(negroni.HandlerFunc(addSecureHeaders))
   negroniHandler.Use(negroni.NewLogger())
   negroniHandler.UseHandler(multiplexer)

   http.ListenAndServe("localhost:3000", negroniHandler)
}
```

# 提供静态文件

另一个常见的 Web 服务器任务是提供静态文件。值得一提的是 Negroni 中间件处理程序，它用于提供静态文件。只需添加额外的 `Use()` 调用，并传递 `negroni.NewStatic()`。确保你的静态文件目录仅包含客户端应该访问的文件。在大多数情况下，静态文件目录包含客户端的 CSS 和 JavaScript 文件。不要放置数据库备份、配置文件、SSH 密钥、Git 仓库、开发文件或任何客户端不应该访问的内容。像这样添加静态文件中间件：

```
negroniHandler.Use(negroni.NewStatic(http.Dir("/path/to/static/files")))  
```

# 其他最佳实践

在创建 Web 应用程序时，还有一些其他值得考虑的事项。虽然这些并非 Go 特有的，但在开发过程中，考虑这些最佳实践是值得的。

# CSRF 令牌

**跨站请求伪造**（**CSRF**）令牌是一种防止一个网站代替你在另一个网站上执行操作的方式。

CSRF 是一种常见的攻击方式，受害者会访问一个嵌入恶意代码的网站，该代码尝试向其他网站发起请求。例如，攻击者嵌入了一个 JavaScript，使其向每个银行网站发送一个 POST 请求，试图将 1,000 美元转账到攻击者的银行账户。如果受害者在其中一个银行有活动会话，并且该银行未实现 CSRF 令牌，那么银行网站可能会接受并处理该请求。

即使在受信任的网站上，如果该网站容易受到反射型或存储型跨站脚本攻击，仍然可能成为 CSRF 攻击的受害者。自 2007 年以来，CSRF 一直位于 *OWASP Top 10* 中，并在 2017 年继续位列其中。

Go 提供了一个 `xsrftoken` 包，你可以在 [`godoc.org/golang.org/x/net/xsrftoken`](https://godoc.org/golang.org/x/net/xsrftoken) 上了解更多信息。它提供了一个 `Generate()` 函数用于生成令牌，和一个 `Valid()` 函数用于验证令牌。你可以使用他们的实现，或者根据你的需求开发自己的实现。

要实现 CSRF 令牌，创建一个 16 字节的随机令牌，并将其存储在与用户会话相关联的服务器上。你可以使用任何后端存储令牌，无论是在内存中、数据库中还是文件中。将 CSRF 令牌嵌入到表单中作为隐藏字段。在服务器端处理表单时，验证 CSRF 令牌是否存在且与用户匹配。令牌使用后销毁，不要重复使用同一个令牌。

实现 CSRF 令牌的各种要求已在前面的章节中介绍：

+   生成令牌：在第六章，《*加密学*》中，标题为《*加密安全伪随机数生成器（CSPRNG）*》的部分提供了一个生成随机数、字符串和字节的示例。

+   创建、提供和处理 HTML 表单：在第九章，《*Web 应用程序*》中，标题为《*HTTP 服务器*》的部分提供了关于创建安全 Web 服务器的信息，而第十二章，《*社会工程学*》中的《*HTTP POST 表单登录蜜罐*》部分有一个处理 POST 请求的示例。

+   存储令牌到文件中：在第三章，《*操作文件*》一节中，标题为《*将字节写入文件*》的部分提供了一个将数据存储到文件中的示例。

+   将令牌存储在数据库中：在第八章，《*暴力破解*》中，标题为《*暴力破解数据库登录*》的部分提供了连接到各种数据库类型的蓝图。

# 防止用户枚举和滥用

需要记住的要点如下：

+   不要让人们知道谁有账户

+   不要让某人利用你的邮箱服务器向用户发送垃圾邮件

+   不要允许人们通过暴力破解尝试找出谁已注册

让我们详细讨论一些实际的例子。

# 注册

当有人尝试注册一个电子邮件地址时，不要向网页客户端用户提供任何关于账户是否已注册的反馈。相反，向该邮箱地址发送邮件，并简单地给网页用户一个信息：“一封邮件已发送至提供的地址。”

如果他们从未注册过，一切正常。如果他们已经注册，网页用户不会被告知该邮箱已经注册。相反，会向用户的邮箱地址发送一封邮件，告知该邮箱已被注册。这将提醒他们已经拥有一个帐户，可以使用密码重置工具，或者让他们知道某些情况可能存在异常，可能有人在进行恶意操作。

小心不要允许攻击者反复尝试登录过程，产生大量邮件发送给真实用户。

# 登录

不要向网页用户反馈电子邮件是否存在。你不希望用户通过尝试使用某个电子邮件地址登录并根据返回的错误信息判断该地址是否注册了账户。例如，攻击者可能会尝试使用一系列电子邮件地址登录，如果服务器返回“密码不匹配”的错误信息给某些电子邮件地址，而返回“该电子邮件未注册”的错误信息给其他地址，攻击者就能确定哪些电子邮件地址已注册。

# 重置密码

避免允许电子邮件垃圾邮件。对发送的电子邮件进行速率限制，确保攻击者无法通过多次提交忘记密码表单来向用户发送垃圾邮件。

创建重置令牌时，确保令牌具有良好的熵值，防止其被猜测。不要仅仅基于时间和用户 ID 来创建令牌，因为这样容易被猜测和暴力破解，因为熵值不足。你应该至少使用 16-32 个随机字节来确保令牌具有足够的熵。有关生成加密安全随机字节的示例，请参考 第六章，*密码学*。

同时，设置令牌在短时间后过期。根据应用程序的不同，1 小时到 1 天之间是不错的选择。每次只允许使用一个重置令牌，并在使用后销毁该令牌，以防止其被重放和再次使用。

# 用户资料

类似于登录页面，如果你有用户资料页面，务必小心避免用户名枚举攻击。例如，如果某人访问 `/users/JohnDoe` 和 `/users/JaneDoe`，其中一个返回 `404 Not Found` 错误，而另一个返回 `401 Access Denied` 错误，攻击者就可以推断出一个账户存在而另一个账户不存在。

# 防止 LFI 和 RFI 滥用

**本地文件包含** (**LFI**) 和 **远程文件包含** (**RFI**) 是另外两种 *OWASP Top 10* 漏洞。它们指的是从本地文件系统或远程主机加载本不应加载的文件，或者加载了本应加载的文件，但这些文件被污染了。远程文件包含尤其危险，因为如果没有采取预防措施，用户可能会提供来自恶意服务器的远程文件。

如果文件名由用户指定而没有进行任何清理，切勿从本地文件系统中打开该文件。假设一个例子，文件是通过 Web 服务器响应用户请求返回的。用户可能能够请求一个包含敏感系统信息的文件，比如 `/etc/passwd`，URL 可能是这样的：

```
http://localhost/displayFile?filename=/etc/passwd  
```

如果 Web 服务器像这样处理，可能会带来大麻烦（伪代码）：

```
file = os.Open(request.GET['filename'])
return file.ReadAll()
```

你不能仅仅通过在路径前添加特定的目录来修复这个问题：

```
os.Open('/path/to/mydir/' + GET['filename']).
```

这还不够，因为攻击者可以利用目录遍历攻击回到文件系统的根目录，如下所示：

```
http://localhost/displayFile?filename=../../../etc/passwd   
```

确保在任何文件包含操作中检查目录遍历攻击。

# 被污染的文件

如果攻击者发现 LFI（本地文件包含漏洞），或者你提供了一个用于查看日志文件的 Web 界面，你需要确保即使日志被污染，也不会执行任何代码。

攻击者可能通过在你的服务上采取某些行动来污染你的日志并插入恶意代码，从而创建一个日志条目。任何生成的日志都必须加载或显示时，都必须考虑到这一点。

例如，Web 服务器日志可能会被通过对一个实际上是代码的 URL 发起 HTTP 请求而污染。你的日志将会有 `404 Not Found` 错误，并记录被请求的 URL，而该 URL 实际上是代码。如果是 PHP 服务器或其他脚本语言，这可能会导致潜在的代码执行，但在 Go 中，最糟糕的情况是 JavaScript 注入，这对用户仍然可能是危险的。想象一下这样的场景：一个 Web 应用程序有一个 HTTP 日志查看器，它从磁盘加载日志文件。如果攻击者向 `yourwebsite.com/<script>alert("test");</script>` 发起请求，那么如果 HTML 日志查看器没有正确地转义或清理代码，最终可能会渲染出这些代码。

# HTTP 客户端

现在，HTTP 请求是许多应用程序的核心部分。Go 语言作为一种 web 友好的语言，包含了多个用于发起 HTTP 请求的工具，这些工具位于 `net/http` 包中。

# 基本的 HTTP 请求

这个示例使用了来自 `net/http` 标准库包的 `http.Get()` 函数。它将整个响应体读取到名为 `body` 的变量中，然后将其打印到标准输出：

```
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
)

func main() {
   // Make basic HTTP GET request
   response, err := http.Get("http://www.example.com")
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Read body from response
   body, err := ioutil.ReadAll(response.Body)
   response.Body.Close()
   if err != nil {
      log.Fatal("Error reading response. ", err)
   }

   fmt.Printf("%s\n", body)
}
```

# 使用客户端 SSL 证书

如果远程 HTTPS 服务器有严格的身份验证并且需要受信任的客户端证书，你可以通过设置 `http.Transport` 对象中的 `TLSClientConfig` 变量来指定证书文件，该对象是 `http.Client` 用于发起 GET 请求的。

这个示例发起了一个类似于前面示例的 HTTP GET 请求，但它没有使用 `net/http` 包提供的默认 HTTP 客户端。它创建了一个自定义的 `http.Client` 并配置了它以使用带有客户端证书的 TLS。如果你需要证书或私钥，请参考 第六章，*加密学*，其中包含生成密钥和自签名证书的示例：

```
package main

import (
   "crypto/tls"
   "log"
   "net/http"
)

func main() {
   // Load cert
   cert, err := tls.LoadX509KeyPair("cert.pem", "privKey.pem")
   if err != nil {
      log.Fatal(err)
   }

   // Configure TLS client
   tlsConfig := &tls.Config{
      Certificates: []tls.Certificate{cert},
   }
   tlsConfig.BuildNameToCertificate()
   transport := &http.Transport{ 
      TLSClientConfig: tlsConfig, 
   }
   client := &http.Client{Transport: transport}

   // Use client to make request.
   // Ignoring response, just verifying connection accepted.
   _, err = client.Get("https://example.com")
   if err != nil {
      log.Println("Error making request. ", err)
   }
}
```

# 使用代理

正向代理对许多用途非常有用，包括查看 HTTP 流量、调试应用程序、逆向工程 API 和修改头信息，它也可以用来增加你在目标服务器上的匿名性。然而，要注意，许多代理服务器仍然通过 `X-Forwarded-For` 头部转发你的原始 IP。

你可以使用环境变量来设置代理，或者显式地在请求中设置代理。Go HTTP 客户端支持 HTTP、HTTPS 和 SOCKS5 代理，例如 Tor。

# 使用系统代理

Go 的默认 HTTP 客户端会尊重系统通过环境变量设置的 HTTP(S) 代理。Go 使用 `HTTP_PROXY`、`HTTPS_PROXY` 和 `NO_PROXY` 环境变量。小写版本也有效。你可以在运行进程之前设置环境变量，或者使用以下方式在 Go 中设置环境变量：

```
os.Setenv("HTTP_PROXY", "proxyIp:proxyPort")  
```

配置好环境变量后，任何使用默认 Go HTTP 客户端发起的 HTTP 请求都会遵循代理设置。了解更多关于默认代理设置的信息，请访问 [`golang.org/pkg/net/http/#ProxyFromEnvironment`](https://golang.org/pkg/net/http/#ProxyFromEnvironment)。

# 使用特定的 HTTP 代理

若要显式设置代理 URL，忽略环境变量，可以在自定义的 `http.Transport` 对象中设置 `ProxyURL` 变量，`http.Client` 会使用该自定义传输对象。以下示例创建了一个自定义的 `http.Transport` 并指定了 `proxyUrlString`。该示例中代理的值为占位符，需要替换为有效的代理。然后创建并配置 `http.Client` 使用带代理的自定义传输：

```
package main

import (
   "io/ioutil"
   "log"
   "net/http"
   "net/url"
   "time"
)

func main() {
   proxyUrlString := "http://<proxyIp>:<proxyPort>"
   proxyUrl, err := url.Parse(proxyUrlString)
   if err != nil {
      log.Fatal("Error parsing URL. ", err)
   }

   // Set up a custom HTTP transport for client
   customTransport := &http.Transport{ 
      Proxy: http.ProxyURL(proxyUrl), 
   }
   httpClient := &http.Client{ 
      Transport: customTransport, 
      Timeout:   time.Second * 5, 
   }

   // Make request
   response, err := httpClient.Get("http://www.example.com")
   if err != nil {
      log.Fatal("Error making GET request. ", err)
   }
   defer response.Body.Close()

   // Read and print response from server
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading body of response. ", err)
   }
   log.Println(string(body))
}
```

# 使用 SOCKS5 代理（Tor）

Tor 是一个匿名性服务，旨在保护你的隐私。除非你完全理解所有的影响，否则不要使用 Tor。了解更多关于 Tor 的信息，请访问 [`www.torproject.org`](https://www.torproject.org)。此示例展示了如何在发起请求时使用 Tor，但这同样适用于其他 SOCKS5 代理。

要使用 SOCKS5 代理，唯一需要修改的是代理的 URL 字符串。请使用 `socks5://` 协议前缀代替 HTTP 协议。

默认的 Tor 端口是 `9050`，或者在使用 Tor 浏览器捆绑包时是 `9150`。以下示例将执行一个 GET 请求到 `check.torproject.org`，通过该请求可以查看是否已正确通过 Tor 网络进行路由：

```
package main

import (
   "io/ioutil"
   "log"
   "net/http"
   "net/url"
   "time"
)

// The Tor proxy server must already be running and listening
func main() {
   targetUrl := "https://check.torproject.org"
   torProxy := "socks5://localhost:9050" // 9150 w/ Tor Browser

   // Parse Tor proxy URL string to a URL type
   torProxyUrl, err := url.Parse(torProxy)
   if err != nil {
      log.Fatal("Error parsing Tor proxy URL:", torProxy, ". ", err)
   }

   // Set up a custom HTTP transport for the client   
   torTransport := &http.Transport{Proxy: http.ProxyURL(torProxyUrl)}
   client := &http.Client{
      Transport: torTransport,
      Timeout: time.Second * 5
   }

   // Make request
   response, err := client.Get(targetUrl)
   if err != nil {
      log.Fatal("Error making GET request. ", err)
   }
   defer response.Body.Close()

   // Read response
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading body of response. ", err)
   }
   log.Println(string(body))
}
```

# 总结

在本章中，我们介绍了如何运行用 Go 编写的 Web 服务器的基础知识。现在，你应该能够创建一个基本的 HTTP 和 HTTPS 服务器。此外，你应该理解中间件的概念，并知道如何使用 Negroni 包实现预构建和自定义中间件。

我们还介绍了一些确保 Web 服务器安全的最佳实践。你应该理解 CSRF 攻击是什么，以及如何防止它。你应该能够解释本地和远程文件包含的概念以及相关的风险。

标准库中的 Web 服务器质量足以用于生产，它具备了创建生产就绪 Web 应用所需的一切。还有一些其他的 Web 应用框架，如 Gorilla、Revel 和 Martini，但最终你需要评估每个框架提供的功能，看看它们是否符合你的项目需求。

我们还讲解了标准库提供的 HTTP 客户端函数。你应该知道如何使用客户端证书发起基本的 HTTP 请求和认证请求。你应该理解如何在发起请求时使用 HTTP 代理。

在接下来的章节中，我们将探讨网页抓取技术，从 HTML 格式的网站中提取信息。我们将从基本技术开始，例如字符串匹配和正则表达式，还将探讨`goquery`包用于处理 HTML DOM。我们还将介绍如何使用 Cookie 在登录会话中进行爬取。此外，我们还会讨论指纹识别网站应用程序以识别框架。我们还将涵盖使用广度优先和深度优先方法爬取网络。

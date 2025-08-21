# 第十一章：主机发现与枚举

主机发现是查找网络上主机的过程。如果你已经访问了一个私有网络中的机器，并且想查看该网络上还有哪些机器，进而开始收集网络的概况，这个过程就很有用。你也可以将整个互联网视作网络，寻找某些类型的主机，或者只查找任何主机。Ping 扫描和端口扫描是识别主机的常见技术。nmap 是用于此目的的常用工具。在本章中，我们将介绍 TCP 连接扫描和横幅抓取的基本端口扫描，这两者是 nmap 的最常见用例之一。我们还将讨论可以用来手动交互并探索服务器端口的原始套接字连接。

枚举是一个类似的概念，但它指的是主动检查特定机器，尽可能多地获取信息。这包括扫描服务器的端口以查看哪些端口开放，抓取横幅以检查服务，调用各种服务获取版本号，并通常搜索攻击向量。

主机发现与枚举是有效渗透测试中的关键步骤，因为如果你甚至不知道某台机器存在，你就无法对其进行利用。例如，如果攻击者只知道如何使用`ping`命令来查找主机，那么你只需要忽略 ping 请求，就能轻松将所有主机隐藏起来，防止攻击者发现。

主机发现与枚举需要与机器建立主动连接，这样会留下日志，可能触发警报，或者让你被注意到。有一些方法可以做到偷偷摸摸，比如只进行 TCP SYN 扫描，避免建立完整的 TCP 连接，或在连接时使用代理，虽然这样并不能完全隐藏你的存在，但会让你看起来像是从别的地方连接的。如果 IP 被封锁，使用代理隐藏你的 IP 会很有用，因为你可以轻松切换到新的代理。

本章还会简要介绍模糊测试，虽然只是触及了这个话题。模糊测试本身值得一章的内容，实际上，已经有整本书专门讨论这个主题。模糊测试在逆向工程或寻找漏洞时更为有用，但也可以用于获取有关服务的信息。例如，某个服务可能不会返回任何响应，这样你就无法了解它的用途，但如果你用错误数据进行模糊测试，并且它返回了错误信息，你可能会了解到它期望什么类型的输入。

本章我们将专门讨论以下主题：

+   TCP 与 UDP 套接字

+   端口扫描

+   横幅抓取

+   TCP 代理

+   在网络上查找命名主机

+   网络服务模糊测试

# TCP 与 UDP 套接字

套接字是网络的构建块。服务器通过监听，客户端通过拨号来使用套接字绑定在一起并共享信息。**互联网协议**（**IP**）层指定了机器的地址，但**传输控制协议**（**TCP**）或**用户数据报协议**（**UDP**）指定了应使用机器上的哪个端口。

两者之间的主要区别在于连接状态。TCP 保持连接并验证消息是否被接收，而 UDP 仅发送消息，而不接收来自远程主机的确认。

# 创建服务器

这是一个示例服务器。如果你想更改协议，可以将 `net.Listen()` 中的 `tcp` 参数改为 `udp`：

```
package main

import (
   "net"
   "fmt"
   "log"
)

var protocol = "tcp" // tcp or udp
var listenAddress = "localhost:3000"

func main() {
   listener, err := net.Listen(protocol, listenAddress)
   if err != nil {
      log.Fatal("Error creating listener. ", err)
   }
   log.Printf("Now listening for connections.")

   for {
      conn, err := listener.Accept()
      if err != nil {
         log.Println("Error accepting connection. ", err)
      }
      go handleConnection(conn)
   }
}

func handleConnection(conn net.Conn) {
   incomingMessageBuffer := make([]byte, 4096)

   numBytesRead, err := conn.Read(incomingMessageBuffer)
   if err != nil {
      log.Print("Error reading from client. ", err)
   }

   fmt.Fprintf(conn, "Thank you. I processed %d bytes.\n", 
      numBytesRead)
} 
```

# 创建客户端

这个示例创建了一个简单的网络客户端，它将与前一个示例中的服务器一起工作。这个示例使用 TCP，但像 `net.Listen()` 一样，如果你想切换协议，只需在 `net.Dial()` 中将 `tcp` 换成 `udp` 即可：

```
package main

import (
   "net"
   "log"
)

var protocol = "tcp" // tcp or udp
var remoteHostAddress = "localhost:3000"

func main() {
   conn, err := net.Dial(protocol, remoteHostAddress)
   if err != nil {
      log.Fatal("Error creating listener. ", err)
   }
   conn.Write([]byte("Hello, server. Are you there?"))

   serverResponseBuffer := make([]byte, 4096)
   numBytesRead, err := conn.Read(serverResponseBuffer)
   if err != nil {
      log.Print("Error reading from server. ", err)
   }
   log.Println("Message recieved from server:")
   log.Printf("%s\n", serverResponseBuffer[0:numBytesRead])
} 
```

# 端口扫描

在网络上找到主机后，可能是通过执行 ping 扫描或监控网络流量，你通常会想要扫描端口，查看哪些端口是开放并接受连接的。通过查看哪些端口开放，你可以学到很多关于机器的信息。你可能能判断它是 Windows 还是 Linux，或者它是否托管着邮件服务器、Web 服务器、数据库服务器等。

端口扫描有很多种类型，但这个示例演示了最基础和直接的端口扫描示例，这是一个 TCP 连接扫描。它像典型的客户端一样连接，看看服务器是否接受请求。它不会发送或接收任何数据，并在成功时立即断开连接，记录是否成功。

以下示例只扫描本地主机，并将检查的端口限制在保留端口 0-1024 范围内。数据库服务器，如 MySQL，通常监听较高的端口，如 `3306`，因此你可能需要调整端口范围或使用预定义的常见端口列表。

每个 TCP 连接请求都会在单独的 goroutine 中执行，因此它们将并发运行，并且非常快速地完成。`net.DialTimeout()` 函数被用来设置我们愿意等待的最大时间：

```
package main

import (
   "strconv"
   "log"
   "net"
   "time"
)

var ipToScan = "127.0.0.1"
var minPort = 0
var maxPort = 1024

func main() {
   activeThreads := 0
   doneChannel := make(chan bool)

   for port := minPort; port <= maxPort ; port++ {
      go testTcpConnection(ipToScan, port, doneChannel)
      activeThreads++
   }

   // Wait for all threads to finish
   for activeThreads > 0 {
      <- doneChannel
      activeThreads--
   }
}

func testTcpConnection(ip string, port int, doneChannel chan bool) {
   _, err := net.DialTimeout("tcp", ip + ":" + strconv.Itoa(port), 
      time.Second*10)
   if err == nil {
      log.Printf("Port %d: Open\n", port)
   }
   doneChannel <- true
} 
```

# 从服务中抓取横幅

确定了开放的端口后，你可以尝试从连接中读取，看看服务是否提供了一个横幅或初始消息。

以下示例与之前类似，但与仅连接和断开连接不同，它将连接并尝试从服务器读取初始消息。如果服务器提供任何数据，它会被打印出来；但如果服务器没有发送任何数据，则什么也不会显示：

```
package main

import (
   "strconv"
   "log"
   "net"
   "time"
)

var ipToScan = "127.0.0.1"

func main() {
   activeThreads := 0
   doneChannel := make(chan bool)

   for port := 0; port <= 1024 ; port++ {
      go grabBanner(ipToScan, port, doneChannel)
      activeThreads++
   }

   // Wait for all threads to finish
   for activeThreads > 0 {
      <- doneChannel
      activeThreads--
   }
}

func grabBanner(ip string, port int, doneChannel chan bool) {
   connection, err := net.DialTimeout(
      "tcp", 
      ip + ":"+strconv.Itoa(port),  
      time.Second*10)
   if err != nil {
      doneChannel<-true
      return
   }

   // See if server offers anything to read
   buffer := make([]byte, 4096)
   connection.SetReadDeadline(time.Now().Add(time.Second*5)) 
   // Set timeout
   numBytesRead, err := connection.Read(buffer)
   if err != nil {
      doneChannel<-true
      return
   }
   log.Printf("Banner from port %d\n%s\n", port,
      buffer[0:numBytesRead])

   doneChannel <- true
} 
```

# 创建 TCP 代理

就像在第九章中的 HTTP 代理一样，*Web 应用程序*，TCP 级代理也可以用于调试、日志记录、流量分析和隐私保护。在进行端口扫描、主机发现和枚举时，代理可以帮助隐藏你的位置信息和源 IP 地址。你可能想隐藏你的来源位置，伪装身份，或者在执行请求时使用一个临时 IP，以防你因被列入黑名单而受阻。

以下例子将监听本地端口，将请求转发到远程主机，然后将远程服务器的响应返回给客户端。它还会记录所有请求。

你可以通过运行前一节中的服务器，并设置代理转发到该服务器，来测试这个代理。当回显服务器和代理服务器运行时，使用 TCP 客户端连接到代理服务器：

```
package main

import (
   "net"
   "log"
)

var localListenAddress = "localhost:9999"
var remoteHostAddress = "localhost:3000" // Not required to be remote

func main() {
   listener, err := net.Listen("tcp", localListenAddress)
   if err != nil {
      log.Fatal("Error creating listener. ", err)
   }

   for {
      conn, err := listener.Accept()
      if err != nil {
         log.Println("Error accepting connection. ", err)
      }
      go handleConnection(conn)
   }
}

// Forward the request to the remote host and pass response 
// back to client
func handleConnection(localConn net.Conn) {
   // Create remote connection that will receive forwarded data
   remoteConn, err := net.Dial("tcp", remoteHostAddress)
   if err != nil {
      log.Fatal("Error creating listener. ", err)
   }
   defer remoteConn.Close()

   // Read from the client and forward to remote host
   buf := make([]byte, 4096) // 4k buffer
   numBytesRead, err := localConn.Read(buf)
   if err != nil {
      log.Println("Error reading from client.", err)
   }
   log.Printf(
      "Forwarding from %s to %s:\n%s\n\n",
      localConn.LocalAddr(),
      remoteConn.RemoteAddr(),
      buf[0:numBytesRead],
   )
   _, err = remoteConn.Write(buf[0:numBytesRead])
   if err != nil {
      log.Println("Error writing to remote host. ", err)
   }

   // Read response from remote host and pass it back to our client
   buf = make([]byte, 4096)
   numBytesRead, err = remoteConn.Read(buf)
   if err != nil {
      log.Println("Error reading from remote host. ", err)
   }
   log.Printf(
      "Passing response back from %s to %s:\n%s\n\n",
      remoteConn.RemoteAddr(),
      localConn.LocalAddr(),
      buf[0:numBytesRead],
   )
   _, err = localConn.Write(buf[0:numBytesRead])
   if err != nil {
      log.Println("Error writing back to client.", err)
   }
}
```

# 在网络上查找命名的主机

如果你刚刚获得对一个网络的访问权限，首先可以做的事情之一就是了解网络上有哪些主机。你可以扫描子网上的所有 IP 地址，然后进行 DNS 查询，看看能否找到任何命名的主机。主机名可以具有描述性或信息性名称，从中可以得知服务器可能运行的服务。

默认情况下，纯 Go 解析器只能阻塞一个 goroutine，而不是系统线程，从而提高了一些效率。你可以通过设置环境变量显式指定 DNS 解析器：

```
export GODEBUG=netdns=go    # Use pure Go resolver (default)
export GODEBUG=netdns=cgo   # Use cgo resolver
```

这个例子查找子网中的所有可能主机，并尝试为每个 IP 解析主机名：

```
package main

import (
   "strconv"
   "log"
   "net"
   "strings"
)

var subnetToScan = "192.168.0" // First three octets

func main() {
   activeThreads := 0
   doneChannel := make(chan bool)

   for ip := 0; ip <= 255; ip++ {
      fullIp := subnetToScan + "." + strconv.Itoa(ip)
      go resolve(fullIp, doneChannel)
      activeThreads++
   }

   // Wait for all threads to finish
   for activeThreads > 0 {
      <- doneChannel
      activeThreads--
   }
}

func resolve(ip string, doneChannel chan bool) {
   addresses, err := net.LookupAddr(ip)
   if err == nil {
      log.Printf("%s - %s\n", ip, strings.Join(addresses, ", "))
   }
   doneChannel <- true
} 
```

# 对网络服务进行模糊测试

模糊测试是向应用程序发送故意构造的错误格式、过多或随机的数据，试图使其行为异常、崩溃或泄露敏感信息。你可以通过模糊测试识别缓冲区溢出漏洞，这可能导致远程代码执行。如果你发送特定大小的数据后导致应用程序崩溃或停止响应，可能是由于缓冲区溢出引起的。

有时，你可能仅仅是通过让服务使用过多内存或占用所有处理能力，导致服务拒绝。正则表达式以其极慢而著称，且可能在 Web 应用程序的 URL 路由机制中被滥用，消耗大量 CPU，尽管请求数很少。

非随机但格式错误的数据可能同样危险，甚至更为严重。一个适当格式错误的视频文件可能导致 VLC 崩溃并暴露代码执行漏洞。一个适当格式错误的数据包，改变 1 个字节，就可能导致敏感数据泄露，就像 Heartbleed OpenSSL 漏洞一样。

以下例子将演示一个非常基础的 TCP 模糊测试器。它向服务器发送长度逐渐增加的随机字节。它从 1 个字节开始，然后以 2 的幂指数增长。首先发送 1 个字节，然后是 2、4、8、16，继续发送，直到出现错误或达到最大配置限制。

调整`maxFuzzBytes`以设置发送到服务的最大数据大小。注意，它会同时启动所有线程，所以要小心服务器负载。查看响应中的异常或服务器的完全崩溃：

```
package main

import (
   "crypto/rand"
   "log"
   "net"
   "strconv"
   "time"
)

var ipToScan = "www.devdungeon.com"
var port = 80
var maxFuzzBytes = 1024

func main() {
   activeThreads := 0
   doneChannel := make(chan bool)

   for fuzzSize := 1; fuzzSize <= maxFuzzBytes; 
      fuzzSize = fuzzSize * 2 {
      go fuzz(ipToScan, port, fuzzSize, doneChannel)
      activeThreads++
   }

   // Wait for all threads to finish
   for activeThreads > 0 {
      <- doneChannel
      activeThreads--
   }
}

func fuzz(ip string, port int, fuzzSize int, doneChannel chan bool) {
   log.Printf("Fuzzing %d.\n", fuzzSize)

   conn, err := net.DialTimeout("tcp", ip + ":" + strconv.Itoa(port), 
      time.Second*10)
   if err != nil {
      log.Printf(
         "Fuzz of %d attempted. Could not connect to server. %s\n", 
         fuzzSize, 
         err,
      )
      doneChannel <- true
      return
   }

   // Write random bytes to server
   randomBytes := make([]byte, fuzzSize)
   rand.Read(randomBytes)
   conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
   numBytesWritten, err := conn.Write(randomBytes)
   if err != nil { // Error writing
      log.Printf(
         "Fuzz of %d attempted. Could not write to server. %s\n", 
         fuzzSize,
         err,
      )
      doneChannel <- true
      return
   }
   if numBytesWritten != fuzzSize {
      log.Printf("Unable to write the full %d bytes.\n", fuzzSize)
   }
   log.Printf("Sent %d bytes:\n%s\n\n", numBytesWritten, randomBytes)

   // Read up to 4k back
   readBuffer := make([]byte, 4096)
   conn.SetReadDeadline(time.Now().Add(time.Second *5))
   numBytesRead, err := conn.Read(readBuffer)
   if err != nil { // Error reading
      log.Printf(
         "Fuzz of %d attempted. Could not read from server. %s\n", 
         fuzzSize,
         err,
      )
      doneChannel <- true
      return
   }

   log.Printf(
      "Sent %d bytes to server. Read %d bytes back:\n,
      fuzzSize,
      numBytesRead, 
   )
   log.Printf(
      "Data:\n%s\n\n",
      readBuffer[0:numBytesRead],
   )
   doneChannel <- true
} 
```

# 总结

阅读完本章后，你应该已经理解了主机发现和枚举的基本概念。你应该能够从高层次解释这些概念，并提供每个概念的基本示例。

首先，我们讨论了原始的 TCP 套接字，并通过一个简单的服务器和客户端的示例来说明。虽然这些示例本身并不是特别有用，但它们是构建与服务进行自定义交互的工具的模板。这在尝试指纹识别一个未识别的服务时会非常有帮助。

你现在应该知道如何运行一个简单的端口扫描，并理解为什么你可能需要进行端口扫描。你应该理解如何使用 TCP 代理及其所带来的好处。你应该理解横幅抓取的原理，并知道为什么它是收集信息的一个有用方法。

还有许多其他形式的枚举。在 Web 应用程序中，你可以枚举用户名、用户 ID、电子邮件等。例如，如果一个网站使用 URL 格式 [www.example.com/user_profile/1234](http://www.example.com/user_profile/1234)，你可以从数字 1 开始，并每次递增 1，遍历网站上所有的用户个人资料。其他形式的枚举包括 SNMP、DNS、LDAP 和 SMB。

你能想到其他什么形式的枚举？如果你已经是服务器上一个低权限用户，你能想到什么样的枚举？一旦你有了一个 shell，你想收集关于服务器的哪些信息？

一旦你进入服务器，你可以收集大量信息：用户名和用户组、主机名、网络设备信息、挂载的文件系统、正在运行的服务、iptables 设置、定时任务、启动服务等。有关获取机器访问权限后的更多信息，请参考第十三章，*后期利用*。

在下一章，我们将讨论社会工程学，以及如何通过 JSON REST API 从网络收集情报、发送钓鱼邮件并生成二维码。我们还将介绍多个蜜罐的示例，包括 TCP 蜜罐和两种 HTTP 蜜罐的方法。

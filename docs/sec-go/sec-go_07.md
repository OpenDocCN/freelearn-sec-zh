# 第七章：安全外壳（SSH）

**安全外壳（SSH）**是一种用于在不安全网络上进行通信的加密网络协议。SSH 最常见的用途是连接到远程服务器并与 shell 交互。还可以通过 SSH 协议进行文件传输，如 SCP 和 SFTP。SSH 的创建是为了取代明文协议 Telnet。随着时间的推移，有许多 RFC 定义了 SSH。以下是一部分列出的 RFC，以帮助理解其定义。由于它是如此常见和关键的协议，值得花时间了解其详细信息。以下是其中一些 RFC：

+   *RFC 4250* ([`tools.ietf.org/html/rfc4250`](https://tools.ietf.org/html/rfc4250)): *安全外壳（SSH）协议分配号码*

+   *RFC 4251* ([`tools.ietf.org/html/rfc4251`](https://tools.ietf.org/html/rfc4251)): *安全外壳（SSH）协议架构*

+   *RFC 4252* ([`tools.ietf.org/html/rfc4252`](https://tools.ietf.org/html/rfc4252)): *安全外壳（SSH）身份验证协议*

+   *RFC 4253* ([`tools.ietf.org/html/rfc4253`](https://tools.ietf.org/html/rfc4253)): *安全外壳（SSH）传输层协议*

+   *RFC 4254* ([`tools.ietf.org/html/rfc4254`](https://tools.ietf.org/html/rfc4254)): *安全外壳（SSH）连接协议*

+   *RFC 4255* ([`tools.ietf.org/html/rfc4255`](https://tools.ietf.org/html/rfc4255)): *使用 DNS 安全发布安全外壳（SSH）密钥指纹*

+   *RFC 4256* ([`tools.ietf.org/html/rfc4256`](https://tools.ietf.org/html/rfc4256)): *安全外壳协议（SSH）的通用消息交换认证*

+   *RFC 4335* ([`tools.ietf.org/html/rfc4335`](https://tools.ietf.org/html/rfc4335)): **安全外壳（SSH）会话通道断开扩展**

+   *RFC 4344* ([`tools.ietf.org/html/rfc4344`](https://tools.ietf.org/html/rfc4344)): *安全外壳（SSH）传输层加密模式*

+   *RFC 4345* ([`tools.ietf.org/html/rfc4345`](https://tools.ietf.org/html/rfc4345)): *安全外壳（SSH）传输层协议的改进 Arcfour 模式*

后来标准还有其他扩展，您可以在[`en.wikipedia.org/wiki/Secure_Shell#Standards_documentation`](https://en.wikipedia.org/wiki/Secure_Shell#Standards_documentation)上了解更多信息。

SSH 是互联网上常见的暴力破解和默认凭证攻击目标。因此，您可以考虑将 SSH 放在非标准端口上，但仍需将其保留在系统端口（小于 1024），以防止低权限用户在服务崩溃时可能劫持端口。如果保留 SSH 在默认端口上，像`fail2ban`这样的服务在限制速率和阻止暴力攻击方面将非常有价值。理想情况下，应完全禁用密码身份验证，并要求使用密钥进行身份验证。

SSH 包并未随标准库一起打包，尽管它是由 Go 团队编写的。它是 Go 项目的正式组成部分，但位于 Go 源代码树之外，因此默认情况下不会与 Go 一起安装。它可以从 [`golang.org/`](https://golang.org/) 获取，并可以使用以下命令安装：

```
go get golang.org/x/crypto/ssh
```

本章将介绍如何使用 SSH 客户端连接、执行命令并使用交互式 shell。我们还将介绍不同的身份验证方法，例如使用密码或私钥。SSH 包提供了创建服务器的功能，但本书仅介绍客户端部分。

本章将专门涵盖 SSH 的以下内容：

+   使用密码进行身份验证

+   使用私钥进行身份验证

+   验证远程主机的密钥

+   通过 SSH 执行命令

+   启动交互式 shell

# 使用 Go SSH 客户端

`golang.org/x/crypto/ssh` 包提供了与 SSH 版本 2（最新版本）兼容的 SSH 客户端。该客户端可以与 OpenSSH 服务器以及任何遵循 SSH 规范的其他服务器一起使用。它支持传统的客户端功能，如子进程、端口转发和隧道。

# 身份验证方法

身份验证不仅是第一步，而且是最关键的一步。身份验证不当可能导致机密性、完整性和可用性的潜在丧失。如果远程服务器没有经过验证，可能会发生中间人攻击，导致数据被窃听、篡改或阻塞。弱密码身份验证可能会受到暴力破解攻击的利用。

这里提供了三个示例。第一个示例涵盖了常见的密码身份验证，但不推荐使用，因为与加密密钥相比，密码的熵值和位数较低。第二个示例演示了如何使用私钥与远程服务器进行身份验证。这两个示例都忽略了远程主机提供的公钥。这是不安全的，因为你可能最终连接到一个你不信任的远程主机，但对于测试来说已经足够。第三个身份验证示例是理想的流程。它通过密钥进行身份验证，并验证远程服务器。

请注意，本章没有使用 第六章 中的 PEM 格式密钥文件，*密码学*。本章使用的是 SSH 格式的密钥，这是处理 SSH 时最常见的格式。这些示例与 OpenSSH 工具和密钥兼容，如 `ssh`、`sshd`、`ssh-keygen`、`ssh-copy-id` 和 `ssh-keyscan`。

我建议你使用 `ssh-keygen` 来生成用于身份验证的公钥和私钥对。这将生成 SSH 密钥格式的 `id_rsa` 和 `id_rsa.pub` 文件。`ssh-keygen` 工具是 OpenSSH 项目的一部分，并且默认与 Ubuntu 一起打包：

```
ssh-keygen
```

使用`ssh-copy-id`将你的公钥（`id_rsa.pub`）复制到远程服务器的`~/.ssh/authorized_keys`文件中，这样你就可以使用私钥进行身份验证：

```
ssh-copy-id yourserver.com
```

# 使用密码进行身份验证

通过 SSH 进行密码认证是最简单的方法。此示例演示了如何使用`ssh.ClientConfig`结构配置 SSH 客户端，然后使用`ssh.Dial()`连接到 SSH 服务器。客户端被配置为通过指定`ssh.Password()`作为身份验证函数来使用密码：

```
package main

import (
   "golang.org/x/crypto/ssh"
   "log"
)

var username = "username"
var password = "password"
var host = "example.com:22"

func main() {
   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.Password(password),
      },
      HostKeyCallback: ssh.InsecureIgnoreHostKey(),
   }
   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   log.Println(string(client.ClientVersion()))
} 
```

# 使用私钥进行身份验证

私钥相比密码有一些优势。它比密码长得多，使得暴力破解变得更加困难。它还消除了输入密码的需求，方便连接远程服务器。无密码身份验证对于 cron 任务和其他需要自动运行的服务非常有用。此外，一些服务器完全禁用了密码身份验证，要求使用密钥。

远程服务器需要将你的公钥设置为授权密钥，才能通过私钥进行身份验证。

如果你的系统上有`ssh-copy-id`工具，你可以使用它。它会将你的公钥复制到远程服务器，放置在主文件夹的 SSH 目录中（`~/.ssh/authorized_keys`），并设置正确的权限：

```
ssh-copy-id example.com 
```

以下示例与之前的示例类似，我们使用密码进行身份验证，但`ssh.ClientConfig`配置为使用`ssh.PublicKeys()`作为身份验证函数，而不是`ssh.Password()`。我们还将创建一个名为`getKeySigner()`的特殊函数，以便从文件中加载客户端的私钥：

```
package main

import (
   "golang.org/x/crypto/ssh"
   "io/ioutil"
   "log"
)

var username = "username"
var host = "example.com:22"
var privateKeyFile = "/home/user/.ssh/id_rsa"

func getKeySigner(privateKeyFile string) ssh.Signer {
   privateKeyData, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   privateKey, err := ssh.ParsePrivateKey(privateKeyData)
   if err != nil {
      log.Fatal("Error parsing private key. ", err)
   }
   return privateKey
}

func main() {
   privateKey := getKeySigner(privateKeyFile)
   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.PublicKeys(privateKey), // Pass 1 or more key
      },
      HostKeyCallback: ssh.InsecureIgnoreHostKey(),
   }

   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   log.Println(string(client.ClientVersion()))
} 
```

请注意，你可以将多个私钥传递给`ssh.PublicKeys()`函数。它可以接受无限数量的密钥。如果你提供了多个密钥，而只有一个能够正常工作，系统将自动使用那个有效的密钥。

如果你希望使用相同的配置连接多个服务器，这将非常有用。你可能希望使用 1,000 个不同的主机名连接到 1,000 个不同的服务器，并使用 1,000 个独特的私钥。你无需为每个主机配置多个 SSH 客户端配置，而是可以重用一个包含所有私钥的单一配置。

# 验证远程主机

要验证远程主机，在`ssh.ClientConfig`中，将`HostKeyCallback`设置为`ssh.FixedHostKey()`并传入远程主机的公钥。如果你尝试连接到服务器且它提供了不同的公钥，连接将会被中断。这对于确保你连接到的是预期的服务器而不是恶意服务器非常重要。如果 DNS 遭到破坏，或者攻击者成功执行了 ARP 欺骗攻击，你的连接可能会被重定向，或者成为中间人攻击的受害者，但攻击者无法在没有相应私钥的情况下伪装成真实服务器。为了测试目的，你可以选择忽略远程主机提供的密钥。

这个示例是连接的最安全方式。它使用密钥进行身份验证，而不是密码，并且验证远程服务器的公钥。

该方法将使用 `ssh.ParseKnownHosts()`。它使用标准的 `known_hosts` 文件。`known_hosts` 格式是 OpenSSH 的标准格式，文档可以参考 *sshd(8)* 手册页。

请注意，Go 的 `ssh.ParseKnownHosts()` 只会解析单一条目，因此你应创建一个包含单个条目的唯一文件，或者确保所需条目位于文件的顶部。

要获取远程服务器的公钥以进行验证，可以使用 `ssh-keyscan`。它将返回以 `known_hosts` 格式的服务器密钥，以下示例将使用该格式。记住，Go 的 `ssh.ParseKnownHosts` 命令只会读取 `known_hosts` 文件中的第一条条目：

```
ssh-keyscan yourserver.com
```

`ssh-keyscan` 程序会返回多种密钥类型，除非通过 `-t` 标志指定了密钥类型。确保选择与所需密钥算法匹配的类型，并且 `ssh.ClientConfig()` 中列出的 `HostKeyAlgorithm` 也要匹配。此示例包括了所有可能的 `ssh.KeyAlgo*` 选项。我建议你选择最强的算法，并只允许该选项：

```
package main

import (
   "golang.org/x/crypto/ssh"
   "io/ioutil"
   "log"
)

var username = "username"
var host = "example.com:22"
var privateKeyFile = "/home/user/.ssh/id_rsa"

// Known hosts only reads FIRST entry
var knownHostsFile = "/home/user/.ssh/known_hosts"

func getKeySigner(privateKeyFile string) ssh.Signer {
   privateKeyData, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   privateKey, err := ssh.ParsePrivateKey(privateKeyData)
   if err != nil {
      log.Fatal("Error parsing private key. ", err)
   }
   return privateKey
}

func loadServerPublicKey(knownHostsFile string) ssh.PublicKey {
   publicKeyData, err := ioutil.ReadFile(knownHostsFile)
   if err != nil {
      log.Fatal("Error loading server public key file. ", err)
   }

   _, _, publicKey, _, _, err := ssh.ParseKnownHosts(publicKeyData)
   if err != nil {
      log.Fatal("Error parsing server public key. ", err)
   }
   return publicKey
}

func main() {
   userPrivateKey := getKeySigner(privateKeyFile)
   serverPublicKey := loadServerPublicKey(knownHostsFile)

   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.PublicKeys(userPrivateKey),
      },
      HostKeyCallback: ssh.FixedHostKey(serverPublicKey),
      // Acceptable host key algorithms (Allow all)
      HostKeyAlgorithms: []string{
         ssh.KeyAlgoRSA,
         ssh.KeyAlgoDSA,
         ssh.KeyAlgoECDSA256,
         ssh.KeyAlgoECDSA384,
         ssh.KeyAlgoECDSA521,
         ssh.KeyAlgoED25519,
      },
   }

   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   log.Println(string(client.ClientVersion()))
} 
```

请注意，除了 `ssh.KeyAlgo*` 常量外，如果使用证书，还有 `ssh.CertAlgo*` 常量。

# 执行 SSH 命令

现在我们已经建立了多种身份验证和连接远程 SSH 服务器的方式，我们需要开始使用 `ssh.Client`。到目前为止，我们只是在打印客户端版本。第一个目标是执行一个命令并查看输出。

一旦创建了 `ssh.Client`，你可以开始创建会话。一个客户端可以同时支持多个会话。每个会话都有自己的标准输入、输出和错误，它们是标准的读写接口。

执行命令有几种选择：`Run()`、`Start()`、`Output()` 和 `CombinedOutput()`。它们非常相似，但行为略有不同：

+   `session.Output(cmd)`：`Output()` 函数将执行命令，并返回 `session.Stdout` 作为字节切片。

+   `session.CombinedOutput(cmd)`：此函数与 `Output()` 相同，但它将返回标准输出和标准错误的组合。

+   `session.Run(cmd)`：`Run()` 函数将执行命令并等待其完成。它会填充标准输出和错误缓冲区，但不会对它们做任何处理。你必须手动读取缓冲区，或者在调用 `Run()` 前将会话输出设置为终端输出（例如，`session.Stdout = os.Stdout`）。只有当程序以错误代码 `0` 退出且没有出现标准输出缓冲区复制问题时，它才会返回并且不报错。

+   `session.Start(cmd)`：`Start()`函数与`Run()`类似，唯一的不同是它不会等待命令完成。如果你希望在命令完成之前阻塞执行，必须显式调用`session.Wait()`。这个方法对于启动长时间运行的命令或需要更多控制应用程序流程的场景非常有用。

一个会话只能执行一个操作。一旦调用了`Run()`、`Output()`、`CombinedOutput()`、`Start()`或`Shell()`，该会话就不能用于执行其他命令。如果你需要运行多个命令，可以将它们用分号分隔在一起。例如，可以像这样将多个命令传递到单个命令字符串中：

```
df -h; ps aux; pwd; whoami;
```

否则，你可以为每个需要执行的命令创建一个新的会话。一个会话等同于一个命令。

以下示例使用密钥认证连接到远程 SSH 服务器，然后使用`client.NewSession()`创建一个会话。会话的标准输出被连接到我们本地终端的标准输出，然后调用`session.Run()`，它将在远程服务器上执行命令：

```
package main

import (
   "golang.org/x/crypto/ssh"
   "io/ioutil"
   "log"
   "os"
)

var username = "username"
var host = "example.com:22"
var privateKeyFile = "/home/user/.ssh/id_rsa"
var commandToExecute = "hostname"

func getKeySigner(privateKeyFile string) ssh.Signer {
   privateKeyData, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   privateKey, err := ssh.ParsePrivateKey(privateKeyData)
   if err != nil {
      log.Fatal("Error parsing private key. ", err)
   }
   return privateKey
}

func main() {
   privateKey := getKeySigner(privateKeyFile)
   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.PublicKeys(privateKey),
      },
      HostKeyCallback: ssh.InsecureIgnoreHostKey(),
   }

   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   // Multiple sessions per client are allowed
   session, err := client.NewSession()
   if err != nil {
      log.Fatal("Failed to create session: ", err)
   }
   defer session.Close()

   // Pipe the session output directly to standard output
   // Thanks to the convenience of writer interface
   session.Stdout = os.Stdout

   err = session.Run(commandToExecute)
   if err != nil {
      log.Fatal("Error executing command. ", err)
   }
} 
```

# 启动交互式 Shell

在之前的示例中，我们展示了如何运行命令字符串。还有一个选项是打开一个 Shell。通过调用`session.Shell()`，会执行一个交互式登录 Shell，加载用户的默认 Shell 并加载默认配置文件（例如，`.profile`）。调用`session.RequestPty()`是可选的，但当请求伪终端时，Shell 的表现会更好。你可以将终端名称设置为`xterm`、`vt100`、`linux`，或自定义名称。如果由于输出颜色值而导致乱码，尝试使用`vt100`，如果仍然无法解决问题，可以使用非标准的终端名称，或使用你知道不支持颜色的终端名称。许多程序会在不识别终端名称时禁用颜色输出。某些程序在遇到未知终端类型时可能无法正常工作，例如`tmux`。

更多关于 Go 终端模式常量的信息可以在[`godoc.org/golang.org/x/crypto/ssh#TerminalModes`](https://godoc.org/golang.org/x/crypto/ssh#TerminalModes)中找到。终端模式标志是 POSIX 标准，定义在*RFC 4254*的*终端模式编码*（第八部分）中，你可以在[`tools.ietf.org/html/rfc4254#section-8`](https://tools.ietf.org/html/rfc4254#section-8)找到相关内容。

以下示例使用密钥认证连接到 SSH 服务器，然后通过`client.NewSession()`创建一个新会话。与之前的示例不同，我们不会使用`session.Run()`执行命令，而是使用`session.RequestPty()`来获取一个交互式 Shell。来自远程会话的标准输入、输出和错误流都会连接到本地终端，因此你可以像其他任何 SSH 客户端一样实时与其互动（例如，PuTTY）：

```
package main

import (
   "fmt"
   "golang.org/x/crypto/ssh"
   "io/ioutil"
   "log"
   "os"
)

func checkArgs() (string, string, string) {
   if len(os.Args) != 4 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1], os.Args[2], os.Args[3]
}

func printUsage() {
   fmt.Println(os.Args[0] + ` - Open an SSH shell

Usage:
  ` + os.Args[0] + ` <username> <host> <privateKeyFile>

Example:
  ` + os.Args[0] + ` nanodano devdungeon.com:22 ~/.ssh/id_rsa
`)
}

func getKeySigner(privateKeyFile string) ssh.Signer {
   privateKeyData, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   privateKey, err := ssh.ParsePrivateKey(privateKeyData)
   if err != nil {
      log.Fatal("Error parsing private key. ", err)
   }
   return privateKey
}

func main() {
   username, host, privateKeyFile := checkArgs()

   privateKey := getKeySigner(privateKeyFile)
   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.PublicKeys(privateKey),
      },
      HostKeyCallback: ssh.InsecureIgnoreHostKey(),
   }

   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   session, err := client.NewSession()
   if err != nil {
      log.Fatal("Failed to create session: ", err)
   }
   defer session.Close()

   // Pipe the standard buffers together
   session.Stdout = os.Stdout
   session.Stdin = os.Stdin
   session.Stderr = os.Stderr

   // Get psuedo-terminal
   err = session.RequestPty(
      "vt100", // or "linux", "xterm"
      40,      // Height
      80,      // Width
      // https://godoc.org/golang.org/x/crypto/ssh#TerminalModes
      // POSIX Terminal mode flags defined in RFC 4254 Section 8.
      // https://tools.ietf.org/html/rfc4254#section-8
      ssh.TerminalModes{
         ssh.ECHO: 0,
      })
   if err != nil {
      log.Fatal("Error requesting psuedo-terminal. ", err)
   }

   // Run shell until it is exited
   err = session.Shell()
   if err != nil {
      log.Fatal("Error executing command. ", err)
   }
   session.Wait()
} 
```

# 总结

阅读完本章后，你应该已经理解如何使用 Go SSH 客户端通过密码或私钥进行连接和认证。此外，你现在应该了解如何在远程服务器上执行命令，或者如何开始交互式会话。

你如何以编程方式应用 SSH 客户端？你能想到什么使用场景吗？你是否管理多个远程服务器？你能否自动化某些任务？

SSH 包还包含用于创建 SSH 服务器的类型和函数，但我们在本书中没有涉及这些内容。关于创建 SSH 服务器的更多信息，请阅读 [`godoc.org/golang.org/x/crypto/ssh#NewServerConn`](https://godoc.org/golang.org/x/crypto/ssh#NewServerConn)，以及关于 SSH 包的更多信息，请阅读 [`godoc.org/golang.org/x/crypto/ssh`](https://godoc.org/golang.org/x/crypto/ssh)。

在下一章中，我们将讨论暴力破解攻击，即通过不断猜测密码，直到最终找到正确的密码。暴力破解是我们可以使用 SSH 客户端以及其他协议和应用程序进行的操作。继续阅读下一章，了解如何执行暴力破解攻击。

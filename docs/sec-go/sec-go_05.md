# 第五章：数据包捕获与注入

数据包捕获是监控通过网络传输的原始流量的过程。这适用于有线以太网和无线网络设备。`tcpdump` 和 `libpcap` 包是数据包捕获的标准。它们是在 1980 年代编写的，至今仍在使用。`gopacket` 包不仅封装了 C 库，还增加了 Go 的抽象层，使其更加符合 Go 语言的习惯并更便于使用。

`pcap` 库允许你收集关于网络设备的信息，读取从网络传输的数据包，*从链路上* 存储流量到 `.pcap` 文件，根据多个标准过滤流量，或者伪造自定义数据包并通过网络设备发送。对于 `pcap` 库，过滤是通过 **伯克利数据包过滤器** (**BPF**) 完成的。

数据包捕获有无数的用途。它可以用来设置蜜罐并监控接收到的流量类型。它可以帮助法医调查，以确定哪些主机执行了恶意操作，哪些主机被利用。它可以协助识别网络中的瓶颈。它也可以被恶意使用，用于从无线网络窃取信息、执行数据包扫描、模糊测试、ARP 欺骗等攻击。

这些示例需要非 Go 依赖项和 `libpcap` 包，因此，运行起来可能会更具挑战性。如果你没有将 Linux 作为主要桌面操作系统，我强烈建议你使用 Ubuntu 或其他 Linux 发行版，并在虚拟机中运行这些示例，以获得最佳效果。

Tcpdump 是由 `libpcap` 的作者编写的应用程序。Tcpdump 提供了一个命令行工具来捕获数据包。这些示例将让你复制 `tcpdump` 包的功能，并将其嵌入到其他应用程序中。有些示例与 `tcpdump` 的现有功能非常相似，并且在适用的情况下，将提供 `tcpdump` 的示例用法。由于 `gopacket` 和 `tcpdump` 都依赖于相同的底层 `libpcap` 包，它们的文件格式是兼容的。你可以使用 `tcpdump` 捕获文件并使用 `gopacket` 读取，也可以使用 `gopacket` 捕获数据包并用任何支持 `libpcap` 的应用程序读取，比如 Wireshark。

`gopacket` 包的官方文档可以在 [`godoc.org/github.com/google/gopacket`](https://godoc.org/github.com/google/gopacket) 查阅。

# 前提条件

在运行这些示例之前，你需要安装 `libpcap`。此外，我们还需要使用一个第三方 Go 包。幸运的是，这个包是由 Google 提供的，一个值得信赖的来源。Go 的 `get` 功能会下载并安装这个远程包。Git 也需要正确安装，才能使 `go get` 正常工作。

# 安装 libpcap 和 Git

`libpcap` 包依赖项并不是大多数系统默认安装的，每个操作系统的安装过程有所不同。这里将涵盖在 Ubuntu、Windows 和 macOS 上安装 `libpcap` 和 `git` 的步骤。我强烈建议你使用 Ubuntu 或其他 Linux 发行版，以获得最佳效果。没有 `libpcap`，`gopacket` 将无法工作，而 `git` 则是获取 `gopacket` 依赖项所必需的。

# 在 Ubuntu 上安装 libpcap

在 Ubuntu 中，`libpcap-0.8` 已经默认安装。但为了安装 `gopacket` 库，你还需要开发包中的头文件。你可以通过 `libpcap-dev` 包来安装头文件。我们还将安装 `git`，因为在稍后安装 `gopacket` 时需要运行 `go get` 命令：

```
sudo apt-get install git libpcap-dev
```

# 在 Windows 上安装 libpcap

Windows 是最棘手的，且会出现最多问题。Windows 的实现支持不太好，效果可能因人而异。WinPcap 与 libpcap 兼容，示例中使用的源代码无需修改即可正常工作。在 Windows 中运行时，唯一明显的区别是网络设备的命名方式。

可以从 [`www.winpcap.org/`](https://www.winpcap.org/) 获取 WinPcap 安装程序，这是一个必需组件。如果需要开发者包，可以从 [`www.winpcap.org/devel.htm`](https://www.winpcap.org/devel.htm) 获取，其中包含 C 语言编写的头文件和示例程序。在大多数情况下，你不需要开发者包。Git 可以从 [`git-scm.com/download/win`](https://git-scm.com/download/win) 下载。你还需要从 [`www.mingw.org`](http://www.mingw.org) 获取用于编译器的 MinGW。你需要确保 32 位和 64 位设置一致。你可以设置 `GOARCH=386` 或 `GOARCH=amd64` 环境变量来切换 32 位和 64 位模式。

# 在 macOS 上安装 libpcap

在 macOS 中，`libpcap` 已经默认安装。你还需要 Git，可以通过 Homebrew 从 [`brew.sh`](https://brew.sh) 安装，或者通过 Git 包管理器安装，后者可以从 [`git-scm.com/downloads`](https://git-scm.com/downloads) 获取。

# 安装 gopacket

在安装了 `libpcap` 和 `git` 包后，你可以从 GitHub 获取 `gopacket` 包：

```
go get github.com/google/gopacket  
```

# 权限问题

在 Linux 和 macOS 环境中执行程序时，如果尝试访问网络设备，可能会遇到权限问题。你可以使用 `sudo` 提升权限或将用户切换为 `root`，但不推荐这样做。

# 获取网络设备列表

`pcap` 库的一部分包含一个获取网络设备列表的功能。

该程序将简单地获取网络设备列表并列出其信息。在 Linux 中，常见的默认设备名称是`eth0`或`wlan0`。在 Mac 上是`en0`。在 Windows 上，名称较长且不可读，因为它们代表的是唯一的 ID。你将在后续示例中使用设备名称作为字符串来标识要捕获的设备。如果你没有看到确切的设备列表，可能需要使用管理员权限（例如`sudo`）运行该示例。

用于列出设备的等效`tcpdump`命令如下：

```
tcpdump -D
```

你也可以使用以下命令：

```
tcpdump --list-interfaces
```

你还可以使用`ifconfig`和`ip`等工具来获取网络设备的名称：

```
package main

import (
   "fmt"
   "log"
   "github.com/google/gopacket/pcap"
)

func main() {
   // Find all devices
   devices, err := pcap.FindAllDevs()
   if err != nil {
      log.Fatal(err)
   }

   // Print device information
   fmt.Println("Devices found:")
   for _, device := range devices {
      fmt.Println("\nName: ", device.Name)
      fmt.Println("Description: ", device.Description)
      fmt.Println("Devices addresses: ", device.Description)
      for _, address := range device.Addresses {
         fmt.Println("- IP address: ", address.IP)
         fmt.Println("- Subnet mask: ", address.Netmask)
      }
   }
}
```

# 捕获数据包

以下程序演示了捕获数据包的基础知识。设备名称作为字符串传入。如果你不知道设备名称，可以使用之前的示例获取机器上可用设备的列表。如果没有看到准确列出的设备，可能需要提升权限并使用`sudo`运行该程序。

混杂模式是你可以启用的一种选项，用来监听那些不是为你的设备指定的数据包。混杂模式对于无线设备尤为重要，因为无线网络设备实际上具备接收空中广播的数据包的能力，这些数据包本应发送给其他接收者。

无线流量特别容易受到*嗅探*攻击，因为所有数据包都是通过空中广播的，而不是通过以太网进行传输，后者需要物理访问才能拦截流量。为顾客提供不加密的免费无线网络在咖啡馆等场所非常常见。这对客人很方便，但也会让你的信息面临风险。如果某个场所提供加密的无线网络，这并不意味着它就一定更安全。如果密码贴在墙上或者随便发放，那么任何拥有密码的人都可以解密无线流量。为了增强客用无线网络的安全性，常用的一种技术是捕获门户。捕获门户要求用户以某种方式进行身份验证，即使是作为访客，然后他们的会话会通过独立的加密进行隔离，这样其他人就无法解密。

提供完全未加密流量的无线接入点必须小心使用。如果你连接到一个传输敏感信息的网站，请确保该网站使用 HTTPS，以便你与访问的网络服务器之间的数据是加密的。VPN 连接也提供通过未加密通道的加密隧道。

有些网站由不知情或疏忽的程序员构建，他们没有在服务器上实现 SSL。有些网站只加密登录页面，以确保你的密码安全，但随后将会话 Cookie 以明文传递。这意味着任何能够捕获无线流量的人都可以看到会话 Cookie，并利用它冒充受害者与 Web 服务器交互。Web 服务器会把攻击者当作受害者已登录的用户。攻击者从未知道密码，但只要会话保持活动状态，就不需要密码。

有些网站没有会话过期时间，用户的会话将保持活动状态，直到显式退出。移动应用特别容易受到这种问题的影响，因为用户很少退出并重新登录应用程序。关闭应用并重新打开并不一定会创建一个新的会话。

这个示例将打开网络设备进行实时捕获，然后打印每个接收到的包的详细信息。程序将持续运行，直到程序通过*Ctrl* + *C*被终止：

```
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "log"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous,  
      timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   // Use the handle as a packet source to process all packets
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      // Process packet here
      fmt.Println(packet)
   }
}
```

# 使用过滤器进行捕获

以下程序演示了如何设置过滤器。过滤器使用 BPF 格式。如果你曾使用过 Wireshark，你可能已经熟悉过滤器。有很多过滤器选项可以进行逻辑组合。过滤器可以非常复杂，并且网上有很多常见过滤器和巧妙技巧的备忘单。以下是一些示例，帮助你了解一些非常基础的过滤器：

+   `host 192.168.0.123`

+   `dst net 192.168.0.0/24`

+   `port 22`

+   `not broadcast and not multicast`

前面的一些过滤器应该是显而易见的。`host`过滤器将只显示发送到或来自该主机的包。`dst net`过滤器将捕获发送到`192.168.0.*`地址的传入流量。`port`过滤器只关注端口`22`的流量。`not broadcast and not multicast`过滤器演示了如何否定并组合多个过滤器。过滤掉`broadcast`和`multicast`非常有用，因为它们往往会干扰捕获。

对于基本捕获，等效的`tcpdump`命令就是运行它并传递一个接口：

```
tcpdump -i eth0
```

如果你想应用过滤器，只需将其作为命令行参数传递，像这样：

```
tcpdump -i eth0 tcp port 80
```

这个示例使用了一个过滤器，它只会捕获`80`端口上的流量，这应该是 HTTP 流量。它并没有指定是本地端口还是远程端口为`80`，因此它会捕获任何进出端口`80`的流量。如果你在个人电脑上运行，可能没有运行 Web 服务器，所以它会捕获你通过浏览器产生的 HTTP 流量。如果你在 Web 服务器上运行该捕获，它会捕获传入的 HTTP 请求流量。

在此示例中，使用`pcap.OpenLive()`创建网络设备的句柄。在从设备读取数据包之前，通过`handle.SetBPFFilter()`设置过滤器，然后从句柄中读取数据包。关于过滤器的更多信息，请访问[`en.wikipedia.org/wiki/Berkeley_Packet_Filter`](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)。

此示例打开网络设备进行实时捕获，然后使用`SetBPFFilter()`设置过滤器。在此案例中，我们将使用`tcp and port 80`过滤器来查找 HTTP 流量。所有捕获的数据包将打印到标准输出：

```
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "log"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous,  
      timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   // Set filter
   var filter string = "tcp and port 80" // or os.Args[1]
   err = handle.SetBPFFilter(filter)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println("Only capturing TCP port 80 packets.")

   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      // Do something with a packet here.
      fmt.Println(packet)
   }
}
```

# 保存到 pcap 文件

该程序将执行数据包捕获并将结果存储到文件中。在此示例中，关键步骤是调用`pcapgo`包的`Writer`的`WriteFileHeader()`函数。之后，可以使用`WritePacket()`函数将所需的数据包写入文件。如果需要，可以捕获所有流量并根据自己的过滤标准选择仅写入特定数据包。也许你只想将奇数或格式错误的数据包写入日志以记录异常。

要使用`tcpdump`实现相同的功能，只需传递`-w`标志和文件名，如以下命令所示：

```
tcpdump -i eth0 -w my_capture.pcap
```

使用此示例创建的 pcap 文件可以通过 Wireshark 打开，并像使用`tcpdump`创建的文件一样查看。

此示例创建一个名为`test.pcap`的输出文件，并打开网络设备进行实时捕获。它将 100 个数据包捕获到文件中，然后退出：

```
package main

import (
   "fmt"
   "os"
   "time"

   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
   "github.com/google/gopacket/pcapgo"
)

var (
   deviceName        = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = -1 * time.Second
   handle      *pcap.Handle
   packetCount = 0
)

func main() {
   // Open output pcap file and write header
   f, _ := os.Create("test.pcap")
   w := pcapgo.NewWriter(f)
   w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
   defer f.Close()

   // Open the device for capturing
   handle, err = pcap.OpenLive(deviceName, snapshotLen, promiscuous, 
      timeout)
   if err != nil {
      fmt.Printf("Error opening device %s: %v", deviceName, err)
      os.Exit(1)
   }
   defer handle.Close()

   // Start processing packets
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      // Process packet here
      fmt.Println(packet)
      w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
      packetCount++

      // Only capture 100 and then stop
      if packetCount > 100 {
         break
      }
   }
}
```

# 从 pcap 文件中读取

除了打开设备进行实时捕获外，你还可以打开一个 pcap 文件进行离线检查。获取句柄后，无论是通过`pcap.OpenLive()`还是`pcap.OpenOffline()`获得的，句柄的处理方式是相同的。创建句柄后，实时设备和捕获文件之间没有区别，唯一的区别是实时设备会继续传送数据包，而文件最终会结束。

你可以读取任何通过`libpcap`客户端（包括 Wireshark、`tcpdump`或其他`gopacket`应用程序）捕获的 pcap 文件。此示例使用`pcap.OpenOffline()`打开名为`test.pcap`的文件，然后使用`range`遍历数据包并打印基本的数据包信息。将文件名从`test.pcap`更改为你想要读取的任何文件：

```
package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "log"
)

var (
   pcapFile = "test.pcap"
   handle   *pcap.Handle
   err      error
)

func main() {
   // Open file instead of device
   handle, err = pcap.OpenOffline(pcapFile)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   // Loop through packets in file
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      fmt.Println(packet)
   }
}
```

# 解码数据包层

数据包可以通过`packet.Layer()`函数逐层解码。该程序将检查数据包，查找 TCP 流量，然后输出以太网层、IP 层、TCP 层和应用层信息。当到达应用层时，它会查找`HTTP`关键字，如果发现，则输出一条消息：

```
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
   "log"
   "strings"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, 
      timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      printPacketInfo(packet)
   }
}

func printPacketInfo(packet gopacket.Packet) {
   // Let's see if the packet is an ethernet packet
   ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
   if ethernetLayer != nil {
      fmt.Println("Ethernet layer detected.")
      ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
      fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
      fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
      // Ethernet type is typically IPv4 but could be ARP or other
      fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
      fmt.Println()
   }

   // Let's see if the packet is IP (even though the ether type told 
   //us)
   ipLayer := packet.Layer(layers.LayerTypeIPv4)
   if ipLayer != nil {
      fmt.Println("IPv4 layer detected.")
      ip, _ := ipLayer.(*layers.IPv4)

      // IP layer variables:
      // Version (Either 4 or 6)
      // IHL (IP Header Length in 32-bit words)
      // TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
      // Checksum, SrcIP, DstIP
      fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
      fmt.Println("Protocol: ", ip.Protocol)
      fmt.Println()
   }

   // Let's see if the packet is TCP
   tcpLayer := packet.Layer(layers.LayerTypeTCP)
   if tcpLayer != nil {
      fmt.Println("TCP layer detected.")
      tcp, _ := tcpLayer.(*layers.TCP)

      // TCP layer variables:
      // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, 
      //Urgent
      // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
      fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
      fmt.Println("Sequence number: ", tcp.Seq)
      fmt.Println()
   }

   // Iterate over all layers, printing out each layer type
   fmt.Println("All packet layers:")
   for _, layer := range packet.Layers() {
      fmt.Println("- ", layer.LayerType())
   }

   // When iterating through packet.Layers() above,
   // if it lists Payload layer then that is the same as
   // this applicationLayer. applicationLayer contains the payload
   applicationLayer := packet.ApplicationLayer()
   if applicationLayer != nil {
      fmt.Println("Application layer/Payload found.")
      fmt.Printf("%s\n", applicationLayer.Payload())

      // Search for a string inside the payload
      if strings.Contains(string(applicationLayer.Payload()), "HTTP")    
      {
         fmt.Println("HTTP found!")
      }
   }

   // Check for errors
   if err := packet.ErrorLayer(); err != nil {
      fmt.Println("Error decoding some part of the packet:", err)
   }
}
```

# 创建自定义层

你不局限于最常见的层次，如以太网、IP 和 TCP。你可以创建自己的层次。对于大多数人来说，这种功能的使用范围有限，但在某些极其罕见的情况下，替换 TCP 层为定制的层，以满足特定需求，可能是有意义的。

这个示例演示了如何创建一个自定义层。这对于实现`gopacket/layers`包中未包含的协议非常有用。`gopacket`已包含超过 100 种层类型。你可以在任何层次创建自定义层。

这段代码做的第一件事是定义一个自定义数据结构来表示我们的层。该数据结构不仅保存我们的自定义数据（`SomeByte`和`AnotherByte`），还需要一个字节切片来存储其余的实际有效负载以及任何其他层（`restOfData`）：

```
package main

import (
   "fmt"
   "github.com/google/gopacket"
)

// Create custom layer structure
type CustomLayer struct {
   // This layer just has two bytes at the front
   SomeByte    byte
   AnotherByte byte
   restOfData  []byte
}

// Register the layer type so we can use it
// The first argument is an ID. Use negative
// or 2000+ for custom layers. It must be unique
var CustomLayerType = gopacket.RegisterLayerType(
   2001,
   gopacket.LayerTypeMetadata{
      "CustomLayerType",
      gopacket.DecodeFunc(decodeCustomLayer),
   },
)

// When we inquire about the type, what type of layer should
// we say it is? We want it to return our custom layer type
func (l CustomLayer) LayerType() gopacket.LayerType {
   return CustomLayerType
}

// LayerContents returns the information that our layer
// provides. In this case it is a header layer so
// we return the header information
func (l CustomLayer) LayerContents() []byte {
   return []byte{l.SomeByte, l.AnotherByte}
}

// LayerPayload returns the subsequent layer built
// on top of our layer or raw payload
func (l CustomLayer) LayerPayload() []byte {
   return l.restOfData
}

// Custom decode function. We can name it whatever we want
// but it should have the same arguments and return value
// When the layer is registered we tell it to use this decode function
func decodeCustomLayer(data []byte, p gopacket.PacketBuilder) error {
   // AddLayer appends to the list of layers that the packet has
   p.AddLayer(&CustomLayer{data[0], data[1], data[2:]})

   // The return value tells the packet what layer to expect
   // with the rest of the data. It could be another header layer,
   // nothing, or a payload layer.

   // nil means this is the last layer. No more decoding
   // return nil
   // Returning another layer type tells it to decode
   // the next layer with that layer's decoder function
   // return p.NextDecoder(layers.LayerTypeEthernet)

   // Returning payload type means the rest of the data
   // is raw payload. It will set the application layer
   // contents with the payload
   return p.NextDecoder(gopacket.LayerTypePayload)
}

func main() {
   // If you create your own encoding and decoding you can essentially
   // create your own protocol or implement a protocol that is not
   // already defined in the layers package. In our example we are    
   // just wrapping a normal ethernet packet with our own layer.
   // Creating your own protocol is good if you want to create
   // some obfuscated binary data type that was difficult for others
   // to decode. Finally, decode your packets:
   rawBytes := []byte{0xF0, 0x0F, 65, 65, 66, 67, 68}
   packet := gopacket.NewPacket(
      rawBytes,
      CustomLayerType,
      gopacket.Default,
   )
   fmt.Println("Created packet out of raw bytes.")
   fmt.Println(packet)

   // Decode the packet as our custom layer
   customLayer := packet.Layer(CustomLayerType)
   if customLayer != nil {
      fmt.Println("Packet was successfully decoded.")
      customLayerContent, _ := customLayer.(*CustomLayer)
      // Now we can access the elements of the custom struct
      fmt.Println("Payload: ", customLayerContent.LayerPayload())
      fmt.Println("SomeByte element:", customLayerContent.SomeByte)
      fmt.Println("AnotherByte element:",  
         customLayerContent.AnotherByte)
   }
}
```

# 字节与数据包之间的转换

在某些情况下，可能有原始字节，你想将其转换为数据包，或者反之亦然。这个示例创建了一个简单的数据包，然后获取组成该数据包的原始字节。原始字节随后被转换回数据包，以演示这个过程。

在这个示例中，我们将使用`gopacket.SerializeLayers()`创建并序列化一个数据包。该数据包由几个层次组成：以太网、IP、TCP 和有效负载。在序列化过程中，如果任何数据包返回 nil，这意味着它无法解码为正确的层（格式错误或不正确的数据包类型）。在将数据包序列化到缓冲区后，我们将通过`buffer.Bytes()`获取组成数据包的原始字节的副本。借助这些原始字节，我们可以使用`gopacket.NewPacket()`逐层解码数据。通过利用`SerializeLayers()`，你可以将数据包结构体转换为原始字节，使用`gopacket.NewPacket()`，你可以将原始字节转换回结构化数据。

`NewPacket()`将原始字节作为第一个参数。第二个参数是你想解码的最低层次，它会解码该层及其之上的所有层。`NewPacket()`的第三个参数是解码类型，必须是以下之一：

+   `gopacket.Default`：这是一次性解码所有内容，最安全的方法。

+   `gopacket.Lazy`：这是按需解码，但它不是并发安全的。

+   `gopacket.NoCopy`：这将不会创建缓冲区的副本。仅当你可以保证内存中的数据包数据不会改变时，才使用它。

下面是将数据包结构体转换为字节并再次转换回数据包的完整代码：

```
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
)

func main() {
   payload := []byte{2, 4, 6}
   options := gopacket.SerializeOptions{}
   buffer := gopacket.NewSerializeBuffer()
   gopacket.SerializeLayers(buffer, options,
      &layers.Ethernet{},
      &layers.IPv4{},
      &layers.TCP{},
      gopacket.Payload(payload),
   )
   rawBytes := buffer.Bytes()

   // Decode an ethernet packet
   ethPacket :=
      gopacket.NewPacket(
         rawBytes,
         layers.LayerTypeEthernet,
         gopacket.Default,
      )

   // with Lazy decoding it will only decode what it needs when it 
   //needs it
   // This is not concurrency safe. If using concurrency, use default
   ipPacket :=
      gopacket.NewPacket(
         rawBytes,
         layers.LayerTypeIPv4,
         gopacket.Lazy,
      )

   // With the NoCopy option, the underlying slices are referenced
   // directly and not copied. If the underlying bytes change so will
   // the packet
   tcpPacket :=
      gopacket.NewPacket(
         rawBytes,
         layers.LayerTypeTCP,
         gopacket.NoCopy,
      )

   fmt.Println(ethPacket)
   fmt.Println(ipPacket)
   fmt.Println(tcpPacket)
}
```

# 创建和发送数据包

这个示例做了几件事。首先，它会展示如何使用网络设备发送原始字节，因此你几乎可以像串行连接一样使用它来发送数据。这对于低级别的数据传输非常有用，但如果你想与应用程序交互，你可能想构建一个其他硬件和软件可以识别的数据包。

接下来它会展示如何创建一个包含以太网、IP 和 TCP 层的数据包。不过，这些层都是默认的且为空的，所以它实际上并没有做什么。

最后，我们将创建另一个数据包，但这次我们会为以太网层填入一些 MAC 地址，为 IPv4 填入一些 IP 地址，为 TCP 层填入端口号。你应该能看到如何伪造数据包并模拟设备。

TCP 层结构有布尔字段，用于`SYN`、`FIN`和`ACK`标志，这些标志可以读取或设置。这对于操作和模糊化 TCP 握手、会话以及端口扫描非常有用。

`pcap`库提供了一个简单的发送字节的方式，而`gopacket`中的`layers`包帮助我们为各层创建字节结构。

以下是此示例的代码实现：

```
package main

import (
   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
   "log"
   "net"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
   buffer      gopacket.SerializeBuffer
   options     gopacket.SerializeOptions
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, 
      timeout)
   if err != nil {
      log.Fatal("Error opening device. ", err)
   }
   defer handle.Close()

   // Send raw bytes over wire
   rawBytes := []byte{10, 20, 30}
   err = handle.WritePacketData(rawBytes)
   if err != nil {
      log.Fatal("Error writing bytes to network device. ", err)
   }

   // Create a properly formed packet, just with
   // empty details. Should fill out MAC addresses,
   // IP addresses, etc.
   buffer = gopacket.NewSerializeBuffer()
   gopacket.SerializeLayers(buffer, options,
      &layers.Ethernet{},
      &layers.IPv4{},
      &layers.TCP{},
      gopacket.Payload(rawBytes),
   )
   outgoingPacket := buffer.Bytes()
   // Send our packet
   err = handle.WritePacketData(outgoingPacket)
   if err != nil {
      log.Fatal("Error sending packet to network device. ", err)
   }

   // This time lets fill out some information
   ipLayer := &layers.IPv4{
      SrcIP: net.IP{127, 0, 0, 1},
      DstIP: net.IP{8, 8, 8, 8},
   }
   ethernetLayer := &layers.Ethernet{
      SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
      DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
   }
   tcpLayer := &layers.TCP{
      SrcPort: layers.TCPPort(4321),
      DstPort: layers.TCPPort(80),
   }
   // And create the packet with the layers
   buffer = gopacket.NewSerializeBuffer()
   gopacket.SerializeLayers(buffer, options,
      ethernetLayer,
      ipLayer,
      tcpLayer,
      gopacket.Payload(rawBytes),
   )
   outgoingPacket = buffer.Bytes()
}
```

# 更快速地解码数据包

如果我们知道预期的层级，我们可以使用现有结构来存储数据包信息，而不是为每个数据包创建新的结构，这样既能节省时间，也能节省内存。使用`DecodingLayerParser`会更快，这就像是数据的编组和解编组。

本示例演示了如何在程序开始时创建层变量，并反复使用相同的变量，而不是为每个数据包创建新的变量。通过`gopacket.NewDecodingLayerParser()`创建一个解析器，并提供我们想要使用的层变量。这里的一个注意事项是，它仅解码你最初创建的层类型。

以下是此示例的代码实现：

```
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
   "log"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
   // Reuse these for each packet
   ethLayer layers.Ethernet
   ipLayer  layers.IPv4
   tcpLayer layers.TCP
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, 
   timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      parser := gopacket.NewDecodingLayerParser(
         layers.LayerTypeEthernet,
         &ethLayer,
         &ipLayer,
         &tcpLayer,
      )
      foundLayerTypes := []gopacket.LayerType{}

      err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
      if err != nil {
         fmt.Println("Trouble decoding layers: ", err)
      }

      for _, layerType := range foundLayerTypes {
         if layerType == layers.LayerTypeIPv4 {
            fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
         }
         if layerType == layers.LayerTypeTCP {
            fmt.Println("TCP Port: ", tcpLayer.SrcPort,               
               "->", tcpLayer.DstPort)
            fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", 
               tcpLayer.ACK)
         }
      }
   }
}
```

# 总结

阅读完这一章后，你应该对`gopacket`包有了很好的理解。你应该能够使用本章中的示例编写一个简单的数据包捕获应用程序。再次强调，这并不是要记住所有的函数或关于各层的细节，重要的是要从高层次理解整体框架，并在开发和实现应用程序时能够回忆起可用的工具。

尝试根据这些示例编写你自己的程序，以捕获来自你计算机的有趣网络流量。尝试捕获并检查特定端口或应用程序，看看它在网络上传输的方式。观察使用加密的应用程序与通过明文传输数据的应用程序之间的差异。你可能还想捕获后台所有的流量，看看即使你在计算机空闲时，哪些应用程序在网络上很活跃。

使用`gopacket`库可以构建各种有用的工具。除了基本的数据包捕获以供后续查看外，你还可以实现一个监控系统，当检测到流量突然激增时进行警报，或者用于识别异常流量。

因为`gopacket`库也可以用来发送数据包，所以可以创建一个高度定制化的端口扫描器。你可以构造原始数据包来执行仅进行 TCP SYN 扫描的操作，这种扫描中连接从未完全建立；XMAS 扫描，所有标志位都会被打开；NULL 扫描，所有字段都设置为 null；以及其他各种扫描，需要对发送的数据包进行完全控制，包括故意发送格式错误的数据包。你还可以构建模糊测试工具，向网络服务发送不良数据包，以查看它的反应。所以，看看你能想到哪些创意吧。

在下一章，我们将探讨 Go 中的密码学。我们将从哈希算法、校验和、以及安全存储密码开始。然后我们将讨论对称加密和非对称加密，它们是什么，有什么不同，为什么它们有用，以及如何在 Go 中使用它们。我们还将研究如何创建带有证书的加密服务器，以及如何使用加密客户端进行连接。理解密码学的应用对于现代安全至关重要，因此我们将重点讨论最常见和最实际的使用案例。

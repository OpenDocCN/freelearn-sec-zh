# 第六章：故障排除 OpenVPN - 配置

在本章中，我们将讨论以下内容：

+   加密算法不匹配

+   TUN 与 TAP 不匹配

+   压缩不匹配

+   密钥不匹配

+   故障排除 MTU 和 `tun-mtu` 问题

+   故障排除网络连接

+   故障排除 `client-config-dir` 问题

+   故障排除多个 `remote` 问题

+   故障排除桥接问题

+   如何读取 OpenVPN 日志文件

# 介绍

本章和下一章的主题是故障排除 OpenVPN。本章将专注于故障排除 OpenVPN 配置错误，而下一章将专注于在设置 VPN 时常见的路由问题。

因此，本章中的方法首先将致力于破坏配置。然后，我们将提供查找和解决配置错误的工具。本章中使用的一些配置指令之前没有演示过，所以即使你不打算破坏配置，本章仍然很有启发性。

# 加密算法不匹配

在本示例中，我们将更改 OpenVPN 使用的加密算法。最初，我们只会在客户端侧更改加密算法，这将导致 VPN 连接初始化失败。本示例的主要目的是展示出现的错误信息，而不是探索 OpenVPN 支持的不同类型的加密算法。

## 准备工作

使用 第二章 *客户端-服务器仅 IP 网络* 中的第一个方法设置客户端和服务器证书。在本示例中，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行 Windows 7 64 位和 OpenVPN 2.3.10。保留来自 第二章 *客户端-服务器仅 IP 网络* 中的 *服务器端路由* 配置文件 `basic-udp-server.conf`，以及客户端配置文件 `basic-udp-client.conf`。

## 如何操作...

1.  使用配置文件 `basic-udp-server.conf` 启动服务器：

    ```
            [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  接下来，通过向 `basic-udp-client.conf` 文件中添加一行来创建客户端配置文件：

    ```
            cipher CAST5-CBC 

    ```

    将其保存为 `example6-1-client.conf`。

1.  启动客户端后，客户端日志中将出现以下信息：

    ```
            [root@client]# openvpn --config example6-1-client.conf 
            ... WARNING: 'cipher' is used inconsistently, local='cipher 
            CAST5-CBC'', remote='cipher BF-CBC'' 
            ... [openvpnserver] Peer Connection Initiated with server-
            ip:1194 
            ... TUN/TAP device tun0 opened 
            ... /sbin/ip link set dev tun0 up mtu 1500 
            ... /sbin/ip addr add dev tun0 10.200.0.2/24 broadcast 
            10.200.0.255 
            ... Initialization Sequence Completed 
            ... Authenticate/Decrypt packet error: cipher final failed 

    ```

    同样，在服务器端：

    ```
            ... client-ip:52461 WARNING: 'cipher' is used inconsistently,         local='cipher BF-CBC'', remote='cipher CAST5-CBC'' 
            ... client-ip:52461 [client1] Peer Connection Initiated with         client1:52461 
            ... client1/client-ip:52461 Authenticate/Decrypt packet error: 
            cipher final failed 
            ... client1/client-ip:52461 Authenticate/Decrypt packet error: 
            cipher final failed 

    ```

    连接不会成功建立，但也不会立即断开连接。

## 它是如何工作的...

在连接阶段，客户端和服务器协商多个安全连接所需的参数。此阶段最重要的参数之一是加密算法，它用于加密和解密所有消息。如果客户端和服务器使用不同的加密算法，它们根本无法互相通信。

通过向服务器配置文件中添加以下配置指令，客户端和服务器可以重新通信：

```
cipher CAST5-CBC 

```

## 还有更多...

OpenVPN 支持许多加密算法，尽管有些加密算法的支持仍处于实验阶段。要查看受支持的加密算法列表，请输入：

```
$ openvpn --show-ciphers

```

这将列出所有加密算法，其中包括变量长度和固定长度的加密算法。OpenVPN 对变量长度的加密算法有很好的支持，其他加密算法有时可能会导致不可预测的结果。

### 可推送的加密算法

从版本 2.4 开始，OpenVPN 客户端支持处理从服务器推送到客户端的加密算法选项。因此，如果所有客户端都运行 OpenVPN 2.4 或更高版本，那么在现有部署中更改加密算法将变得更加容易。

# TUN 与 TAP 的不匹配

在基于 OpenVPN 设置 VPN 时，一个常见的错误是所使用的适配器类型。如果服务器配置为使用 TUN 风格的网络，而客户端配置为使用 TAP 风格的接口，那么 VPN 连接将失败。在这个配方中，我们将展示当出现这个常见配置错误时，通常会看到的情况。

## 准备工作

使用第二章中第一个配方中的内容来设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。在这个配方中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11。客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。保留来自第二章中*服务器端路由*配方的配置文件，`basic-udp-server.conf`，*客户端-服务器仅 IP 网络*。

## 如何操作...

1.  使用配置文件`basic-udp-server.conf`启动服务器：

    ```
            [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  接下来，创建客户端配置：

    ```
            client 
            proto udp 
            remote openvpnserver.example.com 
            port 1194 

            dev tap 
            nobind 

            remote-cert-tls server 
            tls-auth /etc/openvpn/cookbook/ta.key 1 
            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/client1.crt 
            key      /etc/openvpn/cookbook/client1.key  

    ```

    将其保存为`example6-2-client.conf`。

1.  启动客户端：

    ```
            [root@client]# openvpn --config example6-2-client.conf

    ```

    客户端日志将显示如下内容：

    ```
            ... WARNING: 'dev-type' is used inconsistently, local='dev-type 
            tap'', remote='dev-type tun'' 
            ... WARNING: 'link-mtu' is used inconsistently, local='link-mtu 
            1573'', remote='link-mtu 1541'' 
            ... WARNING: 'tun-mtu' is used inconsistently, local='tun-mtu 
            1532'', remote='tun-mtu 1500'' 
            ... [openvpnserver] Peer Connection Initiated with server-
            ip:1194 
            ... TUN/TAP device tap0 opened 
            ... /sbin/ip link set dev tap0 up mtu 1500 
            ... /sbin/ip addr add dev tap0 10.200.0.2/24 broadcast 
            10.200.0.255 
            ... Initialization Sequence Completed 

    ```

    此时，您可以尝试 ping 服务器，但它将返回错误：

    ```
            [client]$ ping 10.200.0.1 
            PING 10.200.0.1 (10.200.0.1) 56(84) bytes of data. 
            From 10.200.0.2 icmp_seq=2 Destination Host Unreachable 
            From 10.200.0.2 icmp_seq=3 Destination Host Unreachable 
            From 10.200.0.2 icmp_seq=4 Destination Host Unreachable 

    ```

## 工作原理...

TUN 风格的接口提供点对点连接，只有 TCP/IP 流量可以通过该接口进行隧道化。TAP 风格的接口提供等同于以太网接口的功能，并包含额外的头信息。这允许用户通过该接口隧道其他类型的流量。当客户端和服务器配置错误时，预期的数据包大小会有所不同：

```
... WARNING: 'tun-mtu' is used inconsistently, local='tun-mtu 1532'', remote='tun-mtu 1500'' 

```

这表明通过 TAP 风格接口发送的每个数据包比通过 TUN 风格接口发送的包大 32 字节。

通过纠正客户端配置，解决了这个问题。

# 压缩不匹配

OpenVPN 支持对通过 VPN 隧道发送的流量进行即时压缩。这可以提高慢速网络线路上的性能，但也会增加一些开销。在传输无法压缩的数据（如 ZIP 文件）时，性能实际上会略微下降。

如果服务器启用了压缩，但客户端没有启用，那么 VPN 连接将失败。

## 准备工作

使用第二章中的 *设置公钥和私钥* 配方来设置客户端和服务器证书。对于此配方，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。保留第二章中 *服务器端路由* 配方中的配置文件 `basic-udp-server.conf`，以及客户端配置文件 `basic-udp-client.conf`。

## 如何操作……

1.  向服务器配置文件 `basic-udp-server.conf` 添加一行：

    ```
            comp-lzo 

    ```

    将其保存为 `example6-3-server.conf`。

1.  启动服务器：

    ```
    [root@server]# openvpn --config example6-3-server.conf

    ```

1.  接下来，启动客户端：

    ```
     [root@client]# openvpn --config basic-udp-client.conf

    ```

    连接将会启动，但是当数据通过 VPN 连接发送时，以下消息将会出现：

    ```
            Initialization Sequence Completed 
            ... write to TUN/TAP : Invalid argument (code=22) 
            ... write to TUN/TAP : Invalid argument (code=22) 

    ```

## 它是如何工作的……

在连接阶段，不使用压缩在客户端和服务器之间传输信息。商定的参数之一是是否为实际的 VPN 负载使用压缩。如果客户端和服务器之间的配置不匹配，那么双方将对对方发送的流量感到困惑。

这个错误可以通过添加一行来轻松修复所有客户端：

```
push "comp-lzo"

```

# 密钥不匹配

OpenVPN 为其 TLS 控制通道提供额外保护，使用的是 HMAC 密钥。这些密钥与在第一章中用于点对点式网络的静态“秘密”密钥完全相同。对于多客户端式网络，可以通过使用 `tls-auth` 指令启用这种额外的保护。如果客户端和服务器之间与 `tls-auth` 密钥相关的配置不匹配，则 VPN 连接将无法初始化。

## 准备就绪

使用第二章中的第一个配方来设置客户端和服务器证书。对于此配方，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。保留第二章中 *服务器端路由* 配方中的配置文件 `basic-udp-server.conf`。

## 如何操作……

1.  使用配置文件 `basic-udp-server.conf` 启动服务器：

    ```
            [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  接下来，创建客户端配置：

    ```
            client 
            proto udp 
            remote openvpnserver.example.com 
            port 1194 

            dev tun 
            nobind 

            remote-cert-tls server 
            tls-auth /etc/openvpn/cookbook/ta.key 
            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/client1.crt 
            key      /etc/openvpn/cookbook/client1.key 

    ```

    注意到缺少 `tls-auth` 的第二个参数。将其保存为 `example6-4-client.conf` 文件。

1.  启动客户端：

    ```
    [root@client]# openvpn --config example6-4-client.conf

    ```

    客户端日志将不会显示错误，但连接也不会建立。在服务器日志中，我们会看到以下内容：

    ```
            ... Initialization Sequence Completed
            ... Authenticate/Decrypt packet error: packet HMAC 
            authentication failed
            ... TLS Error: incoming packet authentication failed from 
            client-ip:54454

    ```

    这表明客户端`client1`使用了错误的`tls-auth`参数，连接被拒绝。

## 工作原理...

在连接初始化的第一阶段，客户端和服务器会相互验证对方的 HMAC 密钥。如果 HMAC 密钥没有正确配置，则初始化会被中止，连接无法建立。由于 OpenVPN 服务器无法确定客户端是简单配置错误，还是恶意客户端试图过载服务器，因此连接会被直接中断。这导致客户端一直监听服务器的流量，直到最终超时。

在这个食谱中，配置错误是配置行末缺少了参数`1`：

```
tls-auth /etc/openvpn/cookbook/ta.key 

```

`tls-auth`指令的第二个参数是密钥的方向。通常，使用以下约定：

+   `0`：从服务器到客户端

+   `1`：从客户端到服务器

这个参数使 OpenVPN 从`ta.key`文件的不同部分派生 HMAC 密钥。如果客户端和服务器在 HMAC 密钥派生的部分上存在分歧，则连接无法建立。同样，如果客户端和服务器从不同的`ta.key`文件中派生 HMAC 密钥，也无法建立连接。

## 参见

+   第一章中的*多个密钥*食谱，详细解释了 OpenVPN 密钥的格式和使用方法。

# 故障排除 MTU 和 tun-mtu 问题

OpenVPN 的一个高级特性是能够调整 TUN（或 TAP）适配器以及加密链路本身的网络参数。这是配置错误的一个常见原因，可能导致性能低下，甚至无法成功地通过 VPN 隧道传输数据。这个食谱将展示如果客户端和服务器之间存在 MTU（最大传输单元）不匹配时会发生什么，以及如何在某些情况下这种不匹配会导致 VPN 隧道失败。

## 准备工作

使用第二章中的第一个食谱，*客户端-服务器 IP 仅网络*，来设置客户端和服务器证书。对于此食谱，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，而客户端运行 Fedora 22 Linux 和 OpenVPN 2.3.11。请将客户端配置文件`basic-udp-client.conf`与来自*服务器端路由*食谱的配置文件`basic-udp-server.conf`一起保管好，这个食谱也在第二章中，此外还需要保管好客户端配置文件`basic-udp-client.conf`。

## 如何操作...

1.  使用配置文件`basic-udp-server.conf`启动服务器：

    ```
            [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  接下来，通过向 `basic-udp-client.conf` 文件添加一行来创建客户端配置文件：

    ```
            tun-mtu 1400 

    ```

    将其保存为 `example6-5-client.conf`。

1.  启动客户端并查看客户端日志：

    ```
            [root@client]# openvpn --config example6-5-client.conf 
            ... WARNING: 'link-mtu' is used inconsistently, local='link-mtu 
            1441'', remote='link-mtu 1541'' 
            ... WARNING: 'tun-mtu' is used inconsistently, local='tun-mtu 
            1400'', remote='tun-mtu 1500'' 
            ... [openvpnserver] Peer Connection Initiated with server-
            ip:1194 
            ... TUN/TAP device tun0 opened 
            ... /sbin/ip link set dev tun0 up mtu 1400 
            ... /sbin/ip addr add dev tun0 10.200.0.2/24 broadcast 
            10.200.0.255 
            ... Initialization Sequence Completed 

    ```

    当隧道建立时会出现一些警告，但连接已初始化。

1.  可以通过链路发送流量，我们可以使用 `ping` 命令来验证：

    ```
            [client]$ ping -c 2 10.200.0.1 
            PING 10.200.0.1 (10.200.0.1) 56(84) bytes of data. 
            64 bytes from 10.200.0.1: icmp_seq=1 ttl=64 time=30.6 ms 
            64 bytes from 10.200.0.1: icmp_seq=2 ttl=64 time=30.7 ms 

    ```

1.  但是，考虑到发送更大包时，例如：

    ```
            [client]$ ping -s 1450 10.200.0.1

    ```

    在这种情况下，客户端日志文件中会出现以下信息：

    ```
            ... Authenticate/Decrypt packet error: packet HMAC 
            authentication failed
            ... Authenticate/Decrypt packet error: packet HMAC 
            authentication failed

    ```

如果客户端尝试下载大文件，也会发生同样的事情。

## 它是如何工作的...

MTU 决定了可以通过隧道发送的最大数据包大小，且不需要将数据包拆分（分片）成多个部分。如果客户端和服务器对 MTU 大小意见不一致，则服务器会向客户端发送过大的数据包。这会导致 HMAC 失败（如果使用 `tls-auth`，如本配方所示），或者超大的部分数据包会被丢弃。

## 还有更多...

在 Windows 平台上，修改 OpenVPN 使用的 Tap-Win32 适配器的 MTU 设置并不容易。可以指定 `tun-mtu` 指令，但 Windows 版本的 OpenVPN 无法更改实际的 MTU 设置，因为 Windows 直到 Vista 版本才支持这一功能。然而，OpenVPN 目前尚不具备在 Windows 上更改 MTU 大小的能力。

## 另请参见

+   第九章，*性能调优*，提供了一些关于如何优化 `tun-mtu` 指令的提示和示例

# 故障排除网络连接问题

本配方将重点介绍在 OpenVPN 配置正确时，但网络连接有问题时，通常会看到的日志消息。在大多数情况下，这是由于防火墙阻止了对服务器或客户端的访问。在本配方中，我们显式地阻止对服务器的访问，然后尝试连接它。

## 准备工作

使用第二章中的第一个配方设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。对于本配方，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。保留客户端配置文件 `basic-udp-client.conf`，以及来自第二章的 *服务器端路由* 配方中的配置文件 `basic-udp-server.conf`，同时保留客户端配置文件 `basic-udp-client.conf`。

## 如何操作...

1.  使用配置文件 `basic-udp-server.conf` 启动服务器：

    ```
            [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  在服务器上，使用 `iptables` 显式阻止对 OpenVPN 的访问：

    ```
            [root@server]# iptables -I INPUT -p udp --dport 1194 -j DROP

    ```

1.  接下来，使用配置文件 `basic-udp-client.conf` 启动客户端：

    ```
            [root@client]# openvpn --config basic-udp-client.conf

    ```

    客户端将尝试使用 UDP 协议连接服务器。过了一段时间，由于没有流量通过，超时发生，客户端将重新启动：

    ```
            ... TLS Error: TLS key negotiation failed to occur within 60 
            seconds (check your network connectivity) 
            ... TLS Error: TLS handshake failed 
            ... SIGUSR1[soft,tls-error] received, process restarting 

    ```

    中止客户端并停止服务器。

## 工作原理...

当 OpenVPN 被配置为使用默认的 UDP 协议时，客户端将等待来自服务器的答复 60 秒。如果没有收到答复，连接将重新启动。由于我们明确地阻止了 UDP 流量，超时会发生，客户端始终无法连接。

客户端等待连接开始的时间由以下指令控制：

```
hand-window N 

```

这里，`N`是等待初始握手完成的秒数。默认值为 60 秒。

当然，可以通过删除防火墙规则来修复连接。

## 还有更多...

UDP 协议和 TCP 协议之间的主要区别之一是连接的建立方式：每个 TCP 连接都需要客户端和服务器通过 TCP 握手来启动。如果握手失败，则连接不会建立。无需等待来自服务器的流量返回，因为连接本身会被断开：

```
... Attempting to establish TCP connection with openvpnserver:1194 [nonblock]
... TCP: connect to openvpnserver:1194 failed, will try again in 5 seconds: Connection refused

```

# 排查客户端配置目录问题

在这个配方中，我们将演示如何排查与使用`client-config-dir`指令相关的问题。这个指令可以用来指定一个目录用于存放所谓的 CCD 文件。CCD 文件可以包含 OpenVPN 指令，根据客户端的证书为客户端分配一个特定的 IP 地址。经验表明，这个指令容易被配置错误。在这个配方中，我们将故意进行一种常见的配置错误，然后展示如何排查该问题。

## 准备就绪

使用第二章中的第一个配方，*客户端-服务器 IP-only 网络*，设置客户端和服务器证书。对于这个配方，服务器运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，而客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。保持客户端配置文件`basic-udp-client.conf`和来自*服务器端路由*配方中的`basic-udp-server.conf`配置文件一同备用，这个配方也来自第二章，*客户端-服务器 IP-only 网络*，同时还需要客户端配置文件`basic-udp-client.conf`。

## 操作方法...

1.  将以下行附加到配置文件`basic-udp-server.conf`：

    ```
            client-config-dir /etc/openvpn/cookbook/clients 
            ccd-exclusive 

    ```

    将其保存为`example6-7-server.conf`。

1.  确保`/etc/openvpn/cookbook/clients`目录只有 root 用户可访问：

    ```
            [root@server]# chown root /etc/openvpn/cookbook/clients
            [root@server]# chmod 700  /etc/openvpn/cookbook/clients

    ```

1.  启动服务器：

    ```
            [root@server]# openvpn --config example6-7-server.conf

    ```

1.  接下来，使用配置文件`basic-udp-client.conf`启动客户端：

    ```
            [root@client]# openvpn --config basic-udp-client.conf

    ```

然后，客户端将以以下信息失败连接：

```
... [openvpnserver] Peer Connection Initiated with server-ip:1194 
... AUTH: Received AUTH_FAILED control message 

```

服务器日志文件有点混乱：首先提到读取 CCD 文件`client1`时出现问题，但随后又说明客户端已连接：

```
... client-ip:45432 TLS Auth Error: --client-config-dir authentication failed for common name 'client1' file=''/etc/openvpn/cookbook/clients/client1'' 
... client-ip:45432 [client1] Peer Connection Initiated with client-ip:45432 

```

然而，VPN 连接没有正确初始化。

## 它是如何工作的……

以下指令被 OpenVPN 服务器用来在`/etc/openvpn/cookbook/clients`目录中查找客户端证书名称（CN）的 CCD 文件：

```
client-config-dir /etc/openvpn/cookbook/clients 
ccd-exclusive 

```

第二个指令`ccd-exclusive`的目的是仅允许那些存在 CCD 文件的客户端。如果某个客户端没有对应的 CCD 文件，则该客户端将被拒绝访问。客户端证书的名称会在服务器日志中列出：

```
... client-ip:45432 TLS Auth Error: --client-config-dir authentication failed for common name 'client1' 

```

然而，也可以通过以下方式获取：

```
openssl x509 -subject -noout -in client1.crt 

```

查找以`/CN=`开头的第一部分，并将所有空格转换为下划线。

OpenVPN 服务器进程是以`nobody`用户身份运行的。由于我们对`/etc/openvpn/cookbook/clients`目录设置了非常严格的权限，因此该用户无法读取该目录中的任何文件。当带有`client1`证书的客户端连接时，OpenVPN 服务器无法读取 CCD 文件（即使该文件可能存在）。由于`ccd-exclusive`指令的存在，客户端因此被拒绝访问。

## 还有更多……

本节将解释如何增加日志的详细程度以及一些最常见的`client-config-dir`错误。

### 更详细的日志记录

增加日志的详细程度通常在排查`client-config-dir`问题时非常有帮助。使用`verb 5`并具备正确权限时，你将在 OpenVPN 服务器日志中看到以下日志条目：

```
client1/client-ip:39814 OPTIONS IMPORT: reading client specific options from: /etc/openvpn/cookbook/clients/client1 

```

如果在服务器日志中没有看到此消息，那么可以安全地假设 CCD 文件没有被读取。

### 其他常见的`client-config-dir`错误

有一些常见的`client-config-dir`错误：

+   使用非绝对路径来指定`client-config-dir`指令，例如：

    ```
            client-config-dir clients

    ```

    这在某些情况下可能有效，但在启动服务器时，或者与`--chroot`或`--cd`等指令结合使用时，必须非常小心。尤其是在使用`--chroot`指令时，所有路径，包括绝对路径，将相对于`chroot`路径。

+   CCD 文件本身必须正确命名，且没有任何扩展名。这通常会让 Windows 用户感到困惑。请查看服务器日志，查看 OpenVPN 服务器认为客户端证书的`/CN= name`是什么。此外，请注意，OpenVPN 会重写某些字符，比如空格。有关将要重映射的字符的完整列表，请参考手册中的*字符串类型和重映射*部分。

+   CCD 文件及其完整路径必须对 OpenVPN 服务器进程运行的用户可读（通常是`nobody`）。

## 另见

+   第二章中的*使用 client-config-dir 文件*配方，*客户端-服务器仅 IP 网络*，解释了客户端配置文件的基本用法。

# 排查多个远程问题

在本示例中，我们将演示如何排查使用多个`remote`指令时出现的问题。能够使用多个`remote`指令是 OpenVPN 2.2 版本以来的一项较少为人知的功能。它允许用户指定多个连接配置文件，以连接到不同的主机、不同的端口和不同的协议（例如，TCP 与 UDP）。

使用此指令时，如果在配置文件的其他地方或在命令行中指定额外的指令时，存在一个需要注意的陷阱。在这个示例中，我们将展示这个陷阱是什么。

## 正在准备中

使用第二章中的第一个配方设置客户端和服务器证书，*客户端-服务器 IP-only 网络*。在这个配方中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端计算机运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。请将客户端配置文件`basic-udp-client.conf`与`basic-udp-server.conf`（来自*服务器端路由*配方，第二章）一起保留，并使用客户端配置文件`basic-udp-client.conf`。

## 如何操作...

1.  使用配置文件`basic-udp-server.conf`启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  接下来，创建客户端配置：

    ```
            client 
            remote openvpnserver.example.com 1195 udp 
            remote openvpnserver.example.com 1196 tcp 
            port 1194 

            dev tun 
            nobind 

            remote-cert-tls server 
            tls-auth /etc/openvpn/cookbook/ta.key 1 
            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/client1.crt 
            key      /etc/openvpn/cookbook/\client1.key  

    ```

    请注意，我们指定了两个连接配置，一个使用 UDP 协议连接到服务器，`端口 1195`，另一个使用 TCP 协议，`端口 1196`。然而，我们期望使用`port 1194`这一行覆盖端口号。将此文件保存为`example6-8-client.conf`。

1.  启动客户端：

    ```
            [root@client]# openvpn --config example6-8-client.conf

    ```

    然后，客户端会因以下错误信息而无法连接：

    ```
            ... UDPv4 link local: [undef] 
            ... UDPv4 link remote: [AF_INET]server-ip:1195 

    ```

    所以，即使我们明确声明了`port 1194`，客户端仍然使用 UDP 协议，`端口 1195`进行连接。

## 它是如何工作的...

当你使用以下方式指定远程连接条目时：

```
 remote openvpnserver.example.com 1195 udp
```

OpenVPN 会将其内部转换为连接配置文件。通常，连接配置文件会继承全局配置中的设置。连接配置文件中的任何内容都会覆盖全局配置中指定的内容，即使它在配置文件中稍后指定，或在命令行中指定。因此，`port 1194`这一行没有任何效果，客户端尝试使用第一个（默认）`remote`连接配置文件、UDP 协议和`端口 1195`进行连接。

要解决这个问题，需要在配置文件中的`remote`行修改端口号。

## 还有更多...

指定`remote openvpnserver.example.com 1195 udp`的另一种方法是使用连接块：

```
<connection> 
    remote openvpnserver.example.com 
    port 1195  
    proto udp 
</connection> 

```

然而，在连接块内部，您可以指定更多的指令，正如我们将在*使用连接块*这一配方中看到的那样，位于第十章，*高级配置*。

## 另请参见

+   在第十章的*使用连接块*一节中，详细讲解了连接块的使用方法。

# 故障排除桥接问题

在本节中，我们将演示如何排除与桥接相关的常见问题。OpenVPN 桥接配置可能很棘手，因为警告和错误信息可能令人困惑。在本节中，我们将故意制造一个常见的配置错误，并展示如何排除故障。

## 准备工作

使用第二章中的第一个食谱设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。对于这个食谱，服务器运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。请保留来自*桥接 - Linux*食谱的脚本`example3-3-bridge-start`和`example3-3-bridge-stop`，以及来自*启用客户端到客户端流量*食谱中的客户端配置文件`example-3-2-client2.ovpn`，这些都来自第三章，*客户端-服务器以太网风格网络*。

## 操作方法...

1.  创建服务器配置文件：

    ```
            proto udp 
            port 1194 
            dev tap 
            server-bridge 192.168.4.65 255.255.255.0 192.168.4.128 
            192.168.4.200 
            push "route 192.168.4.0 255.255.255.0" 

            tls-auth /etc/openvpn/cookbook/ta.key 0 
            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/server.crt 
            key      /etc/openvpn/cookbook/server.key 
            dh       /etc/openvpn/cookbook/dh2048.pem 

            persist-key 
            persist-tun 
            keepalive 10 60 

            user  nobody 
            group nobody  # use "group nogroup" on some distros 

            daemon 
            log-append /var/log/openvpn.log 

    ```

    请注意，我们并未明确指定适配器名称（tap0）。将其保存为`example-6-9-server.conf`。

1.  创建网络桥接并验证其工作状态：

    ```
     [root@server]# bash example3-3-bridge-start 
              TUN/TAP device tap0 opened 
              Persist state set to: ON 
     [root@server]# brctl show 
              bridge name bridge id         STP enabled interfaces 
              br0         8000.00219bd2d422 no          eth0 
                           tap0 

    ```

1.  启动 OpenVPN 服务器：

    ```
     [root@server]# openvpn --config example6-9-server.conf

    ```

1.  启动客户端：![操作方法...](img/image00379.jpeg)

1.  现在，尝试连接到服务器：

    ```
    [WinClient]C:> ping 192.168.4.65

    ```

    即使连接已经建立，客户端仍然无法连接到服务器。

    请记住，在停止 OpenVPN 服务器进程后，关闭以太网桥接。

## 它是如何工作的……

本例中的连接失败是因为 OpenVPN 服务器在启动时打开了一个新的 tap 适配器，而不是连接到桥接。服务器日志文件中给出了提示：

```
... TUN/TAP device tap1 opened 

```

检查服务器上的 tap 接口时，我们看到现在有两个 tap 接口：

```
[root@server]# ip addr show
...
39: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue 
    state UNKNOWN 
 link/ether 00:25:90:c0:3e:d0 brd ff:ff:ff:ff:ff:ff
 inet 192.168.4.65/24 brd 192.168.4.255 scope global br0
 inet6 fe80::225:90ff:fec0:3ed0/64 scope link 
 valid_lft forever preferred_lft forever
40: tap1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 
    100
 link/ether ae:9f:3e:ae:93:ba brd ff:ff:ff:ff:ff:ff

```

第二个 tap 接口，`tap1`，是 OpenVPN 正在使用的接口，并且没有分配 IP 地址！

为了解决这个问题，需要在服务器配置文件中指定正确的 tap 适配器。

## 另见

+   第三章中的*Linux - 桥接*一节，详细解释了如何在 Linux 上设置桥接。

# 如何读取 OpenVPN 日志文件

排除 OpenVPN 配置问题通常需要正确地阅读和解释 OpenVPN 日志文件。在这个指南中，将不会介绍 OpenVPN 的新特性，而是会详细讲解如何分析 OpenVPN 日志文件。将会使用本章前面 *排除 MTU 和 tun-mtu 问题* 这一节中的配置作为起始点。

## 准备就绪

使用与本章前面 *排除 MTU 和 tun-mtu 问题* 章节中的相同配置进行操作。本节中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，而客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。保留从 第二章 *服务器端路由* 这一节中获得的 `basic-udp-server.conf` 配置文件。对于客户端，保留从 *排除 MTU 和 tun-mtu 问题* 章节中获得的 `example6-5-client.conf` 配置文件。

## 如何操作...

1.  使用配置文件 `basic-udp-server.conf` 启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  接下来，使用增加的详细日志设置启动客户端，并且日志文件中不包含时间戳：

    ```
    [root@client]# openvpn --config example6-5-client.conf \
     --verb 7 --suppress-timestamps

    ```

    连接会启动，但无法发送大数据包。

1.  通过输入以下内容来触发错误：

    ```
    [client]$ ping -c 1 10.200.0.1
    [client]$ ping -c 1 -s 1450 10.200.0.1

    ```

1.  中止客户端。日志文件会很快变得很大。

1.  使用文本编辑器打开日志文件并浏览它。日志文件的一般结构将在下一部分中解释。

## 它是如何工作的...

日志文件的第一部分包含了配置文件和命令行参数中指定的配置信息。这一部分从以下一行开始：

```
Current Parameter Settings: 
  config = 'example6-5-client.conf' 

```

它以以下这一行结束：

```
OpenVPN 2.3.11 x86_64-redhat-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [PKCS11] [MH] [IPv6] built on May 10 2016 

```

这一部分大约有 275 行，具体取决于配置，包含了 OpenVPN 所认为的配置内容。请仔细检查此部分，确保你与它的配置一致。

接下来的有趣部分如下：

```
Control Channel Authentication: using '/etc/openvpn/cookbook/ta.key' as a OpenVPN static key file 
Outgoing Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication 
Outgoing Control Channel Authentication: HMAC KEY: 51cc24c0 ... 
Outgoing Control Channel Authentication: HMAC size=20 ... Incoming Control Channel Authentication: Using 160 bit ... 
Incoming Control Channel Authentication: HMAC KEY: 1c748f91 ...  
Incoming Control Channel Authentication: HMAC size=20 ...  

```

这一部分显示了 `tls-auth` 密钥已被读取并使用，且两个单独的 HMAC 密钥已被派生。密钥实际上会打印在日志文件中，因此你可以通过服务器日志文件中的输出与之进行对照。服务器接收的密钥应与客户端发送的密钥相同，反之亦然。本章前面 *密钥不匹配* 这一节中的配置错误会出现在这里。

紧接在这一部分之后是警告，它是本章前面 *排除 MTU 和 tun-mtu 问题* 章节中配置错误的根本原因：

```
WARNING: normally if you use --mssfix and/or --fragment, you should also set --tun-mtu 1500 (currently it is 1400) 

```

以 `WARNING` 开头的日志信息应始终特别关注。在某些情况下，这些警告可以忽略，但在本例中，它是导致 VPN 连接无法正常工作的根本原因。

在这个警告之后，会出现一系列如下形式的消息：

```
UDPv4 link remote: [AF_INET]server-ip:1194 
UDPv4 WRITE [42] to [AF_INET]server-ip:1194: P_CONTROL_HARD_RESET_CLIENT_V2 kid=0 pid=[ #1 ] [ ] pid=0 DATA len=0 
UDPv4 READ [54] from [AF_INET]server-ip:1194: P_CONTROL_HARD_RESET_SERVER_V2 kid=0 pid=[ #1 ] [ 0 ] pid=0 DATA len=0 
TLS: Initial packet from [AF_INET]server-ip:1194, sid=c483bcc9 a60cc834 
PID_TEST [0] [TLS_AUTH-0] [] 0:0 1469290891:1 t=1469290891[0] r=[0,64,15,0,1] sl=[0,0,64,528] 
UDPv4 WRITE [50] to [AF_INET]server-ip:1194: P_ACK_V1 kid=0 pid=[ #2 ] [ 0 ] 
UDPv4 WRITE [249] to [AF_INET]server-ip:1194: P_CONTROL_V1 kid=0 pid=[ #3 ] [ ] pid=1 DATA len=207 

```

这些消息都是客户端与服务器之间初始握手的一部分，用于交换配置信息、加密密钥及其他建立 VPN 连接所需的信息。紧接着是另一个关于配置错误的提示：

```
WARNING: 'link-mtu' is used inconsistently, local='link-mtu 1441', remote='link-mtu 1541' 
WARNING: 'tun-mtu' is used inconsistently, local='tun-mtu 1400', remote='tun-mtu 1500'  

```

我们跳过了许多 `TLS_prf` 消息，继续到达连接握手的结束部分：

```
Control Channel: TLSv1.2, cipher TLSv1/SSLv3 DHE-RSA-AES256-GCM-SHA384, 2048 bit RSA 
[openvpnserver] Peer Connection Initiated with [AF_INET]server-ip:1194 

```

此时，OpenVPN 客户端已与服务器建立了初始连接，若有配置指令推送，客户端现在已准备好处理：

```
PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.200.0.1,topology subnet,ping 10,ping-restart 60,ifconfig 10.200.0.2 255.255.255.0' 

```

这是一个重要的检查项，它显示了服务器实际上推送给客户端的内容。确认这是否与你认为服务器应该推送的内容一致。

之后，启动并初始化本地 TUN 适配器，第一批数据包开始流动。

第一个 `ping` 命令运行正常，从以下部分可以看到：

```
TUN READ [84] 
... 
UDPv4 WRITE [125] to server-ip:1194: P_DATA_V1 kid=0 DATA len=124 
UDPv4 READ [125] from server-ip:1194: P_DATA_V1 kid=0 DATA len=124 
TLS: tls_pre_decrypt, key_id=0, IP=server-ip:1194 
TUN WRITE [84] 

```

`TUN READ` 是从 TUN 接口读取的 ping 命令，随后通过加密通道写入远程服务器。注意包大小的差异：通过加密隧道发送的包为 125 字节，比从 TUN 接口读取的原始包大 41 字节。这正好匹配了前面日志文件中所显示的 `link-mtu` 和 `tun-mtu` 选项之间的差异。

接下来是 `ping -s 1450` 命令出现问题的部分。如果接口的 MTU 设置为 1400，1450 字节的 `ping` 无法一次性读取，因此需要进行两次 `TUN READ` 才能捕获所有数据：

```
TUN READ [1396] 
... 
UDPv4 WRITE [1437] to server-ip:1194: P_DATA_V1 kid=0 DATA len=1436 
TUN READ [102] 
... 
UDPv4 WRITE [141] to server-ip:1194: P_DATA_V1 kid=0 DATA len=140 

```

注意，数据实际上是作为两个独立的数据包发送到服务器的。这是完全正常的行为，因为数据包需要进行分段。包的大小与 MTU 大小之间的计算在这种情况下失效，因为第二个数据包并不是一个完整的 IP 包。

服务器接收到大的 `ping` 命令并发送了同样大的回复。由于服务器的 MTU 设置为 1500，因此无需对数据进行分段，数据作为一个完整的数据包到达客户端：

```
UDPv4 READ [1441] from server-ip:1194: P_DATA_V1 kid=0 DATA len=1440 
TLS: tls_pre_decrypt, key_id=0, IP=server-ip:1194 
Authenticate/Decrypt packet error: packet HMAC authentication failed 

```

然而，客户端期望接收到一个最大为 1400 字节的数据包。它无法正确解码较大的数据包，并输出 `packet HMAC authentication failed` 消息。

最后，当我们中止客户端时，会看到 `interrupted system call` 消息（在此情况下，使用了 ***Ctrl*** + ***C*** 中止客户端，并且在客户端实际停止之前，还会出现一系列清理消息）：

```
event_wait : Interrupted system call (code=4) 
PID packet_id_free 
... 
TCP/UDP: Closing socket 
Closing TUN/TAP interface 
/sbin/ip addr del dev tun0 10.200.0.2/24 
PID packet_id_free 
SIGINT[hard,] received, process exiting 

```

考虑到客户端配置中包含了以下内容：

```
user nobody 

```

然后，我们也应该会看到类似这样的消息：

```
SIOCSIFADDR: Permission denied 
SIOCSIFFLAGS: Permission denied 
Linux ip addr del failed: external program exited with error status: 255 

```

在这种情况下，这些是无害的。

## 还有更多内容...

在基于 UNIX 的操作系统上，还可以通过 `syslog` 发送 OpenVPN 日志输出。这样可以让系统管理员通过单一的系统日志接口有效地管理大量计算机。要通过 `syslog` 发送日志消息，需将指令 `log-append` 替换为以下内容：

```
syslog [name] 

```

在这里，`name`是一个可选参数，用于指定 syslog 日志文件中 OpenVPN 实例的名称。如果在单个主机上运行多个 OpenVPN 实例，并且它们都使用`syslog`来记录输出和错误信息，那么这个参数特别有用。

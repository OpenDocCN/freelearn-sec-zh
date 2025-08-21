# 第十章。高级配置

本章内容包括：

+   在配置文件中包含配置文件

+   多个远程和远程随机

+   内联证书

+   连接块

+   `ifconfig-pool-persist`的详细信息

+   使用 SOCKS 代理进行连接

+   通过 HTTP 代理进行连接

+   通过带认证的 HTTP 代理进行连接

+   无 IP 设置 - `ifconfig-noexec`

+   与 HTTPS 服务器共享端口

+   路由功能 - `redirect-private`, `allow-pull-fqdn`

+   过滤掉推送的选项

+   分配公共 IP 地址

# 介绍

本章中的配方将涵盖 OpenVPN 的高级配置。本章将重点介绍一些 OpenVPN 提供的鲜为人知的配置选项，以及一些针对实际部署的高级配方。配方将涵盖高级服务器配置，如使用连接块和内联证书，以及高级客户端配置，如使用代理服务器连接 OpenVPN 服务器。

# 在配置文件中包含配置文件

使用配置文件时，较少为人所知的可能性之一是能够包含其他配置文件。当设置一个复杂的 OpenVPN 服务器时，尤其可以派上用场，因为它允许同时提供多个 OpenVPN 实例。通用配置指令可以存储在一个文件中，而每个实例的特定连接部分可以存储在单独的文件中。在这个配方中，我们将设置两个 OpenVPN 实例，一个使用 UDP，另一个使用 TCP 作为传输协议。

请注意，此选项不允许在多个实例之间共享 VPN IP 地址范围。

## 准备工作

使用第二章中第一个配方设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。在此配方中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11 版本。

## 如何操作……

1.  首先，创建通用配置文件：

    ```
            dev tun 

            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/server.crt 
            key      /etc/openvpn/cookbook/server.key 
            dh       /etc/openvpn/cookbook/dh2048.pem 
            tls-auth /etc/openvpn/cookbook/ta.key 0 

            persist-key 
            persist-tun 
            keepalive 10 60 

            push "route 10.198.0.0 255.255.0.0" 
            topology subnet 

            user  nobody 
            group nobody 

            daemon 

    ```

    将其保存为`example10-1-common.conf`。请注意，此配置文件不包含协议规范或服务器行。此外，请注意，我们将为两个 OpenVPN 实例使用相同的服务器证书。

1.  接下来，创建以下用于 UDP 连接的服务器配置文件：

    ```
            config example10-1-common.conf 

            proto udp 
            port 1194 
            server 10.200.0.0 255.255.255.0 

            log-append /var/log/openvpn-udp.log 

    ```

    将其保存为`example10-1-server1.conf`。

1.  并创建一个用于 TCP 连接的服务器配置文件：

    ```
            config example10-1-common.conf 

            proto tcp 
            port 443 
            server 10.201.0.0 255.255.255.0 

            log-append /var/log/openvpn-tcp.log 

    ```

    将其保存为`example10-1-server2.conf`。该实例正在监听 HTTPS 端口`443`，这是一个常用的技巧，用于绕过非常严格的防火墙，或解决配置不当的防火墙问题。

1.  启动两个服务器：

    ```
    [root@server]# openvpn --config example10-1-server1.conf
    [root@server]# openvpn --config example10-1-server2.conf

    ```

    检查日志文件，查看两个服务器是否已成功启动。

## 它是如何工作的……

OpenVPN 配置文件的处理方式与命令行选项非常相似。由于`--config`命令行选项几乎总是使用，因此也可以在配置文件中再次使用它。这允许配置选项的拆分，将所有 OpenVPN 实例共有的指令存储在一个文件中，便于维护。与之相对，特定实例的指令（例如`server`指令）可以存储在更小的配置文件中，这些文件通常不会随时间变化。这样可以简化大规模 OpenVPN 服务器设置的维护工作。

OpenVPN 有一个内置的保护机制，避免递归地包含相同的配置文件。

# 多个远程服务器和`remote-random`

OpenVPN 内置（有限的）自动故障转移和负载均衡支持：如果无法建立与一个 OpenVPN 服务器的连接，则选择下一个配置的服务器。可以使用`remote-random`指令将多个 OpenVPN 客户端负载均衡到多个 OpenVPN 服务器上。在此配方中，我们将设置两个 OpenVPN 服务器，然后使用`remote-random`指令让客户端选择两个服务器中的任意一个。

请注意，OpenVPN 不提供透明的故障转移，这意味着现有连接不会自动迁移到另一个服务器。实现透明故障转移对于 VPN 设置（不仅仅是 OpenVPN）来说要困难得多，因为安全会话密钥也需要从一个服务器迁移到另一个服务器。目前，OpenVPN 无法实现这一功能。

## 准备就绪

我们将使用以下网络布局：

![准备就绪](img/image00431.jpeg)

使用第二章中的第一个配方设置客户端和服务器证书，*客户端-服务器 IP 专用网络*。对于这个配方，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行 Fedora 22 Linux 和 OpenVPN 2.3.11。请保留来自*服务器端路由*配方的配置文件`basic-udp-server.conf`，该配方来自第二章，*客户端-服务器 IP 专用网络*，以及客户端配置文件`basic-udp-client.conf`。

## 如何操作...

1.  启动两个服务器：

    ```
    [root@server1]# openvpn --config basic-udp-server.conf
    [root@server2]# openvpn --config basic-udp-server.conf

    ```

    检查日志文件，确保两个服务器已经成功启动。

    请注意，我们可以在两个服务器上使用完全相同的配置文件。通过使用伪装，VPN 客户端将表现为来自`server1`或`server2`。

1.  在两个服务器上设置伪装：

    ```
    [root@server1]# iptables -t nat -I POSTROUTING -o eth0 \
     -j MASQUERADE
    [root@server2]# iptables -t nat -I POSTROUTING -o eth0 \
     -j MASQUERADE

    ```

1.  创建客户端配置文件：

    ```
            client 
            proto udp 
            remote openvpnserver1.example.com 1194 
            remote openvpnserver2.example.com 1194 
            remote-random 
            dev tun 
            nobind 

            remote-cert-tls server 
            tls-auth /etc/openvpn/cookbook/ta.key 1 
            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/client1.crt 
            key     /etc/openvpn/cookbook/client1.key 

    ```

1.  将其保存为`example10-2-client.conf`。

1.  启动客户端：

    ```
    [root@client]# openvpn --config example10-2-client.conf

    ```

OpenVPN 客户端将随机选择一个服务器进行连接。

在建立连接后，停止客户端连接到的服务器上的第一个 OpenVPN 进程：

```
[root@server1]# killall openvpn

```

等待客户端重新连接。在默认超时期后，客户端将重新连接到备用服务器。

## 它是如何工作的...

当 OpenVPN 客户端启动并且指定了 `remote-random` 时，它会从可用的远程服务器列表中随机选择一个服务器。如果无法建立与该服务器的 VPN 连接，它将选择列表中的下一个服务器，以此类推。当 VPN 连接断开时，例如由于服务器故障，OpenVPN 客户端将在默认超时期后尝试重新连接。在第二章的 *服务器端路由* 配方中使用的服务器配置文件里，超时周期是通过 `keepalive` 选项进行配置的。

## 更多内容...

在设置故障转移 OpenVPN 解决方案时，有许多需要考虑的因素，其中一些在这里概述。

### 混合使用基于 TCP 和 UDP 的设置

也可以通过在 `remote` 指令中指定协议类型，将 TCP 和 UDP 基础的设置混合使用：

```
remote openvpnserver1.example.com 1194 udp 
remote openvpnserver2.example.com 1194 tcp 

```

在这种情况下，使用连接块会更加方便。连接块的使用将在本章稍后进行解释。

### 使用基于 TCP 的连接的优势

当将基于 TCP 的设置与故障转移解决方案结合使用时，有一个主要优势。如果客户端连接的 OpenVPN 服务器不可用，TCP 连接几乎会立即失败。这导致超时周期非常短，之后 OpenVPN 客户端将尝试重新连接。使用基于 UDP 的设置时，客户端无法如此容易地检测服务器是否不可用，必须先等待 `keepalive` 超时过去。

### 自动恢复连接到第一个 OpenVPN 服务器

时常会有人提问，是否可以配置 OpenVPN 以支持自动恢复：设置第二个 OpenVPN 实例提供故障转移解决方案。当主 OpenVPN 服务器不可用时，备用实例接管。然而，当主 OpenVPN 服务器重新上线时，客户端不会自动重新连接到主服务器。为此，需要进行客户端重置（或第二个 OpenVPN 实例的服务器重置）。可以通过脚本实现这一点，但这在很大程度上取决于所接受的连接类型：OpenVPN 客户端需要一些时间来检测远程服务器不可响应并重新连接。在这种设置下，VPN 连接将是间歇性的，特别是当与主 OpenVPN 服务器的网络连接不稳定时，这可能导致非常低的可用性。

一种简单粗暴的方法让所有客户端恢复连接到第一个服务器，是通过第二个服务器上的管理接口断开所有客户端。

## 另见

+   来自第二章的 *服务器端路由* 方案，*客户端-服务器 IP 网络*，解释了 OpenVPN 的基本设置。

+   *连接块*配方，它展示了一种支持在单一客户端配置文件中使用多个服务器的替代且更灵活的方法

# 内联证书

为了简化 OpenVPN 配置及公私钥文件的部署，现已提供一项新功能，可以将它们全部包含在一个文件中。这是通过将`ca`、`cert`、`key`，以及可选的`tls-auth`文件的内容集成到客户端配置文件中来实现的。在这个配方中，我们将设置这样的配置文件，并使用它连接到我们的标准 OpenVPN 服务器。

## 准备就绪

我们将使用以下网络布局：

![准备就绪](img/image00432.jpeg)

使用第二章中的第一个配方，*客户端-服务器 IP 仅网络*，来设置客户端和服务器证书。对于这个配方，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，而客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。保留来自第二章的*服务器端路由*配方中的配置文件`basic-udp-server.conf`，以及客户端配置文件`basic-udp-client.conf`。

## 如何操作...

1.  首先，启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  创建客户端配置文件：

    ```
            client 
            proto udp 
            remote openvpnserver.example.com 
            port 1194 
            dev tun 
            nobind 

            remote-cert-tls server 
            key-direction 1 

            <ca> 
            -----BEGIN CERTIFICATE----- 
            # insert base64 blob from ca.crt 
            -----END CERTIFICATE----- 
            </ca> 

            <cert> 
            -----BEGIN CERTIFICATE----- 
            # insert base64 blob from client1.crt 
            -----END CERTIFICATE----- 
            </cert> 

            <key> 
            -----BEGIN PRIVATE KEY----- 
            # insert base64 blob from client1.key 
            -----END PRIVATE KEY----- 
            </key> 

            <tls-auth> 
            -----BEGIN OpenVPN Static key V1----- 
            # insert ta.key 
            -----END OpenVPN Static key V1----- 
            </tls-auth> 

    ```

    将`ca.crt`、`client1.crt`、`client1.key`和`ta.key`文件的内容插入配置文件中。并将其保存为`example10-3-client.conf`。

1.  然后，连接客户端：

    ```
    [root@client]# openvpn --config example10-3-client.conf

    ```

## 它是如何工作的...

当 OpenVPN 解析配置文件时，它会扫描`ca`、`cert`、`key`和`tls-auth`指令（对于服务器配置文件还包括`dh`），同时也会扫描以`<ca>`、`<cert>`、`<key>`、`<tls-auth>`和`<dh>`为开头的类似 XML 的块。如果找到类似 XML 的块，则会读取该块的内容，并按指定文件的方式处理它。当所有必要的配置文件或块都存在时，连接将建立。

请注意，并不要求以相同的方式处理所有上述的配置指令。也可以仅为 CA 证书和`tls-auth`文件指定内联块，因为这些文件对于所有客户端通常是静态的。

## 还有更多内容...

正如《OpenVPN 2 Cookbook》第一版中所述，之前也可以使用`[[inline]]`标签来指定内联文件。然而，这个标签从未得到妥善的文档化，并且从 OpenVPN 2.3 开始，它已不再起作用。

# 连接块

与前一个配方中使用的内联证书类似，也可以指定连接块。这些连接块被视为多个远程服务器的定义，并按顺序尝试，直到建立 VPN 连接为止。使用连接块的好处是，对于每个远程服务器，可以指定特定的参数，如协议（UDP 或 TCP）、远程端口、是否使用代理服务器等。

在本配方中，我们将设置两个服务器，一个监听 UDP 端口，另一个监听 TCP 端口。然后，我们将配置 OpenVPN 客户端以通过 UDP 连接尝试连接第一个服务器。如果连接无法建立，客户端将尝试通过 TCP 连接连接第二个服务器。

## 准备中

我们将使用以下网络布局：

![准备中](img/image00433.jpeg)

使用第二章中的第一个配方，设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。在此配方中，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行 Fedora 22 Linux 和 OpenVPN 2.3.11。保留*服务器端路由*配方中的配置文件`basic-udp-server.conf`，该配方位于第二章，*客户端-服务器仅 IP 网络*，以及*调优基于 TCP 的连接*配方中的服务器配置文件`example8-9-server.conf`，该配方位于第八章，*性能调优*。

## 操作步骤...

1.  启动两个服务器：

    ```
    [root@server1]# openvpn --config basic-udp-server.conf
    [root@server2]# openvpn --config example8-9-server.conf

    ```

1.  检查日志文件，确认两个服务器已经成功启动。

1.  创建客户端配置文件：

    ```
            client 
            dev tun 

            <connection> 
            remote openvpnserver1.example.com 
            proto udp 
            port 1194 
            </connection> 

            <connection> 
            remote openvpnserver2.example.com 
            proto tcp 
            port 1194 
            </connection> 

            remote-cert-tls server 
            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/client1.crt 
            key      /etc/openvpn/cookbook/client1.key 
            tls-auth /etc/openvpn/cookbook/ta.key 1 

    ```

1.  将其保存为`example10-4-client.conf`。

1.  启动客户端：

    ```
    [root@client]# openvpn --config example10-4-client.conf

    ```

1.  连接建立后，停止客户端连接的第一个 OpenVPN 进程：

    ```
    [root@server1]# killall openvpn

    ```

    等待客户端重新连接。在默认的超时期后，客户端将使用 TCP 协议重新连接到备用服务器。

## 工作原理...

当 OpenVPN 客户端启动时，它会尝试连接到第一个`<connection>`块中指定的服务器。如果该连接失败，它将尝试下一个`<connection>`块条目，以此类推。当 OpenVPN 服务器不可用或被停止时，客户端将自动重启并再次尝试连接到第一个可用的 OpenVPN 服务器。

OpenVPN 客户端首先解析全局指令，这些指令在`<connection>`块之外指定。对于每个块，使用块特定的指令覆盖全局指令。这使得在`<connection>`块中只需指定每个连接不同的参数。

## 还有更多...

连接块以及内联证书是非常方便的功能，可以通过单个文件轻松分发 OpenVPN 配置。然而，这些功能的一个后果是，使用命令行来覆盖配置文件中指定的指令变得更加困难，甚至几乎不可能。在使用连接块时，还有一些其他需要注意的事项。

### 连接块内允许的指令

连接块中只允许使用少数几条指令：

+   `bind` 和 `bind-ipv6`

+   `connect-retry`、`connect-retry-max` 和 `connect-timeout`

+   `explicit-exit-notify`

+   `float`

+   `http-proxy`、`http-proxy-option`、`http-proxy-retry` 和 `http-proxy-timeout`

+   `link-mtu` 和 `link-mtu-extra`

+   `local lport`

+   `mssfix`

+   `nobind`

+   `port`

+   `proto`

+   `remote` 和 `rport`

+   `socks-proxy` 和 `socks-proxy-retry`

+   `tun-mtu` 和 `tun-mtu-extra`

所有其他指令都被视为全局指令，且只能指定一次。

### 混合 TCP 和 UDP 配置时的潜在问题

连接块使得混合 TCP 和 UDP 配置变得非常容易。缺点是，配置文件中指定的全局参数必须对 TCP 和 UDP 配置都有效。

## 另见

+   本章前面提到的 *多个远程和远程随机* 方法，解释了如何在不使用连接块的情况下实现相同的设置

# `ifconfig-pool-persist` 的详细信息

OpenVPN 中的一个选项是 `ifconfig-pool-persist`，它可能会导致很多混淆。这个指令告诉 OpenVPN 服务器保持一个持久的 IP 地址列表，分配给不同的客户端。当客户端稍后重新连接时，之前使用的地址会被重新使用。这只是为 OpenVPN 客户端分配静态地址的三种方法之一。其他两种方法是：

+   在客户端连接脚本中使用 `ifconfig-push` 语句

+   在客户端配置文件中使用 `ifconfig-push` 语句

这两个参数优先于 `ifconfig-pool-persist` 文件中的条目。经验表明，当 OpenVPN 设置无法正常工作时，暂时禁用此选项通常是个好主意。

在本方法中，我们将演示如何使用 `ifconfig-pool-persist` 以及它的潜在问题。

## 准备工作

我们将使用以下网络布局：

![准备工作](img/image00434.jpeg)

使用第二章中的第一个配方设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。对于这个配方，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行 Fedora 22 Linux 和 OpenVPN 2.3.11。保留*第二章*中*服务器端路由*配方中的配置文件`basic-udp-server.conf`，以及来自同一配方的客户端配置文件`basic-udp-client.conf`。第二个客户端运行 Windows 7 64 位和 OpenVPN 2.3.11。对于此客户端，请保留*使用 ifconfig-pool 块*配方中来自第二章的客户端配置文件`basic-udp-client.ovpn`。

## 如何操作...

1.  通过向`basic-udp-server.conf`文件添加以下行来创建服务器配置文件：

    ```
    ifconfig-pool-persist /etc/openvpn/cookbook/ipp.txt

    ```

1.  将其保存为`example10-4-server.conf`文件。

1.  启动服务器：

    ```
    [root@server]# openvpn --config example10-4-server.conf

    ```

    一个空文件`/etc/openvpn/cookbook/ipp.txt`将在服务器启动时创建。

1.  连接第一个客户端：

    ```
    [root@client]# openvpn --config basic-udp-client.conf

    ```

    通常，这个客户端将被分配`10.200.0.2`，这是`server` IP 范围内第一个可用的 IP 地址。

1.  停止客户端和服务器。列出`ipp.txt`文件的内容：

    ```
    [root@server]# cat /etc/openvpn/cookbook/ipp.txt
    client1,10.200.0.2

    ```

1.  重新启动服务器。现在，连接第二个客户端，该客户端有不同的证书：![如何操作...](img/image00435.jpeg)

    现在，这个客户端将被分配地址`10.200.0.3`。如果没有`ifconfig-pool-persist`选项，它将被分配第一个可用地址`10.200.0.2`。

## 它是如何工作的...

当 OpenVPN 服务器启动时，它会读取`ipp.txt`文件（如果存在），并尝试重新分配文件中找到的客户端证书的 IP 地址。每当一个 OpenVPN 客户端使用现有的客户端证书连接时，它将被分配`ipp.txt`文件中找到的地址，除非服务器的 VPN IP 地址空间对已经连接的客户端数量来说过小。在这种情况下，客户端将从服务器 VPN IP 地址空间中获得第一个可用地址。

第一个连接的客户端从 VPN IP 服务器地址范围中接收到第一个可用地址`10.200.0.2`。当 OpenVPN 服务器关闭时，这些信息会被记录在`ipp.txt`文件中。第二次启动 OpenVPN 服务器时，这些信息会被重新加载，并且地址`10.200.0.2`被为证书`client1`的客户端保留。当第二个客户端使用证书`client2`连接时，它将获得服务器 VPN IP 地址范围中的下一个可用地址，即`10.200.0.3`。当服务器再次关闭时，这些信息也会记录在`ipp.txt`文件中。

这意味着，从现在开始，第一个客户端将始终获得 `.2` 地址，第二个客户端将获得 `.3` 地址。然而，并不能保证列出的 IP 地址会分配给特定的客户端证书。例外情况发生在多个 VPN 客户端连接到服务器时。如果 VPN IP 地址范围被用尽，而第一个客户端此时没有连接，它的地址会被回收并分配给其他 VPN 客户端。如果具有证书 `client1` 的客户端随后尝试连接服务器，它将被分配到第一个可用地址。为了保证分配，可以使用 `client-config-dir` 文件。

## 还有更多内容...

使用 `ifconfig-pool-persist` 指令时，需要注意一些陷阱。

### 指定更新间隔

因为我们没有显式指定更新间隔，`ipp.txt` 文件每 600 秒（10 分钟）更新一次。通过查看新客户端连接后不久的 `ipp.txt` 文件，也可以看到这一点：直到第一个更新间隔过去或 OpenVPN 服务器进程关闭时，新找到的客户端证书和 VPN IP 才会出现在 `ipp.txt` 文件中。

还可以指定 0 秒的更新间隔，这意味着 `ipp.txt` 文件永远不会更新。这会导致 OpenVPN 服务器在启动时将 IP 地址与 `ipp.txt` 文件中找到的客户端证书名称关联，但这些关联之后不会再发生变化。

### 警告 - `duplicate-cn` 选项

`duplicate-cn` 选项可用于允许相同的客户端证书多次连接到同一服务器。如果使用此选项，则 `ifconfig-pool-persist` 选项将变得无效，因为相同的客户端证书会连接两次。这意味着 OpenVPN 服务器必须为每个客户端分配两个不同的 IP 地址，并且 `ipp.txt` 文件中的条目变得毫无意义。

### 当使用 `topology net30` 时

当使用服务器选项 `topology net30` 时，`ipp.txt` 文件的格式会略有不同。在 `net30` 拓扑模式中，每个客户端都会分配一个由四个 IP 地址组成的 `/30` 网络地址：网络地址、VPN 服务器端点地址、实际的客户端 VPN IP 地址，以及 `/30` 网络的广播地址。在 `ipp.txt` 文件中，记录的是其中的第一个地址：

```
client1,10.200.0.4 
client2,10.200.0.8 

```

# 使用 SOCKS 代理连接

在某些情况下，无法直接连接到 OpenVPN 服务器。这种情况最常发生在防火墙限制 UDP 流量时。在这种情况下，OpenVPN 可以通过一个中介主机（即代理）连接到 OpenVPN 服务器。OpenVPN 支持两种类型的代理：SOCKS 和基于 HTTP 的代理，二者都仅通过基于 TCP 的配置工作。本食谱将介绍如何通过 SOCKS 代理访问 OpenVPN 服务器，而接下来的两个食谱将展示如何使用 HTTP 代理，包括和不包括身份验证。

可以通过几乎任何 SSH 客户端轻松设置 SOCKS 代理。在 Linux 和 Mac OS X 上，可以使用`ssh`或`slogin`命令，而在 Windows 上，可以使用免费的 SSH 客户端 PuTTY。在这个步骤中，我们将在 Linux 客户端上使用 SSH 设置一个公共 SOCKS 代理。Windows OpenVPN 客户端将通过此代理连接。

## 准备工作

我们将使用以下网络布局：

![准备工作](img/image00436.jpeg)

使用第二章中的第一个步骤来设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。在本步骤中，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.12，客户端运行 Windows 7 64 位和 OpenVPN 2.3.10。保留来自第八章，*性能调优*的`example8-9-server.conf`配置文件。对于客户端，保留来自第二章的`basic-tcp-client.ovpn`配置文件。

## 如何操作...

1.  启动服务器：

    ```
    [root@server]# openvpn --config example8-9-server.conf

    ```

1.  右键单击 OpenVPN GUI 托盘图标并选择**设置**。填写**SOCKS 代理**主机的名称或 IP 地址，然后单击**确定**：![如何操作...](img/image00437.jpeg)

1.  通过在中介代理主机上设置 SSH 连接来设置**SOCKS 代理**。SSH 连接的目标地址是可以访问 OpenVPN 服务器的服务器：

    ```
    [socks-proxy]$ ssh -g -D 1080 remote-host.example.com

    ```

1.  现在，在另一个终端窗口中启动 OpenVPN 客户端：![如何操作...](img/image00438.jpeg)![如何操作...](img/image00439.jpeg)

1.  连接日志会显示 OpenVPN 首先连接到远程代理主机（在此截图中，使用的 IP 地址是`192.168.3.17`）。然后，该连接被转发到 OpenVPN 服务器，并建立 VPN：![如何操作...](img/image00440.jpeg)

## 工作原理...

**SOCKS 代理**主机充当(OpenVPN)客户端和服务器之间的中介。SOCKS 代理还可以在大多数 Web 浏览器中配置，通常用于通过酒店或企业防火墙访问网络。客户端首先连接到**SOCKS 代理**主机，然后请求与实际终端的新连接，在本例中是 OpenVPN 服务器。如果 SOCKS 主机允许此连接，则连接将建立，VPN 连接可以设置。

## 还有更多...

在使用代理主机设置 VPN 连接之前，有几个事项需要考虑：

### 性能

代理主机往往会严重影响 VPN 设置的性能。使用代理主机时，带宽和延迟通常都会受到影响。这主要是由于需要连接到一个独立的主机。对于这种性能下降，很难采取有效措施。

### 通过 SSH 的 SOCKS 代理

SSH 可以是设置**SOCKS 代理**主机的非常方便工具，通过它可以建立 OpenVPN 连接。除了上述提到的缺点外，这还带来另一个问题：SSH 连接和 VPN 连接通常都会加密。因此，通过加密 VPN 连接传输流量，其本身又通过加密 SSH 连接进行了双重加密！

如果您正在通过 SSH 隧道隧道化 VPN 流量，则应问自己的一个问题是：为什么？什么类型的流量需要通过 VPN 链路进行隧道，而不能通过 SOCKS-over-SSH 隧道进行隧道？大多数现代 Web 浏览器和电子邮件客户端都内置了对 SOCKS 主机的支持，从而无需完整的 VPN。文件共享协议（如 Windows 文件共享（**Common Internet File System**（**CIFS**））也可以通过 SSH 连接进行隧道化。在这些情况下，VPN 隧道只增加了额外的复杂性。

### 使用明文身份验证的 SOCKS 代理

在 OpenVPN 2.2 及更高版本中，添加了对需要身份验证的 SOCKS 代理的支持。对于 OpenVPN 2.2，添加了明文身份验证支持。尽管“明文”可能暗示着不同，但认证机制是安全的，因为与**SOCKS 代理**主机的连接首先是加密的。

## 参见

+   本章的接下来两个配方将处理通过 HTTP 代理将 OpenVPN 客户端连接到服务器的问题

# 连接到 HTTP 代理

如前一配方所述，在某些情况下不可能直接连接到 OpenVPN 服务器。在这种情况下，OpenVPN 可以通过称为代理的中间主机连接到 OpenVPN 服务器。本配方将概述如何通过代理访问 OpenVPN 服务器。

此配方中使用的 HTTP 代理是基于 Linux 的 Apache `httpd` 服务器，并加载了`mod_proxy`模块。可以配置此模块以允许`CONNECT`请求。需要此类型请求来连接到安全的 Web 服务器（HTTPS）以及 OpenVPN 服务器。如果不允许`CONNECT`请求，则无法使用 HTTP 代理设置 OpenVPN 连接。

## 准备就绪

我们将使用以下网络布局：

![准备就绪](img/image00441.jpeg)

使用第二章中的第一篇配方设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。对于这个配方，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.12。客户端运行 Windows 7 64 位和 OpenVPN 2.3.11。保留配置文件`example8-9-server.conf`，来自第八章的*Tuning TCP-based connections*配方，以及相同配方的客户端配置文件`example8-9.ovpn`。

## 如何操作...

1.  启动服务器:

    ```
    [root@server]# openvpn --config example8-9-server.conf

    ```

1.  通过添加以下行来修改客户端配置文件`example8-9.ovpn`：

    ```
    http-proxy http-proxy-host 80
    verb 4

    ```

    在这里，`http-proxy-host`是运行 HTTP 代理软件的主机的名称或 IP 地址。在此示例中，HTTP 代理运行在默认 HTTP 端口`80`上。将配置文件保存为`example10-6.ovpn`。

1.  启动客户端，然后检查连接日志。

    连接日志将显示 OpenVPN 客户端首先连接到 HTTP 代理主机，然后发送`HTTP 'CONNECT'`请求以连接到 OpenVPN 服务器：

    ![如何操作...](img/image00442.jpeg)

    HTTP 代理主机响应 HTTP 代码`200`，表示`OK`，之后建立 VPN 连接。

## 它是如何工作的...

HTTP 代理主机充当（OpenVPN）客户端和服务器之间的中介。HTTP 代理可以在大多数网页浏览器中配置，通常用于通过酒店或公司防火墙获取访问权限。客户端首先连接到 HTTP 代理主机，然后使用`HTTP 'CONNECT'`请求向实际终端发起新连接。如果 HTTP 代理主机允许`CONNECT`请求，则返回 HTTP 代码`200`，并授权连接到 OpenVPN 服务器。从此以后，OpenVPN 连接的设置方式与常规的基于 TCP 的设置相似。

## 还有更多内容...

当使用 HTTP 代理主机连接到 OpenVPN 服务器时，有几个需要注意的事项。

### http-proxy 选项

OpenVPN 提供了一些选项来配置 OpenVPN 如何与 HTTP 代理主机连接：

+   `http-proxy-timeout`（`n`）：此选项将连接到 HTTP 代理主机的超时时间设置为（`n`）秒。默认值为 5 秒。

+   `http-proxy-option AGENT`（`string`）：在连接到 HTTP 代理主机时，将 HTTP 代理设置为（`string`）。一些代理仅允许来自“知名”网页浏览器的连接。

+   `http-proxy-option VERSION 1.1`：此选项将 HTTP 协议版本设置为 1.1。默认值为 HTTP/1.0。当 OpenVPN 2.1 连接到 HTTP 代理主机时，并未完全支持 HTTP/1.1，这导致一些代理拒绝访问。在 OpenVPN 2.2 中已修复此问题。

### 躲避防火墙

请注意，OpenVPN 不会尝试隐藏自己以躲避防火墙。现代防火墙进行所谓的深度包检查时，能够轻松检测到 OpenVPN 用于连接到 OpenVPN 服务器的流量类型，并可以基于此阻止访问。

### 性能

类似于 SOCKS 代理，HTTP 代理主机通常会对 VPN 设置的性能产生影响。使用代理主机时，带宽和延迟通常会受到影响。这主要是由于需要连接到一个单独的主机。

### 使用 OpenVPN GUI

在 Windows 中，你还可以使用 OpenVPN GUI 应用程序来设置 HTTP 代理服务器：

![使用 OpenVPN GUI](img/image00443.jpeg)

## 另请参见

+   本章的前后示例分别介绍了通过**SOCKS 代理**主机连接以及通过带身份验证的 HTTP 代理连接。

# 通过带身份验证的 HTTP 代理连接

在前面的食谱中，使用了一个普通的 HTTP 代理来连接 OpenVPN 服务器。作为后续步骤，在本食谱中我们将展示当 HTTP 代理服务器需要身份验证时，如何设置 OpenVPN 连接。

本食谱中使用的 HTTP 代理是一个基于 Linux 的 Apache `httpd` 服务器，已加载并配置了支持基本身份验证的 `mod_proxy` 模块。

## 准备就绪

我们将使用以下网络布局：

![准备就绪](img/image00444.jpeg)

使用 第二章 的第一个食谱来设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。对于这个食谱，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.12，客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。保留来自 第八章，*性能优化*，中 *优化基于 TCP 的连接* 食谱中的配置文件 `example8-9-server.conf`，以及来自 第二章，*客户端-服务器仅 IP 网络* 中 *服务器端路由* 食谱中的客户端配置文件 `basic-tcp-client.conf`。

## 如何操作...

1.  启动服务器：

    ```
    [root@server]# openvpn --config example8-9-server.conf

    ```

1.  设置 HTTP 代理服务器以支持基本身份验证。对于本食谱中使用的 Apache `httpd` 服务器，使用了以下 `proxy.conf` 文件：

    ```
            LoadModule proxy_module modules/mod_proxy.so 
            LoadModule proxy_balancer_module modules/mod_proxy_balancer.so 
            LoadModule proxy_ftp_module modules/mod_proxy_ftp.so 
            LoadModule proxy_http_module modules/mod_proxy_http.so 
            LoadModule proxy_connect_module modules/mod_proxy_connect.so 

            ProxyRequests On 
            ProxyVia On 
            AllowCONNECT 1194 
            KeepAlive on 

            <Proxy *> 
                Order deny,allow 
                Deny from all 
                Require user cookbook 
                AuthType Basic 
                AuthName "Password Required" 
                AuthUserFile /etc/httpd/conf/proxy-password 
            </Proxy> 

    ```

1.  使用 Apache 的 `htpasswd` 命令创建 `proxy-password` 文件：

    ```
     [root@proxyhost]# cd /etc/httpd/conf
    [root@proxyhost]# htpasswd -c proxy-password cookbook

    ```

1.  在客户端配置文件 `basic-tcp-client.conf` 中添加以下行：

    ```
            verb 5 
            http-proxy proxy.example.com 80 /etc/openvpn/cookbook/proxypass 

    ```

1.  将配置文件保存为 `example10-7-client.conf`。

1.  创建一个包含步骤 3 中创建的用户名和密码的纯文本文件；例如，使用以下方法：

    ```
    [client]# echo -e "cookbook\ncookbook" > proxy-password

    ```

1.  启动客户端并等待连接建立：

    ```
    [client]# openvpn --config example10-7-client.conf

    ```

1.  接下来，我们更仔细地查看客户端日志文件。如果输入正确的用户名和密码，HTTP 代理将允许连接 OpenVPN 服务器并建立 VPN 连接：

    ```
    Attempting to establish TCP connection with     
            [AF_INET]proxy.example.com:80 [nonblock]
    TCP connection established with [AF_INET]proxy.example.com:80
    Send to HTTP proxy: 'CONNECT openvpnserver.example.com:1194   
            HTTP/1.0'
    Attempting Basic Proxy-Authorization
    HTTP proxy returned: 'HTTP/1.0 200 Connection Established'
    TCPv4_CLIENT link local: [undef]
    TCPv4_CLIENT link remote: [AF_INET]proxy.example.com:80
    TLS: Initial packet from [AF_INET]proxy.example.com:80,      
            sid=3593eadc c87fb5d4
    VERIFY OK: depth=1, C=US, O=Cookbook 2.4, CN=Cookbook 2.4 CA, 
            emailAddress=openvpn@example.com
    Validating certificate key usage
    ++ Certificate has key usage  00a0, expects 00a0
    VERIFY KU OK
    Validating certificate extended key usage
    ++ Certificate has EKU (str) TLS Web Server Authentication, 
            expects TLS Web Server Authentication
    VERIFY EKU OK
    VERIFY OK: depth=0, C=US, O=Cookbook 2.4, CN=openvpnserver
    Data Channel Encrypt: Cipher 'BF-CBC' initialized with 128 bit 
            key

    ```

    从连接日志可以看出，OpenVPN 客户端在连接到 HTTP 代理服务器时尝试进行基本代理授权。如果身份验证成功，HTTP 代理则允许客户端访问并连接到服务器。

## 它是如何工作的...

与前面的食谱类似，OpenVPN 客户端首先连接到 HTTP 代理主机。它尝试使用基本身份验证通过代理密码文件 `/etc/openvpn/cookbook/proxypass` 中提供的用户名和密码进行身份验证。验证成功后，客户端随后发送 `HTTP 'CONNECT'` 请求以连接到 OpenVPN 服务器。从这里开始，OpenVPN 连接的设置与常规的基于 TCP 的设置类似。

## 还有更多...

OpenVPN 支持在连接 HTTP 代理时使用多种身份验证机制。

### NTLM 代理授权

OpenVPN 还支持使用 NTLM 代理授权的 HTTP 代理，其中**NTLM**代表**NT Lan Manager**。通常，这种类型的代理在 Microsoft Windows 环境中使用。不幸的是，OpenVPN 对 NTLM 授权的实现相当有限。它没有发送正确的 NTLMSSP 消息，并且仅适用于非常有限的代理集。为了启用对这种类型代理的支持，可以添加 `http-proxy proxyhost proxyport stdin ntlm` 或 `http-proxy proxyhost proxyport stdin ntlm2`，其中 `stdin` 指示 OpenVPN 在命令提示符下查询用户名和密码。

### 身份验证方法

OpenVPN 还支持 HTTP `digest` 身份验证，这比本方法中描述的明文身份验证更安全。您还可以在 `http-proxy` 身份验证指令中使用选项 `auto-nct` 来拒绝弱代理身份验证方法。

### OpenVPN GUI 限制

当前的 OpenVPN GUI 不允许您在 GUI 中指定用户名或密码。此功能在早期版本的 Windows OpenVPN GUI 应用程序中受支持。由于此功能使用不广泛，因此在重写 GUI 时被移除。

## 另见

+   本章前面的方法，通过不需要额外身份验证的 HTTP 代理建立连接

# 无 IP 设置 - ifconfig-noexec

本方法的目标是创建一个 OpenVPN 隧道，而不为隧道的端点分配 IP 地址。在路由网络设置中，这确保隧道端点无法通过自身访问，从而增强了一定的安全性，并且可以使路由表稍微简短一些。在 OpenVPN 配置文件中，需要指定 IP 地址，但永远不会将其分配给隧道接口。

此方法仅在 Linux 系统上进行过测试，因为它需要一些在其他平台上不可用的网络接口配置。

## 准备工作

我们将使用以下网络布局：

![准备工作](img/image00445.jpeg)

确保客户端和服务器不在同一局域网内。如果客户端和服务器可以直接相互通信，则此方法将失败。使用 第二章 中的第一个方法设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。在此方法中，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.12，客户端运行 Fedora 22 Linux 和 OpenVPN 2.3.11。保持 `example3-1-server.conf` 配置文件，来自 第三章，*客户端-服务器以太网风格网络* 的 *简单配置 - 非桥接* 方法。

## 如何操作...

1.  通过向 `example3-1-server.conf` 文件添加一行来创建服务器配置文件：

    ```
    route 192.168.4.0 255.255.255.0 192.168.99.1

    ```

1.  将其保存为 `example10-8-server.conf`。

1.  启动服务器：

    ```
    [root@server]# openvpn --config example10-8-server.conf

    ```

1.  创建客户端配置文件：

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

            script-security 2 
            ifconfig-noexec 
            up /etc/openvpn/cookbook/example10-8-up.sh 

            route-noexec 
            route-up /etc/openvpn/cookbook/example10-8-route-up.sh 

    ```

1.  将其保存为 `example-10-8-client.conf`。

1.  接下来，创建 `example10-8-up.sh` 脚本：

    ```
            #!/bin/bash 

            /sbin/ifconfig $1 0.0.0.0 up 
            # needed for TAP interfaces !!! 
            echo 1 > /proc/sys/net/ipv4/conf/$1/proxy_arp 

    ```

1.  将其保存为`/etc/openvpn/cookbook/example10-8-up.sh`。

1.  同样，创建`example10-8-route-up.sh`脚本：

    ```
            #!/bin/bash 

            # add an explicit route back to the VPN endpoint 
            /sbin/ip route add $route_vpn_gateway/32 dev $dev 

            n=1; 
            while [ $n -le 100 ] 
            do 
              network=`env | sed -n \  
                 "/^"route_network_${n}=/s/^route_network_${n}=//p"`" 
              netmask=`env | sed -n \ 
                 "/^"route_netmask_${n}=/s/^route_netmask_${n}=//p"`" 

              if [ -z "$"network" -o -z "$"netmask" ] 
              then 
                break 
              fi 

              /sbin/ip route add $network/$netmask dev $dev 
              let n=n+1 
            done 

    ```

1.  将其保存为`/etc/openvpn/cookbook/example10-8-route-up.sh`。

1.  确保两个脚本都具有可执行权限，并且它们都启动客户端：

    ```
    [[root@client]# chmod 755 /etc/openvpn/cookbook/example10-8*.sh
    [root@client]# openvpn --config example10-8-client.conf

    ```

1.  客户端成功连接到 OpenVPN 服务器后，检查`tap0`接口和路由表，验证是否可以 ping 通服务器：

    ```
    [root@client]# ip addr show tap0
    13: tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc  
            pfifo_fast state UNKNOWN group default qlen 100
     link/ether b6:b3:0e:41:d5:4d brd ff:ff:ff:ff:ff:ff
     inet6 fe80::b4b3:eff:fe41:d54d/64 scope link 
     valid_lft forever preferred_lft forever
    [root@client]# netstat-rn
    Kernel IP routing table
    Destination Gateway  Genmask       Flags[...]  Iface
    192.168.4.0 0.0.0.0  255.255.255.0 U   0 0 0 eth0
    10.198.0.0  0.0.0.0  255.255.0.0   U   0 0 0 tap0
    [...]
    [root@client]# ping -c 2 192.168.99.1
    PING 192.168.99.1 (192.168.99.1) 56(84) bytes of data.
    64 bytes from 192.168.99.1: icmp_seq=1 ttl=64 time=25.7 ms
    64 bytes from 192.168.99.1: icmp_seq=2 ttl=64 time=26.2 ms

    ```

## 它的工作原理...

OpenVPN 服务器为客户端分配了一个 IP 地址，但这并不意味着客户端接口实际需要分配这些地址。`example10-8-up.sh`脚本正是实现这一功能。

一些较旧的 Linux 内核拒绝在没有为接口分配地址的情况下添加路由。因此，我们将地址`0.0.0.0`分配给`tun0`接口。为了添加由服务器推送的路由，使用了一个特殊的`route-up`脚本，`example10-8-route-up.sh`，该脚本会启用所有路由。

## 还有更多...

在考虑无 IP 设置时，请注意以下几点。

### 点对点和 TUN 风格的网络

这个方法也可以在点对点风格的环境中使用，在这种环境下使用静态密钥连接两个网络。同样，它也可以在 TUN 风格的设置中使用。

### 路由和防火墙设置

起初，这个方法可能看起来有些奇怪。这种设置的好处是，OpenVPN 客户端本身无法被 VPN 中的其他机器访问。这在将多个客户端连接到 OpenVPN 服务器时非常有用，但有些客户端作为网关连接到它们后面的网络（例如，用于将远程办公室连接到 OpenVPN 服务器）。通过不为远程办公室网关分配 IP 地址，就没有风险让网关本身从远程 VPN 一侧受到攻击。此外，在这种情况下，服务器端的防火墙和`iptables`规则可以稍微简短一些，因为来自 OpenVPN 客户端的流量不会带有 VPN 源地址。这也是为什么服务器配置中明确包含了到客户端网络的路由的原因：

```
route 192.168.4.0 255.255.255.0 192.168.99.1 

```

这也解释了为什么当 VPN 客户端和服务器位于同一个局域网时，这个方法会失败。如果 VPN 客户端能够直接联系 VPN 服务器，那么 VPN 服务器将无法判断哪些流量需要进入隧道，哪些流量需要直接发送到客户端。

# 与 HTTPS 服务器的端口共享

一种常见的 OpenVPN 设置方式是让 OpenVPN 监听安全的 Web 服务器（HTTPS）端口`443`，以便让远程用户访问公司内部网络。缺点是，你将无法在 OpenVPN 服务器上使用该端口来托管安全的网站。OpenVPN 2.1 引入了一个新的`port-sharing`指令，使得 TCP 端口可以实现双重使用。所有被识别为 OpenVPN 流量的请求将由 OpenVPN 服务器自身处理，而所有其他流量将被转发到另一台（本地）机器和/或端口。

在本教程中，我们将设置一个 OpenVPN 服务器，将 TCP 端口 `443` 与 web 服务器共享，并展示 OpenVPN 和 web 浏览器都能成功连接到该服务器。

## 准备开始

我们将使用以下网络布局：

![准备开始](img/image00446.jpeg)

使用 第二章 中的第一个教程设置客户端和服务器证书，*客户端-服务器 IP 专用网络*。在本教程中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.12，客户端运行的是 Windows 7 64 位和 OpenVPN 2.3.10。请保留来自 第八章，*性能调优* 中的服务器配置文件 `example8-9-server.conf`，以及来自相同教程的客户端配置文件 `example8-9.ovpn`。

在服务器计算机上，一个安全的 web 服务器正在 `8443` 端口运行。

## 如何操作...

1.  通过修改 `example8-9-server.conf` 文件来创建服务器配置文件。修改以下行：

    ```
    port 1194

    ```

    将其更改为以下内容：

    ```
    port 443
    port-share localhost 8443

    ```

    将其保存为 `example10-9-server.conf`。

1.  启动服务器：

    ```
    [root@server]# openvpn --config example10-9-server.conf

    ```

1.  接下来，修改客户端配置文件 `example8-9.ovpn`，同样将端口更改为 `443`。将客户端配置文件保存为 `example10-9.ovpn`。

1.  启动客户端并验证客户端是否能连接到 VPN 服务器。

1.  客户端连接后，启动 web 浏览器并浏览到：

    ```
            https://openvpnserver.example.com 

    ```

    OpenVPN 服务器日志文件将显示如下类似的行：

    ```
            ... Re-using SSL/TLS context 
            ... TCP connection established with <client-ip>:53356 
            ... TCPv4_SERVER link local: [undef] 
            ... TCPv4_SERVER link remote: <client-ip>:53356 
            ... <client-ip>:53356 Non-OpenVPN client protocol detected 

    ```

## 它是如何工作的...

当使用 `port-share` 时，OpenVPN 会检查 `443` 端口上的传入流量。如果该流量是 OpenVPN 会话的一部分或是 OpenVPN 的初始握手，则 OpenVPN 服务器会自行处理。如果无法识别为 OpenVPN 流量，则会被转发到 `port-share` 指令中指定的主机和端口。

因此，始终监听 `443` 端口的始终是 OpenVPN 服务器进程。web 服务器必须监听不同的主机、接口或端口。通过这种设置，可以使用相同的端口提供两种不同的服务。

## 还有更多内容...

OpenVPN 转发其流量的 web 服务器必须是一个安全的（HTTPS）web 服务器。这是因为 OpenVPN 服务器本身的入站 SSL 流量的性质。无法将流量转发到常规的（HTTP）web 服务器。如果流量被转发到 `80` 端口，使用本教程中的 Apache web 服务器时，web 服务器的错误日志文件中将出现以下错误：

```
[error] [client 127.0.0.1] Invalid method in request \x16\x03\x01 

```

### 替代方案

有许多可用的替代方案可以实现相同的功能。一个示例工具是基于 Linux 的 `sslh` 工具，它可以区分 OpenVPN、SSL（HTTPS）和 SSH 流量。

# 路由功能 - redirect-private, allow-pull-fqdn

多年来，OpenVPN 的路由功能不断扩展。最显著的变化是，`redirect-gateway` 指令有了许多选项，以及一些其他较不为人知的路由指令：

+   `redirect-private`：此选项的行为与 `redirect-gateway` 指令非常相似，特别是在使用新参数时，但它不会更改默认网关。

+   `allow-pull-fqdn`：此选项允许客户端从 OpenVPN 服务器拉取 DNS 名称。之前只能推送或拉取 IP 地址。此选项不能被推送，需要添加到客户端配置文件中。

+   `route-nopull`：所有选项都会从服务器拉取到客户端，除了路由选项。当排查 OpenVPN 配置问题时，这个选项尤其有用。

+   `max-routes n`：定义可从远程服务器定义或拉取的最大路由数。

在本示例中，我们将重点关注 `redirect-private` 指令及其参数，以及 `allow-pull-fqdn` 参数。

## 准备就绪

我们将使用以下网络布局：

![准备就绪](img/image00447.jpeg)

使用第二章中第一个示例配置客户端和服务器证书，*客户端-服务器 IP 仅网络*。对于此示例，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.12，客户端运行 Windows 7 64 位和 OpenVPN 2.3.11。保留来自*服务器端路由*示例的配置文件 `basic-udp-server.conf`，该示例来自第二章，*客户端-服务器 IP 仅网络*，以及来自第二章中*使用 ifconfig-pool 块*示例的客户端配置文件 `basic-udp-client.ovpn`，*客户端-服务器 IP 仅网络*。

## 如何操作...

1.  将以下行添加到 `basic-udp-server.conf` 文件中：

    ```
            push "redirect-private bypass-dhcp bypass-dns" 
            push "route server.example.com" 

    ```

1.  将其保存为`example10-10-server.conf`。

1.  启动服务器：

    ```
    [root@server]# openvpn --config example10-10-server.conf

    ```

1.  将以下行添加到客户端配置文件 `basic-udp-client.ovpn` 中，并将其保存为 `example10-10.ovpn`：

    ```
            allow-pull-fqdn 

    ```

1.  启动客户端：![如何操作...](img/image00448.jpeg)

1.  在建立连接后查看路由表。

    如果 DHCP 或 DNS 服务器与客户端位于不同的子网中，则会添加新的路由。这是为了确保 DHCP 请求仍然发送到本地 DHCP 服务器，而不是通过 VPN 隧道发送。

    将为主机 `server.example.com` 添加一个路由。

## 它是如何工作的...

`bypass-dhcp` 和 `bypass-dns` 指令的选项会导致 OpenVPN 客户端在 DHCP 和 DNS 服务器位于不同网络时，额外添加一条路由。如果 DNS 服务器不在客户端连接的本地子网中，尤其是在大型网络中，这会非常有用。如果连接后改变到该 DNS 服务器的路由，使其通过 VPN 隧道，则至少会导致严重的性能损失。更有可能的是，整个 DNS 服务器将变得无法访问。

`allow-pull-fqdn` 指令允许在指定路由时使用 DNS 名称而不是 IP 地址。特别是在需要为具有动态 IP 地址的主机专门设置路由时，这非常有用。

请注意，`allow-pull-fqdn` 指令不能从服务器推送。

## 还有更多...

除了本节解释的指令，还有更多的路由指令可用于控制是否以及如何将路由添加到客户端。

### route-nopull 指令

`route-nopull` 指令使客户端从服务器拉取所有信息，但不拉取路由信息。这在调试服务器配置错误时非常有用。这并不意味着 OpenVPN 客户端完全不添加任何路由。只有使用 `push "route"` 指定的路由会被忽略。从 OpenVPN 2.4 开始，还可以过滤掉从服务器推送到客户端的选项。下一节将详细介绍这个内容。

### max-routes 指令

`max-routes` 指令在 OpenVPN 2.1 中引入，因为与 OpenVPN 2.0 相比，2.1 版本允许管理员推送更多的路由。为了防止客户端因路由过多而过载，增加了 `max-routes n` 选项，其中 `n` 是客户端配置文件中可以定义的最大路由数，或者从服务器拉取的最大路由数。

这个参数的默认值是 `100`。

## 参见

+   本章的下一节将讨论如何在应用之前过滤从服务器推送到客户端的选项。

# 过滤掉推送的选项

从 OpenVPN 2.4 开始，现在可以过滤从 OpenVPN 服务器推送到客户端的选项。这使得用户能够更加控制从服务器推送的网络路由和地址。

本节将展示 OpenVPN 新功能是如何工作的。

## 准备就绪

我们将使用以下网络布局：

![准备就绪](img/image00449.jpeg)

使用第二章中的第一个配方设置客户端和服务器证书，*客户端-服务器 IP-only 网络*。对于此配方，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.12，客户端运行的是 Windows 7 64 位和 OpenVPN 2.4_alpha2。对于服务器，保留配置文件`example9-2-server.conf`，该文件来自*Linux - 使用 pull-resolv-conf*配方，位于第九章，*操作系统集成*，并保持在手边。对于客户端，保留配置文件`basic-udp-client.ovpn`，该文件来自第二章中的*使用 ifconfig-pool 块*配方，*客户端-服务器 IP-only 网络*。

## 如何操作...

1.  启动服务器：

    ```
    [root@server]# openvpn --config example9-2-server.conf

    ```

1.  将以下行附加到客户端配置文件`basic-udp-client.ovpn`中，并将其保存为`example10-11.ovpn`：

    ```
            pull-filter ignore "dhcp-option DNS" 

    ```

1.  启动客户端：![如何操作...](img/image00450.jpeg)

1.  通过在 OpenVPN GUI 中选择`查看日志`，查看客户端日志文件。日志文件将包含类似以下内容的行：

    ```
            PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS
            192.168.3.1,route-gateway 10.200.0.1,topology subnet,ping 
            10,ping-restart 60,ifconfig 10.200.0.2 255.255.255.0' 
            Pushed option removed by filter: 'dhcp-option DNS 192.168.3.1' 

    ```

1.  使用`ipconfig /all`等工具验证客户端的 DNS 设置未被更改。

## 工作原理...

`pull-filter`指令接受多个参数：

+   `accept t`：接受来自服务器的推送选项`t`

+   `ignore t`：忽略来自服务器的推送选项`t`，但不终止连接

+   `reject t`：拒绝来自服务器的推送选项`t`并终止 VPN 连接

每个选项可以多次指定，最后一次出现的选项会覆盖之前的行。

通过在客户端配置文件中添加`pull-filter ignore "dhcp-option DNS"`行，我们可以忽略任何以`dhcp-option DNS`开头的推送行。因此，VPN 服务器不会接受任何 DNS 设置。此选项可以应用于所有从服务器推送的选项。

# 分配公共 IP

使用 OpenVPN 提供的`topology subnet`功能，可以将公共 IP 地址分配给连接的客户端。对于此配方，我们将展示如何实现这样的设置。我们将重用来自第二章中的*Proxy-ARP*配方，*客户端-服务器 IP-only 网络*中的技术，使 VPN 客户端看起来就像是远程网络的一部分。如果 VPN 客户端有专用的 IP 地址块，则不需要此步骤。使用`proxy-arp`方法的优势在于，它允许我们只使用昂贵的公共 IP 地址块的一部分。

## 准备工作

对于此配方，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.12，客户端计算机运行的是 Windows 7 64 位和 OpenVPN 2.3.11。保留客户端配置文件`basic-udp-client.ovpn`，该文件来自第二章中的*使用 ifconfig-pool 块*配方，*客户端-服务器 IP-only 网络*。

为了测试此配方，使用了一个 16 个地址的公共 IP 地址块，但在这里，我们将列出一个私有地址块（`10.0.0.0/255.255.255.240`）。该地址块的使用如下：

+   `10.0.0.18`：这是服务器的 VPN IP 地址

+   `10.0.0.19`：不可用

+   `10.0.0.20` - `10.0.0.25`：可供 VPN 客户端使用

+   `10.0.0.26`：不可用

+   `10.0.0.27`：OpenVPN 服务器本身的局域网地址

+   `10.0.0.28` - `10.0.0.29`：不可用

+   `10.0.0.30`：远程 LAN 上的路由器

## 如何操作...

1.  创建服务器配置文件：

    ```
            mode server 
            tls-server 
            proto udp 
            port 1194 
            dev tun 

            ifconfig 10.0.0.18 255.255.255.240 
            ifconfig-pool 10.0.0.20 10.0.0.25 
            push "route 10.0.0.27 255.255.255.255 net_gateway" 
            push "route-gateway 10.0.0.30" 
            push "redirect-gateway def1" 

            tls-auth /etc/openvpn/cookbook/ta.key 0 
            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/server.crt 
            key      /etc/openvpn/cookbook/server.key 
            dh       /etc/openvpn/cookbook/dh2048.pem 

            persist-key 
            persist-tun 
            keepalive 10 60 

            topology subnet 
            push "topology subnet" 

            script-security 2 
            client-connect    /etc/openvpn/cookbook/proxyarp-connect.sh 
            client-disconnect /etc/openvpn/cookbook/proxyarp-disconnect.sh 

            #user  nobody 
            #group nobody 

            daemon 
            log-append /var/log/openvpn.log 

    ```

    请注意，此服务器配置不能以用户`nobody`身份运行。将配置文件保存为`example10-12-server.conf`。

1.  接下来，创建`proxyarp-connect.sh`脚本：

    ```
            #!/bin/bash 
            /sbin/arp -i eth0  -Ds $ifconfig_pool_remote_ip eth0 pub 
            /sbin/ip route add ${ifconfig_pool_remote_ip}/32 dev tun0 

    ```

1.  将其保存为`/etc/openvpn/cookbook/proxyarp-connect.sh`。

1.  同样，创建`proxyarp-disconnect.sh`脚本：

    ```
            #!/bin/bash 
            /sbin/arp -i eth0  -d $ifconfig_pool_remote_ip 
            /sbin/ip route del ${ifconfig_pool_remote_ip}/32 dev tun0 

    ```

1.  将其保存为`/etc/openvpn/cookbook/proxyarp-disconnect.sh`。

1.  确保两个脚本都是可执行的，然后启动服务器：

    ```
    [root@server]# cd /etc/openvpn/cookbook
    [root@server]# chmod 755 proxy-connect.sh proxy-disconnect.sh
    [root@server]# openvpn --config example10-12-server.conf

    ```

1.  接下来，启动客户端。分配给客户端的 IP 地址应为`10.0.0.20`。

1.  使用客户端浏览互联网，并通过访问例如[`www.whatismyip.com`](http://www.whatismyip.com)来检查其 IP 地址。

## 工作原理...

关于服务器配置文件的一些说明，指令：

```
ifconfig 10.0.0.18 255.255.255.240 
ifconfig-pool 10.0.0.20 10.0.0.25 

```

为客户端设置一个（公共）IP 地址池供其使用。由于并非所有这些地址都可以在`/28`块中使用，我们不能简单地使用：

```
server 10.0.0.18 255.255.255.240 

```

下一个语句是确保 VPN 服务器本身是通过常规网络而不是通过 VPN 隧道本身访问的：

```
push "route 10.0.0.27 255.255.255.255 net_gateway" 

```

为了通过 VPN 隧道重定向所有流量，我们需要明确声明新的默认网关和`redirect-gateway`：

```
push "route-gateway 10.0.0.30" 
push "redirect-gateway def1" 

```

通常，以下语句还会将拓扑设置推送到 VPN 客户端：

```
topology subnet 

```

但是，由于我们没有使用`server`指令，因此这一过程不会自动发生。通过明确推送拓扑，我们确保客户端也使用正确的设置。

`client-connect`和`client-disconnect`脚本与第二章中的*Proxy-ARP*配方非常相似，*客户端-服务器 IP 仅网络*。通过使用 Linux `arp`命令的一个便捷功能，我们可以让远程客户端看起来像是本地网络的一部分。

## 还有更多...

`topology subnet`功能是在 OpenVPN 2.1 中引入的，对于使此配方实用至关重要。没有这个功能，每个客户端将被分配一个微型`/30`网络，这意味着每个客户端将使用最多四个公共 IP 地址。这使得将公共 IP 地址分配给 VPN 客户端的部署成本非常高。

## 另请参见

+   来自第二章的*Proxy-ARP*配方，*客户端-服务器 IP 仅网络*，它更详细地解释了 Linux/UNIX Proxy-ARP 功能的工作原理

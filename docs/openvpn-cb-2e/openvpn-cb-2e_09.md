# 第九章：操作系统集成

在本章中，我们将介绍以下教程：

+   Linux — 使用`NetworkManager`

+   Linux — 使用`pull-resolv-conf`

+   Windows — 提升权限

+   Windows — 使用 CryptoAPI 存储

+   Windows — 更新 DNS 缓存

+   Windows — 将 OpenVPN 作为服务运行

+   Windows — 公共与私有网络适配器

+   Windows — 路由方法

+   Windows 8+ — 确保 DNS 查询是安全的

+   Android — 使用 OpenVPN for Android 客户端

+   Push-peer-info — 向 Android 客户端推送选项

# 介绍

在本章中，我们将重点介绍如何在 Linux、Windows 和 Android 上使用 OpenVPN。对于每个操作系统，都可以单独写一章，详细描述在客户端和服务器模式下运行 OpenVPN 的细节，但由于篇幅有限，我们将只关注 OpenVPN 客户端与操作系统的交互。本章中的教程旨在概述在特定平台上运行 OpenVPN 时常见的陷阱。教程主要集中在 OpenVPN 本身的配置，而非如何将一个工作中的 VPN 设置集成到其余的网络基础设施中。

# Linux — 使用 NetworkManager

当 Linux 作为桌面操作系统使用时，网络配置大多数情况下是通过 Linux 的 NetworkManager 进行配置的。这个软件包允许非管理员用户启动和停止网络连接，连接和断开无线网络，并且设置多种类型的 VPN 连接，包括 OpenVPN。在这个教程中，我们将展示如何使用 GNOME 版本的 NetworkManager 配置 OpenVPN 连接。

## 准备工作

使用第二章中的第一个教程设置客户端和服务器证书，*客户端-服务器 IP-only 网络*。在这个教程中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端计算机运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。此版本的 Linux 自带 NetworkManager 1.0.8，并包括`NetworkManager-openvpn`插件。`NetworkManager-openvpn`插件默认没有安装，需要手动添加到系统中。保持第二章中的*服务器端路由*教程中的配置文件`basic-udp-server.conf`，以便随时使用。

## 操作方法...

1.  通过右键点击任务栏中的 NetworkManager 图标并选择**编辑连接**，启动 NetworkManager 配置界面。会弹出一个窗口。

1.  选择**VPN**选项卡来设置一个新的 VPN 连接：![操作方法...](img/image00406.jpeg)

1.  点击**添加**按钮以进入下一个界面：![操作方法...](img/image00407.jpeg)

1.  选择**OpenVPN**作为 VPN 类型，然后点击**创建...**按钮。如果**OpenVPN**连接类型不可用，说明`NetworkManager-openvpn`插件没有安装。

1.  填写下一个窗口的**VPN**选项卡中的详细信息：![如何操作...](img/image00408.jpeg)

    **网关**是 OpenVPN 服务器的主机名或 IP 地址。身份验证的**类型**是**证书（TLS）**。然后，对于**用户证书**、**CA 证书**和**私钥**字段，分别浏览到包含 `client1.crt`、`ca.crt` 和 `client1.key` 文件的目录。如果需要，填写**私钥密码**字段。此时不要点击**保存**按钮，而是点击**高级...**。

1.  在下一个窗口中，转到**安全**选项卡：![如何操作...](img/image00409.jpeg)

1.  选择要用于连接的加密密码和 HMAC 身份验证协议，然后点击**确定**。

1.  然后，转到**TLS 身份验证**选项卡。![如何操作...](img/image00410.jpeg)

1.  启用**验证对等方（服务器）证书使用签名**，然后选择**使用额外的 TLS 身份验证**，并浏览到 `ta.key` 文件的位置。选择**1**作为密钥方向。

1.  完成后，点击**确定**，然后点击**应用**以保存新的 VPN 连接。

1.  接下来，启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  最后，在客户端，通过点击 NetworkManager 图标，选择**VPN 连接**并选择**示例 9-1**来启动 VPN 连接：![如何操作...](img/image00411.jpeg)

你可以通过 ping VPN 服务器 IP 来验证 VPN 连接是否正确建立。

## 工作原理...

`NetworkManager-openvpn` 插件是一个用于设置 OpenVPN 客户端配置文件的图形用户界面。所有设置相当于按照第二章中的*服务器端路由*方法配置客户端配置文件，*客户端-服务器 IP 专用网络*。

## 还有更多...

`NetworkManager-openvpn` 插件支持一些高级配置设置：

### 使用 NetworkManager 设置路由

`NetworkManager-openvpn` 插件也可以用来设置特定于 VPN 的路由。再次打开主 VPN 配置屏幕，进入**IPv4 设置**选项卡。点击此屏幕上的**路由...**按钮：

![使用 NetworkManager 设置路由](img/image00412.jpeg)

将会弹出一个新窗口：

![使用 NetworkManager 设置路由](img/image00413.jpeg)

通过**忽略自动获取的路由**选项，可以覆盖服务器推送的路由。默认情况下，`NetworkManager-openvpn` 插件会启用 `redirect-gateway`，即使服务器未推送该设置。通过勾选**仅将此连接用于其网络上的资源**复选框，可以覆盖这一行为。

### DNS 设置

如果 OpenVPN 服务器通过以下指令推送 DNS 服务器，`NetworkManager-openvpn` 插件还会更新`/etc/resolv.conf` 文件：

```
push "dhcp-option DNS a.b.c.d" 

```

### 脚本

请注意，NetworkManager 不允许在客户端使用脚本或插件，因为由非 root 用户配置时会带来安全风险。

# Linux - 使用 pull-resolv-conf

在 Linux 上设置 VPN 连接时，一个常见的陷阱是 OpenVPN 服务器推送新的 DNS 设置。在之前的例子中，我们看到 `NetworkManager-openvpn` 插件也会更新包含 DNS 设置的系统配置文件`/etc/resolv.conf`。如果使用命令行，这一过程不会自动进行。默认情况下，OpenVPN 配带了两个脚本，用于将 DNS 服务器添加到或从`/etc/resolv.conf`文件中移除。这个教程将展示如何使用这些脚本。

## 准备就绪

我们将使用以下网络布局：

![准备就绪](img/image00414.jpeg)

使用第二章中的第一个教程设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。对于这个例子，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.11。请保存`basic-udp-server.conf`配置文件，这来自第二章中的*服务器端路由*教程，以及`basic-udp-client.conf`客户端配置文件。

## 如何操作...

1.  将以下行附加到`basic-udp-server.conf`文件中：

    ```
            push "dhcp-option DNS 10.198.0.1" 

    ```

    这里，`10.198.0.1`是 VPN 服务器局域网中 DNS 服务器的地址。将其保存为`example9-2-server.conf`。

1.  启动服务器：

    ```
    [root@server]# openvpn --config example9-2-server.conf

    ```

1.  同样，对于客户端，向`basic-udp-client.conf`文件中添加以下行：

    ```
            script-security 2 
            up   "/etc/openvpn/cookbook/client.up" 
            down "/etc/openvpn/cookbook/client.down" 

    ```

1.  将其保存为`example9-2-client.conf`。从 OpenVPN `contrib` 目录中复制`client.up`和`client.down`文件，并使其可执行。在 CentOS 6 和 Fedora 22 中，这些文件位于`/usr/share/doc/openvpn-2.3.11/contrib/pull-resolv-conf`目录：

    ```
    [root@client]# cd /etc/openvpn/cookbook
    [root@client]# cp /usr/share/doc/openvpn-2.3.11/contrib/pull-
            resolv-conf/client.* .
    [root@client]# chmod 755 client.*

    ```

1.  最后，启动客户端：

    ```
    [root@client]# openvpn --config example9-2-client.conf

    ```

VPN 连接建立后，检查`/etc/resolv.conf`文件的内容。第一行应包含 OpenVPN 服务器指定的 DNS 服务器：

```
nameserver 10.198.0.1 

```

当 VPN 连接结束时，该条目会被移除。

## 它是如何工作的...

OpenVPN 提供的脚本解析环境变量`foreign_option_*`，并查找 DOMAIN 和 DNS 设置。这些设置随后会被写入`/etc/resolv.conf`文件的开头。这使得 OpenVPN 服务器推送的 DNS 服务器和 DOMAIN 设置优先于系统的 DNS 和 DOMAIN 设置。

当 VPN 连接断开时，相同的设置会从`/etc/resolv.conf`文件中删除。

## 还有更多...

请注意，当使用`NetworkManager-openvpn`插件时，这些脚本不是必需的，因为 NetworkManager 会自行更新`/etc/resolv.conf`文件。

# Windows - 提升权限

随着 Windows Vista 的推出，微软引入了**用户帐户控制**（**UAC**）。UAC 旨在保护用户免受可能修改操作系统本身的程序的危害。在运行此类程序之前，即使用户具有完全的管理员权限，也需要提升权限。会出现一个对话框，用户必须点击它才能开始执行。为了运行 OpenVPN，需要提升的权限，因为 OpenVPN 需要打开系统设备并启动 VPN 连接。尤其是在需要向系统中添加路由时，提升的权限至关重要。

在 OpenVPN 2.3+版本中，权限提升功能已内置于 OpenVPN GUI 应用程序中。也就是说，即使**以管理员身份运行**标志被关闭，启动 OpenVPN GUI 时，应用程序仍会请求提升的权限。本教程将演示这一行为，而这种行为在旧版本的 OpenVPN 中并不存在。

## 准备工作

使用第二章中的第一个教程设置客户端和服务器证书，*客户端-服务器 IP 专用网络*。在本教程中，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端计算机运行 Windows 7 SP1 和 OpenVPN 2.3.11。保留来自第二章中*服务器端路由*教程中的配置文件`basic-udp-server.conf`。对于客户端，保留来自第二章中*使用 ifconfig-pool 块*教程中的配置文件`basic-udp-client.ovpn`。

## 如何操作…

1.  首先，启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  确保 OpenVPN 没有运行，并且托盘图标不存在。

1.  在启动 OpenVPN GUI 之前，右键点击安装 OpenVPN 2.3.11 Windows 版后放置在桌面上的 OpenVPN GUI 图标。

1.  在弹出的**属性**窗口中，点击**兼容性**选项卡并禁用**以管理员身份运行此程序**：![如何操作…](img/image00415.jpeg)

1.  点击**确定**。

1.  启动 OpenVPN GUI。请注意，它仍然会提示权限（以下截图是 Windows Vista 的界面，但 Windows 7+会弹出类似的窗口）：![如何操作…](img/image00416.jpeg)

1.  点击**继续**以按常规启动 OpenVPN GUI。

1.  通过启动`example5-1`配置文件启动 OpenVPN 客户端：![如何操作…](img/image00417.jpeg)

1.  验证 VPN 连接是否已建立，并且日志文件`c:\temp\openvpn.log`是否已创建。

## 它是如何工作的…

启动 OpenVPN GUI 应用程序时，用户必须始终确认它可以以提升的权限运行。这已内置在 OpenVPN GUI 应用程序中，可以通过注意应用程序图标右下角的盾牌来看到这一点。

![工作原理...](img/image00418.jpeg)

此后，OpenVPN GUI 可以启动其他可执行文件，这些文件也会继承这些权限。当 GUI 启动`openvpn.exe`进程时，它可以打开 VPN 适配器，修改路由表，并运行 up 和 down 脚本。

# Windows - 使用 CryptoAPI 存储

OpenVPN 具有使用 Windows CryptoAPI 存储来检索设置连接所需的公钥和私钥的功能。这在一定程度上提高了安全性，因为 CryptoAPI 存储比通常用于设置 OpenVPN 连接的明文`.crt`和`.key`文件更为安全。

在这个配方中，我们将配置一个 OpenVPN 客户端，在连接到服务器时从 CryptoAPI 存储中检索所需的信息。这个配方在 Windows 7 上进行了测试，但也适用于其他版本的 Windows。

## 准备就绪

使用第二章中的第一个配方设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。对于这个配方，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，而客户端计算机运行的是 Windows 7 SP1 和 OpenVPN 2.3.11。保留第二章中*服务器端路由*配方中的配置文件`basic-udp-server.conf`以备使用。

## 如何操作...

1.  首先，我们需要将客户端证书导入到 CryptoAPI 存储中。为此，我们必须将现有的`client2.crt`和`client2.key`文件转换为 PKCS12 格式。打开 Windows 命令行窗口并切换到这些文件所在的目录：

    ```
    [winclient]C:> cd C:\Program Files\OpenVPN\config
    [winclient]C:\Program Files\OpenVPN\config>..\bin\openssl 
            pkcs12
     -export -in client2.crt -inkey client2.key -out client2.p12
    Enter pass phrase for client2.key: [existing password]
    Enter Export Password: [new export password]
    Verifying - Enter Export Password: [repeat export password]

    ```

1.  接下来，将 PKCS12 文件导入 Windows CryptoAPI 存储：

    ```
    [winclient]C:\Program Files\OpenVPN\config>start client2.p12

    ```

    证书导入向导将启动。

1.  在第一个屏幕上点击**下一步**，然后在第二个屏幕上再次点击**下一步**。接下来，您需要提供上一步中的导出密码：![如何操作...](img/image00419.jpeg)

    如果您选择了**启用强私钥保护。启用此选项后，每次应用程序使用私钥时都需要提示您输入密码**复选框，证书和私钥将得到更好的保护，但每次 OpenVPN 启动时，您都需要重新输入密码。

1.  单击**下一步**。在下一个屏幕中，选择默认选项**自动选择证书存储**，然后再次单击**下一步**。在下一个屏幕中点击**完成**，证书导入完成。![如何操作...](img/image00420.jpeg)

1.  创建客户端配置文件：

    ```
            client 
            proto udp 
            remote openvpnserver.example.com 
            port 1194 

            dev tun 
            nobind 

            remote-cert-tls server 
            tls-auth "c:/program files/openvpn/config/ta.key" 1 
            ca          "c:/program files/openvpn/config/ca.crt" 
            cryptoapicert  "SUBJ:Client2" 

    ```

1.  将配置文件保存为`example9-4.ovpn`。启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  使用 OpenVPN GUI 启动 VPN 连接。

VPN 连接应当能够建立，而无需询问私钥密码。如果启用了 CryptoAPI 选项，**启用强私钥保护**，将弹出一个单独的对话框，要求输入 CryptoAPI 密码。

## 工作原理...

Windows OpenVPN 客户端软件能够从 Windows CryptoAPI 存储中提取证书和公钥，如果指定了证书的主题名称（使用关键字`SUBJ:`）或者指定了证书的指纹（使用关键字`THUMB:`）。在从 CryptoAPI 存储中检索到证书和私钥后，VPN 连接的建立方式与使用明文证书和私钥文件时完全相同。

## 还有更多...

使用 Windows CryptoAPI 存储时有几个小而重要的细节，我们将在接下来的章节中详细讲解。

### CA 证书文件

请注意，仍然需要使用以下行来指定 CA 证书：

```
ca c:/program files/openvpn/config/ca.crt 

```

理论上，也可以从 CryptoAPI 存储中检索 CA 证书，但 OpenVPN 目前没有实现此功能。还需要注意，CA 证书文件需要包含用于签署服务器端证书的证书颁发机构，而不是客户端证书。

### 证书指纹

除了提供 `cryptoapicert SUBJ:<subject name>`，还可以指定 `cryptoapicert THUMB:<fingerprint>`。

X509 证书的指纹或指纹打印可以通过在 Windows 证书存储中查找导入证书的 `Thumb` 属性，或者通过输入 OpenSSL 命令来检索：

```
C:\Program Files\OpenVPN\config>..\bin\openssl x509 \
 -fingerprint -noout -in client2.crt
SHA1 Fingerprint=91:93:72:7D:0D:D7:33:58:81:DA:DE:2C:17:1E:36:43:58:40:BF:50

```

# Windows - 更新 DNS 缓存

在 OpenVPN 用户邮件列表中，经常出现一个问题，关于在 VPN 连接建立后 Windows 的 DNS 名称解析。如果 OpenVPN 服务器推送了新的 DNS 服务器，那么 OpenVPN 客户端会自动获取该 DNS 服务器，但名称解析在建立连接后并不总是正常工作。这与 OpenVPN 关系不大，更多与 Windows DNS 缓存服务的工作方式有关。由于这个问题经常出现，因此 OpenVPN 2.1.3 版本中增加了一个新的指令 `register-dns`。当指定此指令时，OpenVPN 会更新 Windows DNS 缓存，并将 VPN IP 地址注册到 Windows DNS 表中。由于此功能最近才引入，本篇文章也将展示如何在 VPN 连接建立时使用脚本更新 Windows DNS 缓存。有些用户会完全禁用 DNS 缓存服务，这似乎对操作系统影响不大，除了在使用慢速网络时会有一些小的性能损失。

## 准备工作

使用 第二章 中的第一个教程设置客户端和服务器证书，*客户端-服务器仅限 IP 网络*。在本教程中，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端计算机运行 Windows 7 SP1 和 OpenVPN 2.3.11。请保留来自 *Linux: 使用 pull-resolv-conf* 教程中的服务器配置文件 `example9-2-server.conf`，以及来自 *使用 ifconfig-pool 块* 教程中的客户端配置文件 `basic-udp-client.ovpn`，这些都可以在 第二章 中找到，*客户端-服务器仅限 IP 网络*。

## 如何操作...

1.  启动服务器：

    ```
    [root@server]# openvpn --config example9-2-server.conf

    ```

1.  在 `basic-udp-client.ovpn` 配置文件中添加一行：

    ```
            register-dns 

    ```

1.  将此配置文件保存为 `example9-5.ovpn`。启动 OpenVPN 客户端。

    OpenVPN GUI 状态窗口将显示 Windows 服务 `dnscache` 已重新启动：

    ![如何操作...](img/image00421.jpeg)

    VPN 连接建立后，验证名称解析是否使用 VPN 提供的 DNS 服务器，例如通过使用 `nslookup` 命令。

## 工作原理...

当 VPN 连接建立时，OpenVPN 客户端软件将一个 DHCP 数据包发送到 TAP-Win32 适配器，包含 IP 地址、默认网关以及其他网络相关信息，例如新的 DNS 服务器。操作系统会接收这些信息，但本地 DNS 缓存服务不会立即得到通知。`register-dns` 指令会执行以下命令：

```
net stop dnscache
net start dnscache
ipconfig /flushdns
ipconfig /registerdns

```

通过强制重启 DNS 缓存服务，VPN 连接提供的 DNS 服务器会立即生效。

## 另见

+   本章稍后的 *Windows 8+ - 确保 DNS 查找安全* 教程，详细介绍了如何确保 DNS 查找仅通过 VPN 隧道传输

# Windows - 以服务方式运行 OpenVPN

OpenVPN Windows 版本的一个较少为人知的功能是它能够作为服务运行。这允许 OpenVPN 在没有用户登录系统的情况下启动并建立 VPN 连接。OpenVPN 服务默认安装，但不会自动启动。

在这个教程中，我们将展示如何通过 OpenVPN GUI 应用程序控制 OpenVPN 服务，并如何进行服务故障排除。

## 准备工作

使用第二章中的第一个方法设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。在这个方法中，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端计算机运行 Windows 7 SP1 和 OpenVPN 2.3.11。保留*服务器端路由*方法中的配置文件`basic-udp-server.conf`，该方法位于第二章，*客户端-服务器仅 IP 网络*。对于客户端，保留*使用 ifconfig-pool 块*方法中的配置文件`basic-udp-client.ovpn`，该方法也位于第二章，*客户端-服务器仅 IP 网络*。

## 操作方法...

1.  启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  在启动客户端的 OpenVPN GUI 应用程序之前，我们首先启动 Windows 注册表编辑器`regedit`（使用提升权限）。找到`HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN-GUI`键。![操作方法...](img/image00422.jpeg)

1.  记下`config_dir`注册表项，通常设置为`C:\Program Files\OpenVPN\config`。

1.  将注册表项**allow_service**设置为**1**。同时，注意注册表项`log_dir`，通常设置为`C:\Program Files\OpenVPN\log`。

1.  现在，浏览到注册表项`HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN`，并再次检查`config_dir`和`log_dir`键。它们应该指向与 OpenVPN GUI 应用程序相同的目录。

1.  关闭注册表编辑器。

1.  启动 OpenVPN GUI。右键单击任务栏中的图标。一个新的菜单选项将会出现。![操作方法...](img/image00423.jpeg)

    但不要立即启动服务。

1.  首先，修改客户端配置文件`basic-udp-client.ovpn`，更改以下行：

    ```
            cert     "c:/program files/openvpn/config/client2.crt" 
            key      "c:/program files/openvpn/config/client2.key" 

    ```

    将这些更改为以下内容：

    ```
            cert     "c:/program files/openvpn/config/client1.crt" 
            key      "c:/program files/openvpn/config/client1.key" 

    ```

    来自第二章，*客户端-服务器仅 IP 网络*的`client2.key`客户端证书有密码保护，而`client1.key`文件没有。将配置文件保存为`example9-6.ovpn`。

1.  将所有其他`.ovpn`文件移到另一个目录，确保`config`目录中只有此`.ovpn`文件。

1.  现在，启动 OpenVPN 服务。过一段时间后，VPN 连接将会建立，客户端和服务器的日志文件中都可以看到。

## 它是如何工作的...

一个 Windows 服务在系统启动时启动，用户登录之前。OpenVPN 服务扫描注册表项`HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\config_dir`所指向的目录。

这会为该目录中每个`.ovpn`扩展名的文件启动一个 OpenVPN 进程。每个进程的输出都会记录到注册表项指向的日志目录：

```
HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\log_dir 

```

在这里，日志文件名与配置文件名相同，只是扩展名变成了`.log`。在本例中，配置文件为`C:\Program Files\OpenVPN\config\example9-6.ovpn`，日志文件为`C:\Program Files\OpenVPN\log\example9-6.log`。

启动这些连接不需要启动 OpenVPN GUI，但如果添加了正确的注册表项，GUI 应用程序确实提供了管理 OpenVPN 服务的便捷方法。

## 还有更多...

使用 OpenVPN 服务时有一些重要注意事项，这里列出了相关内容。

### 自动服务启动

要使 OpenVPN 服务在系统启动时自动启动，请通过以下路径打开**服务**管理控制面板：**控制面板** | **管理工具** | **服务**。双击**OpenVPN 服务**以打开属性，并将**启动类型**字段设置为**自动**：

![自动服务启动](img/image00424.jpeg)

点击**确定**并关闭**服务**管理控制面板。重新启动 Windows，并在服务器端验证客户端是否在系统启动时连接。

### OpenVPN 用户名

当使用 OpenVPN 服务时，相应的 OpenVPN 进程通常会以**SYSTEM**账户身份运行，正如以下截图所示：

![OpenVPN 用户名](img/image00425.jpeg)

这与配置文件的权限相关。使用`cryptoapicert`指令时也需要特别小心，因为默认情况下，这些证书会被存储在用户证书存储区，而该存储区对**SYSTEM**账户不可访问。可以使用`cryptoapicert`指令，但导入的证书必须作为（本地）系统证书安装，而不是用户证书。

## 另见

+   本章前面提到的*Windows - 使用 CryptoAPI 存储*的技巧，解释了如何使用 Windows CryptoAPI 存储来存储用户证书和私钥

# Windows - 公共网络与私有网络适配器

在 Windows Vista 和 7 中，微软引入了网络类别的概念。网络接口可以是**私有**网络或**公共**网络的一部分。在使用 OpenVPN 时，必须小心适配器所处的网络类型。默认情况下，OpenVPN 的 TAP-Win32 适配器被放置在**公共**网络中，这有一个副作用，即无法挂载文件共享。在本例中，我们将展示如何更改网络类型，以便可以在 VPN 连接上使用文件共享等受信服务。虽然这与配置 OpenVPN 本身关系不大，但这个问题经常出现，值得专门列出一个技巧。

## 准备工作

使用第二章中的第一个食谱来设置客户端和服务器证书，*客户端-服务器 IP 仅网络*。在此食谱中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端计算机运行的是 Windows 7 SP1 和 OpenVPN 2.3.11。请将*服务器端路由*食谱中的`basic-udp-server.conf`配置文件保管好，该文件在第二章，*客户端-服务器 IP 仅网络*中。对于客户端，请将*使用 ifconfig-pool 块*食谱中的`basic-udp-client.ovpn`配置文件保管好，该文件也在第二章，*客户端-服务器 IP 仅网络*中。

## 如何操作...

1.  将以下行附加到`basic-udp-server.conf`文件中：

    ```
            push "route 0.0.0.0 0.0.0.0 vpn_gateway 300" 

    ```

1.  将其保存为`example9-7-server.conf`。启动服务器：

    ```
    [root@server]# openvpn --config example9-7-server.conf

    ```

1.  在 Windows 客户端上，启动 OpenVPN GUI。

1.  在建立 VPN 连接后，会弹出一个窗口询问您这是哪种类型的网络。对于 Windows 7，您可以选择**家庭**、**工作**或**公共**；对于 Windows 8 及以上版本，选择是**私人**或**公共**。

1.  选择**工作**网络，然后打开**网络和共享中心**：![如何操作...](img/image00426.jpeg)

## 它是如何工作的...

在 Windows 7 及以上版本中，每种网络类型有不同的访问权限。权限最少的网络类型是**公共**，这意味着应用程序可以建立 TCP/IP 连接，但不能访问**工作**或**私人**网络中的任何资源，如本地打印机和本地磁盘。当共享与 OpenVPN 客户端在同一网络上的资源时，这可能成为一个问题。

Windows 通过查看该网络是否具有默认网关来确定网络类型。如果没有指定默认网关，则该网络被视为不可信，因此它被设为公共网络。之后没有简单的选项可以更改此设置。

为了克服这一特殊性，我们为其提供了一个具有非常高度量值的默认网关：

```
push "route 0.0.0.0 0.0.0.0 vpn_gateway 300" 

```

使用非常高的度量值，我们避免了所有网络流量都通过 VPN 路由的问题，这可能导致*自咬其尾*问题。

## 另请参见

+   本章前面提到的*Windows - 提升权限*食谱，详细解释了如何以提升权限运行 OpenVPN GUI 应用程序。

# Windows - 路由方法

当路由被推送到 Windows 客户端时，有两种方法可以将这些路由添加到系统路由表中：

+   使用 IPAPI 助手函数（默认方法）

+   使用`ROUTE.EXE`程序

在大多数情况下，IPAPI 方法工作正常，但有时需要覆盖此行为。在本食谱中，我们将展示如何做到这一点，并如何查看客户端日志文件，以验证是否选择了正确的方法。

## 准备工作

使用第二章中的第一个食谱来设置客户端和服务器证书，*客户端-服务器 IP 仅网络*。在此食谱中，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端计算机运行 Windows 7 SP1 和 OpenVPN 2.3.11。请随时备好在第二章中的*服务器端路由*食谱中的配置文件`basic-udp-server.conf`。对于客户端，请随时备好在第二章中的*使用 ifconfig-pool 块*食谱中的配置文件`basic-udp-client.ovpn`。

## 如何操作...

1.  启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  将以下行添加到`basic-udp-client.ovpn`配置文件中：

    ```
            verb 5 
            route-method ipapi 

    ```

1.  将此配置文件保存为`example9-8.ovpn`。使用此配置启动 OpenVPN 客户端。

1.  在连接建立之后，再次打开**显示状态**窗口，并查看连接日志的最后几行。日志会显示类似如下的内容：

    ```
            ...  C:\WINDOWS\system32\route.exe ADD 10.198.0.0 MASK 
            255.255.0.0 10.200.0.1 
            ... Route addition via IPAPI succeeded 
            ... Initialization Sequence Completed 

    ```

    即使`route-method`指令设置为`ipapi`，日志文件仍然会打印出 Windows`route.exe`命令的路径。第二行显示路由实际上是通过 IPAPI 助手函数添加的。

1.  现在，修改配置文件`example9-8.ovpn`，内容如下：

    ```
            verb 5 
            route-method exe 

    ```

1.  重启 OpenVPN 客户端。

1.  再次查看连接日志的最后几行。这一次，日志文件中将不会出现**通过 IPAPI 添加路由成功**的信息，这意味着使用了`route.exe`命令。相反，您会看到类似以下内容：

    ```
            ...  C:\WINDOWS\system32\route.exe ADD 10.198.0.0 MASK 
            255.255.0.0 10.200.0.1 
            ... env_block: add PATH=C:\Windows\System32;C:\Windows;... 
            ... Initialization Sequence Completed 

    ```

    以`env_block`开头的这一行表示在启动外部`route.exe`命令之前，已经设置了一组环境变量。

## 它是如何工作的...

`route-method`指令有三个选项：

+   `adaptive`：首先尝试使用 IPAPI 方法，如果 IPAPI 失败，则回退到`route.exe`方法。这是默认选项。

+   `ipapi`：始终使用 IPAPI 助手函数来添加路由。

+   `exe`：始终使用外部程序`route.exe`。

根据该指令，OpenVPN 客户端将选择如何向 Windows 路由表添加路由。请注意，如果 OpenVPN 无法添加路由，它不会中止连接。当前的 OpenVPN GUI 无法检测到这一点，因此会在任务栏上显示一个绿色图标，表明连接完全成功。

## 还有更多内容...

OpenVPN 被预配置为在 Windows 安装目录中查找`route.exe`程序，通常是在`C:\WINDOWS\system32`。如果 Windows 安装在其他目录中，可以使用`win-sys`指令。`win-sys`指令有两个选项：

+   默认选项，`env`，表示 OpenVPN 客户端将使用环境变量`windir`的内容来定位 Windows 操作系统。此环境变量在正常的 Windows 设置中始终会被设置。从 OpenVPN 2.3 开始，这是默认设置，如果指定了`win-sys env`，则会打印警告信息。

+   Windows 操作系统所在的目录名，例如`D:\WINDOWS`。仅在`route.exe`程序位于非标准位置时使用此路径。

# Windows 8+ - 确保 DNS 查找是安全的

从 Windows 8.1 开始，微软引入了一个新特性，用于将主机名解析为 IP 地址。每当一个应用程序想要解析主机名时，都会通过系统中找到的所有网络适配器发送一个 DNS 查询。第一个响应查询的适配器返回的答案将被使用。

如果用户希望以安全的方式通过 VPN 隧道传输所有流量，那么此功能将不受欢迎。在敌对的网络环境中，可能会返回一个虚假的 IP 地址，甚至可能认为对特定主机进行 DNS 查找是危险的。

从 OpenVPN 2.3.10 开始，新增了一个选项，`block-outside-dns`，用于抑制此功能。在此配方中，我们将展示如何使用此选项。

## 准备工作

使用第二章中的第一个配方设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。对于此配方，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11，客户端计算机运行的是 Windows 8.1 和 OpenVPN 2.3.11。保留第二章中的*服务器端路由*配方中的配置文件`basic-udp-server.conf`，并随时可用。对于客户端，保留第二章中*使用 ifconfig-pool 块*配方中的配置文件`basic-udp-client.ovpn`。

## 如何操作...

1.  启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  将以下行添加到`basic-udp-client.ovpn`配置文件中：

    ```
            verb 5 
            block-outside-dns 

    ```

1.  将此配置文件保存为`example9-9.ovpn`。使用此配置启动 OpenVPN 客户端。

1.  连接建立后，再次打开**显示状态**窗口，查看连接日志的最后几行。输出应类似于以下内容：![如何操作...](img/image00427.jpeg)

    在此日志文件中，**Windows 过滤平台**（**WFP**）被初始化，并添加了特殊规则以阻止 DNS 流量。

1.  停止 OpenVPN 客户端并再次检查日志文件。您应该看到一行显示 WFP 引擎已关闭，从而移除 OpenVPN 添加的过滤规则：

    ```
            ... Closing TUN/TAP interface 
            ... Uninitializing WFP 

    ```

## 它是如何工作的...

使用 `block-outside-dns` 指令，在 VPN 连接建立后创建一组 Windows 过滤规则。这些过滤（或防火墙）规则阻止 DNS 查找通过 Windows 客户端上所有网络适配器发送，除了通过 TAP 适配器发出的查询。当 OpenVPN 连接终止时，WFP 规则将被删除。

## 还有更多...

在使用 OpenVPN 2.3 并同时开启多个隧道时，务必小心此选项。在某些情况下，第一个隧道添加的 WFP 规则在第二个隧道关闭时没有正确恢复，从而阻止所有 DNS 流量。

# Android - 使用 OpenVPN for Android 客户端

OpenVPN 也可以在移动设备上使用，如 Android 或 iPhone 智能手机。在本食谱中，我们将展示如何为 Android 应用设置 OpenVPN 的基本配置文件。相同的配置也可以用于 iPhone 和 iPad。

## 准备工作

使用 第二章 中的第一个食谱设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。在这个食谱中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.11。客户端设备运行的是 Android 4.2 和 OpenVPN for Android 版本 0.6.57。保留来自 第二章，*服务器端路由* 食谱中的配置文件 `basic-udp-server.conf`。对于客户端，保留来自 第二章，*使用 ifconfig-pool 块* 食谱中的配置文件 `basic-udp-client.ovpn`。

## 如何操作...

1.  启动服务器：

    ```
    [root@server]# openvpn --config basic-udp-server.conf

    ```

1.  通过将 `basic-udp-client.ovpn` 文件转换为内联配置文件来创建 OpenVPN 应用配置文件。此过程通过将所有引用外部文件的部分替换为内联块来完成。然后，我们通过复制外部文件的内容将这些内联块添加到配置文件中。最终的配置文件将类似于以下内容：

    ```
            client 
            proto udp 
            remote openvpnserver.example.com 
            port 1194 
            dev tun 
            nobind 
            remote-cert-tls server 
            key-direction 1 
            push-peer-info 

            <ca> 
            -----BEGIN CERTIFICATE----- 
            MIIGDzCCA/egAwIBAgIJAJOj7Wg... 
            ... 
            -----END CERTIFICATE----- 
            </ca> 

            <cert> 
            -----BEGIN CERTIFICATE----- 
            MIIFKzCCAxOgAwIBAgIBAjANBgi... 
            ... 
            -----END CERTIFICATE----- 
            </cert> 

            <key> 
            -----BEGIN RSA PRIVATE KEY----- 
            MIIEvgIBADANBgkqhkiG9w0BAQEF... 
            ... 
            -----END RSA PRIVATE KEY----- 
            </key> 

            <tls-auth> 
            -----BEGIN OpenVPN Static key V1----- 
            5f5b2bfff373961654089871b40a39eb 
            ... 
            -----END OpenVPN Static key V1----- 
            </tls-auth> 

    ```

1.  将此配置文件保存为 `example9-10.ovpn`。

1.  将应用配置文件传输到 Android 智能手机。

1.  启动 OpenVPN for Android 应用并导入 `example9-10.ovpn` 配置文件。如果一切顺利，你应该看到类似以下内容的输出：![如何操作...](img/image00428.jpeg)

1.  启动 OpenVPN 配置文件。在连接建立后，应用会显示当前状态和日志，顶部显示 **Connected: SUCCESS, 10.200.0.2, 192.168.96.101, 1194:** ![如何操作...](img/image00429.jpeg)

## 工作原理...

OpenVPN for Android 应用基于与开源 OpenVPN 软件相同的源代码。因此，几乎所有可以在常规配置文件中指定的选项也可以在 OpenVPN 应用配置文件中指定。然而，建议将所有证书和密钥信息包含在配置文件中，因为这样更便于将配置文件传输到设备。

## 还有更多内容...

如果你希望通过先将应用配置文件上传到 web 服务器的方式进行传输，那么请确保文件类型和扩展名保持不变。如果移动设备无法将其识别为 OpenVPN 配置文件，它将把配置文件视为普通文本文件，这样你将无法将其导入到 OpenVPN for Android 应用中。在这种情况下，建议将 `.ovpn` 文件放入 ZIP（`.zip`）文件中进行传输。

## 另见

+   下一章中的 *Inline certificates* 配方，详细介绍了如何使用内联证书

# Push-peer-info - 向 Android 客户端推送选项

这个配方是前一个配方的延续。在将移动客户端集成到现有的 OpenVPN 设置中时，通常需要将这些移动客户端与常规的 OpenVPN 客户端区分开来。在某些情况下，可能需要将所有移动客户端的流量通过 VPN 隧道进行重定向，或者需要使用不同的加密方案来优化 Android 设备上的 OpenVPN 应用程序。在这个配方中，我们将演示如何将选项推送到 Android 客户端，同时保持所有其他客户端的选项不变。

## 准备工作

使用第二章中的第一个配方设置客户端和服务器证书，*客户端-服务器 IP-only 网络*。对于这个配方，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.4。客户端设备运行 Android 4.2 和 OpenVPN for Android 版本 0.6.57。请保留来自第二章，*客户端-服务器 IP-only 网络* 配方中的配置文件 `basic-udp-server.conf`。对于客户端，保留来自前一个配方的配置文件 `example9-10.ovpn`。

## 如何操作...

1.  将以下行追加到 `basic-udp-server.conf` 服务器配置文件中：

    ```
            script-security 2 
            client-connect    /etc/openvpn/cookbook/example9-11.sh 

    ```

1.  将其保存为`example9-11-server.conf`。接下来，创建连接脚本：

    ```
            #!/bin/bash 

            # Redirect the default gateway for all Android clients 
            if [ "x_${IV_PLAT}" = "x_android" ] 
            then 
                echo "push "redirect-gateway def1"" >> $1 
            fi 

    ```

1.  将此文件保存为 `example9-11.sh`。确保该脚本是可执行的并启动服务器：

    ```
    [root@server]# chmod 755 example9-11.sh
    [root@server]# openvpn --config example9-11-server.conf

    ```

1.  启动 OpenVPN for Android 应用并建立 VPN 连接。

1.  在连接建立后，使用另一个应用程序（如 Fing）确保所有流量都通过 OpenVPN 隧道重定向：![如何操作...](img/image00430.jpeg)

1.  路由跟踪输出中的第一个地址是 `10.200.0.1`，这表明流量通过 OpenVPN 服务器进行了重定向。

## 工作原理...

在 OpenVPN for Android 配置中，我们添加了 `push-peer-info` 选项。这使得 OpenVPN 客户端可以将配置信息发送到服务器。从 OpenVPN 2.4 开始，这些配置信息可以在插件和脚本中使用。`client-connect` 脚本检查环境变量 `IV_PLAT`，并在 Android 客户端连接时推送 `redirect-gateway`。

## 还有更多...

`push-peer-info` 选项在所有 OpenVPN 2.3 客户端中都可用。然而，服务器端处理此信息的支持是在 2.4 版本中添加的。以下对等信息被发送到服务器：

+   `IV_COMP_STUB=1, IV_COMP_STUBv2=1`：这表示客户端支持压缩存根。这也意味着服务器可以将压缩选项推送给客户端。

+   `IV_GUI_VER=de.blinkt.openvpn_0.6.57`：这表示客户端的 GUI 版本。在这种情况下，使用的是 OpenVPN for Android 客户端版本 0.6.57。

+   `IV_HWADDR=00:00:00:00:00:00`：这表示客户端的以太网硬件地址。在 Android 客户端上，该选项始终为`00:00:00`，但在其他平台上，TUN/TAP 适配器的 MAC 地址会被传输。

+   `IV_LZ4=1, IV_LZ4v2=1, IV_LZO=1`：这表示客户端支持 LZ4、LZ4v2 和 LZO 压缩。

+   `IV_NCP=2`：这表示客户端支持加密密码协商。这允许客户端和服务器协商出最优的压缩和 HMAC 算法。

+   `IV_PLAT=android`：这表示客户端平台。

+   `IV_PROTO=2`：这表示推送对等信息格式的版本。未来，发送到服务器的格式或变量集可能会发生变化，这将需要版本号的增加。

+   `IV_RGI6=1`：这表示客户端支持重定向 IPv6 网关地址。

+   `IV_SSL=OpenSSL_1.0.2h__3_May_2016`：这表示 OpenVPN 客户端使用的 SSL 库及其版本。这对于确定某个客户端是否易受加密库漏洞的影响可能非常重要。

+   `IV_VER=2.4_master`：这表示客户端上 OpenVPN 软件的版本。

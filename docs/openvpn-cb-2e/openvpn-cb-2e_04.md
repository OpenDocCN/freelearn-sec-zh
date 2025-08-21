# 第四章：PKI、证书与 OpenSSL

本章内容包括：

+   证书生成

+   OpenSSL 技巧：x509、pkcs12、验证输出

+   撤销证书

+   使用 CRL（证书撤销列表）

+   检查过期/吊销的证书

+   中介 CA

+   多个 CA：堆叠，使用`capath`指令

+   确定使用的加密库

+   OpenSSL 和 PolarSSL 的加密功能

+   推送密码

+   椭圆曲线支持

# 介绍

本章内容是对公钥基础设施（PKI）、证书和`openssl`命令的简单介绍。本章的主要目的是展示如何生成、管理、查看 OpenVPN 中使用的证书，以及 OpenSSL 与 OpenVPN 之间的交互。

# 证书生成

本示例将演示如何使用普通的`openssl`命令创建并签署证书请求。这与使用`easy-rsa`脚本略有不同，但非常有指导意义。

## 准备工作

使用第二章中的第一个配方设置`easy-rsa`证书环境，方法是加载`vars`文件。这个示例在运行 Fedora 22 Linux 的计算机上执行，但也可以轻松在 Windows 或 MacOS 上运行。请注意，`easy-rsa`包可以独立于 OpenVPN 下载。

## 如何实现...

在我们使用普通的`openssl`命令生成和签署请求之前，需要设置一些环境变量。默认情况下，这些变量并未在`vars`文件中设置。

1.  添加缺失的环境变量：

    ```
     $ cd /etc/openvpn/cookbook
     $ . ./vars
     $ export KEY_CN=
     $ export KEY_OU=
     $ export KEY_NAME=
     $ export OPENSSL_CONF=/etc/openvpn/cookbook/openssl-
               1.0.0.cnf

    ```

    请注意，`openssl-1.0.0.cnf`文件是 easy-rsa 分发包的一部分，应该已经存在于`/etc/openvpn/cookbook`目录中。

1.  接下来，我们在不使用密码的情况下生成证书请求。通过将选项`-nodes`添加到`openssl req`命令来实现：

    ```
     $ openssl req -nodes -newkey rsa:2048 -new -out client.req \
     -subj "/C=NL/O=Cookbook/CN=MyClient"
     Generating a 2048 bit RSA private key
     .......................................++++++
     ............++++++
     writing new private key to 'privkey.pem'
     -----

    ```

1.  最后，我们使用证书颁发机构的私钥对证书请求进行签名：

    ```
     $ openssl ca -in client.req -out client.crt
     Using configuration from /etc/openvpn/cookbook/openssl.cnf
     Enter pass phrase for /etc/openvpn/cookbook/keys/ca.key:
     [enter CA key password]
     Check that the request matches the signature
     Signature ok
     The Subject's Distinguished Name is as follows
     countryName           :PRINTABLE:'NL'
     organizationName      :PRINTABLE:'Cookbook'
     commonName            :PRINTABLE:'MyClient'
     Certificate is to be certified until Apr 20 15:08:25 2026 GMT 
            (3650 days)
     Sign the certificate? [y/n]:y
     1 out of 1 certificate requests certified, commit? [y/n]y
     Write out database with 1 new entries
     Data Base Updated

    ```

## 它是如何工作的...

第一步始终是生成一个私钥。在这个示例中，我们生成一个没有密码的私钥，这样并不安全。证书请求使用私钥签名，以证明证书请求和私钥属于同一对。`openssl req`命令一次性生成私钥和证书请求。

第二步是使用**证书颁发机构**（**CA**）的私钥签署证书请求。这样就会生成一个 X.509 证书文件，可用于 OpenVPN。

一个（公有）X.509 证书的副本也存储在`/etc/openvpn/cookbook/keys`目录中。如果证书之后需要被撤销，这个副本非常重要，因此不要将其从该目录中删除。

## 还有更多...

也可以生成一个由密码保护的私钥（在 OpenSSL 中称为“密码短语”）。要生成这样的私钥，只需去掉`-nodes`命令行参数：

```
$ openssl req -newkey rsa:1024 -new -out client.req \
 -subj "/C=NL/O=Cookbook/CN=MyClient"

```

OpenSSL 命令现在将要求输入密码短语：

```
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:

```

## 另见

+   来自第二章的*设置公钥和私钥*配方，*客户端-服务器 IP 仅网络*，该配方解释了如何使用`easy-rsa`脚本进行 PKI 的初步设置

# OpenSSL 技巧 - x509，pkcs12，验证输出

OpenSSL 命令一开始可能看起来令人生畏，但 OpenSSL 工具箱中有很多有用的命令可以用来查看和管理 X.509 证书及私钥。这个配方将展示如何使用其中一些命令。

## 准备工作

使用来自第二章的第一个配方，通过源`vars`文件设置`easy-rsa`证书环境。此配方是在运行 Fedora 22 Linux 的计算机上执行的，但也可以在 Windows 或 MacOS 上轻松运行。

## 如何做...

对于这个配方，我们需要执行以下步骤：

1.  要查看给定证书的主题和过期日期，请输入：

    ```
    $ cd /etc/openvpn/cookbook/keys
    $ openssl x509 -subject -enddate -noout -in client1.crt
     subject= /C=US/O=Cookbook 2.4/CN=client1
    notAfter=Oct 13 17:54:30 2018 GMT

    ```

1.  导出证书和私钥为`PKCS12`格式：

    ```
    $ openssl pkcs12 -export -in client1.crt \
     -inkey client1.key -out client1.p12
     Enter Export Password:[Choose a strong password]
     Verifying - Enter Export Password:[Type the password again]
    $ chmod 600 client1.p12

    ```

    请注意，`chmod 600`确保 PKCS12 文件仅对用户可读。

1.  验证给定证书的用途：

    ```
    $ openssl verify -purpose sslclient -CAfile ca.crt client1.crt
     client1.crt: OK

    ```

1.  如果选择了错误的用途（`sslclient`与`sslserver`），请注意错误：

    ```
    $ openssl verify -purpose sslclient -CAfile ca.crt server.crt
     server.crt: C = US, O = Cookbook 2.4, CN = openvpnserver
     error 26 at 0 depth lookup:unsupported certificate purpose
     OK

    ```

1.  更改证书的密码（密码短语）：

    ```
    $ openssl rsa -in client2.key -aes256 -out newclient.key
     Enter pass phrase for client2.key:[old password]
     writing RSA key
     Enter PEM pass phrase:[new password]
     Verifying - Enter PEM pass phrase:[new password]

    ```

## 它是如何工作的...

OpenSSL 工具包包含广泛的命令，用于生成、操作和查看 X.509 证书及其相应的私钥。本章中的命令只是可用命令的一个小子集。在 Linux 和 UNIX 系统上，您可以使用`openssl -h`以及`x509`、`pkcs12`和`req`的手册页面来获取更多详细信息。手册页面也可以在线访问：[`www.openssl.org/docs/apps/openssl.html`](http://www.openssl.org/docs/apps/openssl.html)。

点击列表中所有命令下方的 OpenSSL 命令以直接指引。

# 撤销证书

在管理 PKI 时，一个常见的任务是撤销不再需要的或已被泄露的证书。这个配方演示了如何使用`easy-rsa`脚本撤销证书，以及如何配置 OpenVPN 以使用**证书撤销列表**（**CRL**）。

## 准备工作

使用来自第二章的第一个配方设置客户端和服务器证书。此配方是在运行 CentOS 6 Linux 的计算机上执行的，但也可以在 Windows 或 Mac OS 上轻松运行。

## 如何做...

1.  首先，我们生成一个证书：

    ```
    $ cd /etc/openvpn/cookbook
    $ . ./vars
    $ ./build-key client4
    [...]

    ```

1.  然后，我们立即撤销它：

    ```
    $ ./revoke-full client4
    Using configuration from /etc/openvpn/cookbook/openssl-
            1.0.0.cnf
    Enter pass phrase for /etc/openvpn/cookbook/keys/ca.key:
    Revoking Certificate 06.
    Data Base Updated
    Using configuration from /etc/openvpn/cookbook/openssl-
            1.0.0.cnf
    Enter pass phrase for /etc/openvpn/cookbook/keys/ca.key:
    client4.crt: C = US, O = Cookbook 2.4, CN = client4
    error 23 at 0 depth lookup:certificate revoked

    ```

1.  这也将更新 CRL 列表。可以使用以下命令查看 CRL：

    ```
    $ openssl crl -text -noout -in keys/crl.pem
    Certificate Revocation List (CRL):
     Version 1 (0x0)
     Signature Algorithm: sha256WithRSAEncryption
     Issuer: /C=US/O=Cookbook 2.4/CN=Cookbook 2.4
                    CA/emailAddress=openvpn@example.com
     Last Update: Apr 22 15:54:10 2016 GMT
     Next Update: May 22 15:54:10 2016 GMT
    Revoked Certificates:
     Serial Number: 06
     Revocation Date: Apr 22 15:54:08 2016 GMT
     Signature Algorithm: sha256WithRSAEncryption
     12:8a:f0:b4:3e:aa:5b:a1:13:64:41:c7:0b:46:ef:00:99:50:
     6b:72:b8:2e:ff:93:eb:9b:7e:63:9e:8d:78:63:e8:96:44:30:
     5b:eb:3d:4a:a4:2a:36:1e:8c:c6:cd:11:63:b1:d5:88:31:46:

    ```

## 它是如何工作的...

CRL 包含已被撤销的证书序列号列表。每个序列号只能由一个 CA 发放一次，因此该序列号对于这个特定的 CA 是唯一的。CRL 使用 CA 的私钥签名，确保 CRL 确实是由适当的方发布的。

## 还有更多...

“撤销证书到底需要什么？”这个问题经常被提到，因此接下来的部分会更深入地探讨这个问题。

### 撤销证书所需的内容

要撤销证书，需要提供证书主题（"DN"）和证书序列号。如果证书丢失，则无法撤销它。这表明进行适当的 PKI 管理非常重要，包括备份已发放给用户的证书。

## 另见

+   下一个配方，*CRL 的使用*

+   本章稍后的配方，*多个 CA：堆叠，使用-capath 指令*

# CRL 的使用

本配方展示了如何配置 OpenVPN 使用 CRL。它使用前一个配方中创建的 CRL。该配方是第二章中的*路由：伪装*配方的扩展，意思是服务器和客户端的配置文件几乎相同。

## 准备工作

使用第二章中的第一个配方，*客户端-服务器仅 IP 网络*，设置客户端和服务器证书。使用前一个配方生成 CRL。在此配方中，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.3.10，客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.3.10。保留第二章中的*服务器端路由*配方中的`basic-udp-server.conf`配置文件，*客户端-服务器仅 IP 网络*。

## 如何操作...

1.  将生成的 CRL 复制到更公开的目录：

    ```
    [root@server]# cd /etc/openvpn/cookbook
    [root@server]# cp keys/crl.pem .

    ```

1.  通过添加以下行修改服务器配置文件`basic-udp-server.conf`：

    ```
            crl-verify /etc/openvpn/cookbook/crl.pem 

    ```

    将其保存为`example4-6-server.conf`。

1.  启动服务器：

    ```
    [root@server]# openvpn --config example4-6-server.conf

    ```

1.  接下来，创建客户端配置文件：

    ```
    client
    proto udp
            remote openvpnserver.example.com
            port 1194
            dev tun
            nobind
            remote-cert-tls server
            tls-auth /etc/openvpn/cookbook/ta.key 1
            ca       /etc/openvpn/cookbook/ca.crt
            cert     /etc/openvpn/cookbook/client4.crt
            key      /etc/openvpn/cookbook/client4.key

    ```

    将其保存为`example4-6-client.conf`。

1.  最后，启动客户端：

    ```
    [root@client]# openvpn --config example4-6-client.conf

    ```

客户端无法连接，而是服务器日志文件中显示：

```
[...] TLS_ERROR: BIO read tls_read_plaintext error: error:140890B2:SSL
 routines:SSL3_GET_CLIENT_CERTIFICATE:no certificate returned
[...] TLS Error: TLS object -> incoming plaintext read error
[...] TLS Error: TLS handshake failed

```

这个相当晦涩的信息证明了客户端由于证书无效而无法连接。

## 它是如何工作的...

每次客户端连接到 OpenVPN 服务器时，都会检查 CRL 以查看客户端证书是否列出。如果列出，OpenVPN 服务器将拒绝接受客户端证书，连接将无法建立。

## 还有更多...

生成 CRL 是一回事，保持其最新是另一回事。确保 CRL 保持最新是非常重要的。为此，最好设置一个 cron 任务，在夜间更新服务器的 CRL 文件。OpenVPN 中有一个与 CRL 更新相关的已知 bug：每当客户端连接时，OpenVPN 服务器都会尝试访问 CRL 文件。如果文件不存在或不可访问，OpenVPN 服务器进程将因错误而中止。正确的行为应该是暂时拒绝客户端的访问，但不幸的是，情况并非如此。

## 另见

+   本章后续的示例，*多个 CA：堆叠，使用-capath 指令*，解释了 CA 和 CRL 的更高级用法。

# 检查过期/撤销的证书

本示例的目标是深入了解一些 OpenSSL CA 命令的内部实现。我们将展示如何将证书的状态从“有效”更改为“撤销”或“过期”。

## 准备工作

使用第二章中的第一个示例设置客户端和服务器证书，*客户端-服务器 IP-only 网络*。这个示例是在运行 CentOS 6 Linux 的计算机上执行的，但它也可以在 Windows 或 Mac OS 上轻松执行。

## 如何操作...

1.  在我们可以使用普通的`openssl`命令之前，需要设置几个环境变量。这些变量在`vars`文件中默认并未设置：

    ```
    $ cd /etc/openvpn/cookbook
    $ . ./vars
    $ export KEY_NAME=
    $ export OPENSSL_CONF=/etc/openvpn/cookbook/openssl-1.0.0.cnf

    ```

1.  现在，我们可以使用证书的序列号查询其状态：

    ```
            $ cd keys
            $ openssl x509 -serial -noout -in server.crt
            serial=01
            $ openssl ca -status 01
            Using configuration from /etc/openvpn/cookbook/openssl-
            1.0.0.cnf
            01=Valid (V)

    ```

    这表明我们的 OpenVPN 服务器证书仍然有效。

1.  我们在*撤销证书*示例中撤销的证书显示如下：

    ```
            $ openssl x509 -serial -noout -in client4.crt 
            serial=06
            $ openssl ca -status 06
            Using configuration from /etc/openvpn/cookbook/openssl-     
            1.0.0.cnf
            08=Revoked (R)

    ```

1.  如果我们查看`index.txt`文件，位于`/etc/openvpn/cookbook/keys`目录下，我们可以看到：

    ```
    V 181013174924Z            01  unknown  .../CN=openvpnserver
    R 190117155337Z 160422155408Z  06  unknown  .../CN=client4

    ```

1.  接下来，我们使用普通的文本编辑器修改此文件，将`R`替换为`E`，并将第三个字段`160422155408Z`用空格清空。该字段是证书撤销的时间戳。现在，第二行变成：

    ```
    E  190117155337Z                 08 unknown .../CN=client4

    ```

1.  现在，如果我们再次检查状态，我们会得到：

    ```
    $ openssl ca -status 06
    Using configuration from /etc/openvpn/cookbook/openssl-
            1.0.0.cnf
    08=Expired (E)

    ```

    如果我们再次生成 CRL，我们可以看到该证书已经被“撤销”：

    ```
              $ openssl ca -gencrl -out crl.pem
              $ openssl crl -text -noout -in crl.pem  | head -8
            Certificate Revocation List (CRL):
                    Version 1 (0x0)
                Signature Algorithm: sha256WithRSAEncryption
                    Issuer: /C=US/O=Cookbook 2.4/CN=Cookbook 2.4     
                    CA/emailAddress=openvpn@example.com
                    Last Update: Apr 26 15:02:01 2016 GMT
                    Next Update: May 26 15:02:01 2016 GMT
            No Revoked Certificates.
                Signature Algorithm: sha256WithRSAEncryption

    ```

## 它是如何工作的...

OpenSSL 的`ca`命令通过查看`index.txt`文件来生成 CRL。每一行以`R`开头的条目都会被添加到 CRL 中，之后，CRL 会使用 CA 私钥进行加密签名。

通过将撤销证书的状态更改为`E`甚至`V`，我们可以撤销撤销的证书。

## 还有更多内容...

在这个示例中，我们将一个证书的状态从`撤销`更改为`过期`。这将允许之前示例中的客户端再次连接到服务器，因为该证书仍然有效。从`index.txt`文件中将证书状态从`有效`更改为`过期`的主要原因，是为了允许我们使用完全相同的名称生成并发放新的证书。

# 中介 CA

本配方展示了如何设置中介 CA，并如何配置 OpenVPN 使用中介 CA。OpenVPN 的 `easy-rsa` 脚本也包括设置中介 CA 的功能。中介 CA（或子 CA）的优势在于，顶级 CA（也称为根 CA）可以更紧密地保护。中介 CA 可以分发给负责生成服务器和客户端证书的人员。

## 准备就绪

使用第二章中的第一个配方，设置客户端和服务器证书，*客户端-服务器仅 IP 网络*。该配方是在运行 CentOS 6 Linux 的计算机上执行的，但也可以在 Windows 或 Mac OS 上轻松执行。

## 如何操作...

1.  首先，我们创建中介 CA 证书：

    ```
    $ cd /etc/openvpn/cookbook/
            $ . ./vars
            $ ./build-inter IntermediateCA

    ```

1.  验证该证书是否可以确实作为证书颁发机构：

    ```
            $ openssl x509 -text -noout -in keys/IntermediateCA.crt \
              | grep -C 1 CA
                        X509v3 Basic Constraints:
                            CA:TRUE
                Signature Algorithm: sha1WithRSAEncryption

    ```

1.  接下来，我们为中介 CA 创建一个新的 `keys` 目录（当前目录仍然是 `/etc/openvpn/cookbook`）：

    ```
            $ mkdir -m 700 -p IntermediateCA/keys
            $ cp [a-z]* IntermediateCA
            $ cd IntermediateCA

    ```

1.  编辑新目录中的 `vars` 文件，并将 `EASY_RSA` 行更改为：

    ```
            export EASY_RSA=/etc/openvpn/cookbook/IntermediateCA 

    ```

1.  来源这个新的 `vars` 文件，并设置 `keys` 目录：

    ```
            $ . ./vars
            $ ./clean-all
            $ cp ../keys/IntermediateCA.crt keys/ca.crt
            $ cp ../keys/IntermediateCA.key keys/ca.key

    ```

1.  现在我们准备创建我们的第一个中介证书：

    ```
            $ ./build-key IntermediateClient

    ```

1.  验证证书是否以新的中介 CA 作为颁发者：

    ```
            $ openssl x509 -subject -issuer -noout -in  
            keys/IntermediateClient.crt
     subject= /C=US/O=Cookbook 2.4/CN=IntermediateClient
               issuer= /C=US/O=Cookbook 2.4/CN=subCA/emailAddress=...

    ```

1.  最后，我们验证证书是否确实是有效的证书。为了做到这一点，我们需要将根 CA（公钥）证书和中介 CA 证书堆叠成一个文件：

    ```
            $ cd /etc/openvpn/cookbook
            $ cat keys/ca.crt IntermediateCA/keys/ca.crt > ca+subca.pem
            $ cp IntermediateCA/keys/IntermediateClient.{crt,key} .
            $ openssl verify -CAfile ca+subca.pem IntermediateClient.crt
            IntermediateClient.crt: OK

    ```

## 它是如何工作的...

中介 CA 证书具有作为证书颁发机构（CA）的“权利”，这意味着它可以自行签发新证书。中介 CA 需要一个目录结构，这个结构与根 CA 的目录结构非常相似。首先，我们设置这个目录结构，然后将所有必要的文件复制过来。之后，我们创建一个客户端证书，并验证它是有效的证书。为了进行此验证，从根级 CA 到中介 CA 到客户端证书的整个证书链都需要存在。这就是为什么根 CA 公钥证书和中介 CA 公钥证书会堆叠到一个文件中的原因。这个单一文件随后用于执行整个证书链验证。

## 还有更多内容...

已由中介 CA 签发的证书也需要由同一 CA 撤销。这意味着，使用多个 CA 时，您还需要使用多个 CRL。幸运的是，CRL 可以像 CA 证书一样堆叠：将文件连接在一起，使用 `cat` 命令，如下一个配方中所述。

# 多个 CA - 堆叠，使用 capath 指令

这个方案的目标是创建一个 OpenVPN 设置，其中客户端证书由“仅客户端”CA 签发，服务器证书由不同的“仅服务器”CA 签发。这提供了额外的操作安全性，其中一个人只被允许创建客户端证书，而另一个人只被允许生成服务器证书。这确保了客户端和服务器证书永远不能混合，从而避免中间人攻击。

## 准备工作

使用第二章中的第一个方案设置服务器证书，*客户端-服务器 IP-only 网络*。使用之前方案中的客户端证书和中介 CA 证书。对于此方案，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.3.10，而客户端运行 Fedora 22 Linux 和 OpenVPN 2.3.10。

## 如何操作...

1.  创建服务器配置文件：

    ```
            tls-server 
            proto udp 
            port 1194 
            dev tun 

            server 192.168.200.0 255.255.255.0 

            ca       /etc/openvpn/cookbook/ca+subca.pem 
            cert     /etc/openvpn/cookbook/server.crt 
            key      /etc/openvpn/cookbook/server.key 
            dh       /etc/openvpn/cookbook/dh1024.pem 
            tls-auth /etc/openvpn/cookbook/ta.key 0 

            persist-key 
            persist-tun 
            keepalive 10 60 

            user  nobody 
            group nobody 

            daemon 
            log-append /var/log/openvpn.log 

    ```

    将其保存为`example4-9-server.conf`。

1.  启动服务器：

    ```
            [root@server]# openvpn --config example4-9-server.conf

    ```

1.  接下来，创建客户端配置文件：

    ```
            client 
            proto udp 
            remote openvpnserver.example.com 
            port 1194 

            dev tun 
            nobind 

            tls-auth /etc/openvpn/cookbook/ta.key 1 
            ca       /etc/openvpn/cookbook/ca.crt 
            cert     /etc/openvpn/cookbook/IntermediateClient.crt 
            key      /etc/openvpn/cookbook/IntermediateClient.key 

    ```

    将其保存为`example4-9-client.conf`。注意，我们没有在客户端配置中指定`ca+subca.pem`文件。

1.  启动客户端：

    ```
            [root@client]# openvpn --config example4-9-client.conf

    ```

1.  在服务器日志文件中，你现在可以看到客户端使用由中介 CA 创建的证书连接：

    ```
            ... openvpnclient:49283 [IntermediateClient] Peer Connection  
            Initiated with openvpnclient:49283 

    ```

## 它是如何工作的...

当客户端连接到服务器时，客户端（公钥）证书会发送给服务器进行验证。服务器需要访问完整的证书链才能进行验证；因此，我们将根 CA 证书和中介 CA（或子 CA）证书堆叠在一起。这使得客户端能够连接到服务器。

相反，当客户端连接时，服务器（公钥）证书也会发送给客户端。由于服务器证书最初是由根 CA 签名的，我们在此不需要指定完整的证书堆栈。

请注意，如果我们忘记在 OpenVPN 服务器配置文件中指定`ca+subca.pem`文件，我们将收到错误信息：

```
openvpnclient:49286 VERIFY ERROR: depth=0, error=unable to get local issuer certificate: C=US, O=Cookbook 2.4, CN=IntermediateClient 

```

## 还有更多...

除了堆叠 CA 证书外，还可以堆叠 CRL 或使用完全不同的机制来支持多个 CA 证书及其对应的 CRL。

### 使用-capath 指令

另一种在 OpenVPN 服务器配置中包含多个 CA 和 CRL 的方法是使用以下指令：

```
capath /etc/openvpn/cookbook/ca-dir 

```

这个目录需要包含所有 CA 证书和 CRL，采用特殊的命名规则：

+   所有 CA 证书的名称必须等于 CA 证书的哈希值，并且必须以`.0`结尾。

+   所有 CRL 的名称必须等于 CA 证书的哈希值，并且必须以`.r0`结尾。

对于我们的根 CA 和中介 CA，我们可以使用以下命令来实现：

```
$ cd /etc/openvpn/cookbook
$ mkdir ca-dir
$ openssl x509 -hash -noout -in keys/ca.crt
bcd54da9

```

这个十六进制数字`bcd54da9`是根 CA 证书的哈希值：

```
$ cp keys/ca.crt  ca-dir/bcd54da9.0
$ cp keys/crl.pem ca-dir/bcd54da9.r0

```

类似地，对于中介 CA 证书：

```
$ openssl x509 -hash -noout -in IntermediateCA/keys/ca.crt
1f5e4734
$ cp IntermediateCA/keys/ca.crt  ca-dir/1f5e4734.0
$ cp IntermediateCA/keys/crl.pem ca-dir/1f5e4734.r0 

```

使用多个不同的 CA 证书和相应的 CRL，这种方法比“堆叠”文件管理起来要简单得多。

# 确定将使用的加密库

从 OpenVPN 2.3 开始，可以使用 OpenSSL 加密库或 PolarSSL 库来构建 OpenVPN。PolarSSL 库现已更名为 "mbedTLS"。PolarSSL 库在 OpenVPN Connect 应用程序中用于 Android 和 iOS 平台，但该库也可以在所有其他支持的平台上使用。

本配方的目标是展示如何确定使用的加密库，包括运行时的版本号。

## 正在准备中

使用来自第二章的第一个配方设置服务器证书，*客户端-服务器仅 IP 网络*。使用前一个配方中的客户端证书和中介 CA 证书。对于本配方，计算机运行的是 Fedora 22 Linux 和 OpenVPN 2.3.10，分别为 OpenSSL 和 PolarSSL 构建。保持来自第二章的 *服务器端路由* 配方中的 `basic-udp-server.conf` 配置文件。

## 如何操作...

1.  使用标准配置文件启动常规版本的 OpenVPN：

    ```
            [root@server]# openvpn --config  basic-udp-server.conf

    ```

1.  检查服务器日志文件的前几行：

    ```
            OpenVPN 2.3.10 x86_64-redhat-linux-gnu [SSL (OpenSSL)] [LZO]         [EPOLL] [PKCS11] [MH] [IPv6] built on Jan  4 2016 

            library versions: OpenSSL 1.0.1e-fips 11 Feb 2013, LZO 2.08 

    ```

1.  通过终止 `openvpn` 进程停止服务器。

1.  接下来，修改系统的 `LD_LIBRARY_PATH`，指向更新版的 OpenSSL：

    ```
            [root@server]# export LD_LIBRARY_PATH=..../openssl-1.0.1s
            [root@server]# openvpn --config  basic-udp-server.conf

    ```

1.  检查服务器日志文件的前几行：

    ```
            OpenVPN 2.3.10 x86_64-redhat-linux-gnu [SSL (OpenSSL)] [LZO]          [EPOLL] [PKCS11] [MH] [IPv6] built on Jan  4 2016 

            library versions: OpenSSL 1.0.1s  1 Mar 2016, LZO 2.08 

    ```

1.  再次通过终止 `openvpn` 进程停止服务器。

1.  切换到使用 PolarSSL 构建的 OpenVPN 版本并重新启动服务器：

    ```
            [root@server]# .../openvpn-2.3.10polarssl/openvpn --config  
            basic-udp-server.conf

    ```

1.  检查服务器日志文件的前几行：

    ```
            OpenVPN 2.3.10 x86_64-unknown-linux-gnu [SSL (PolarSSL)] [LZO]          [EPOLL] [MH] [IPv6] built on Apr 27 2016 

            library versions: PolarSSL 1.3.16, LZO 2.08 

    ```

## 它是如何工作的...

当 OpenVPN 启动时，加密库会被加载和初始化。此时，库的版本信息会被检索并打印出来。通过使用不同构建版本的加密库，我们可以看到只有服务器日志文件的前几行会发生变化。

## 还有更多...

使用的加密库的类型和构建版本决定了 OpenVPN 一些更高级的功能，正如我们在接下来的几个配方中将看到的那样。库的版本信息对于调试无法正常工作的设置提供了至关重要的信息，正如我们在第六章中将看到的，*OpenVPN 故障排除 - 配置*。

## 另见

+   下一个配方将解释加密库之间的差异

+   来自第六章的 *如何阅读 OpenVPN 日志文件* 配方，详细介绍了如何阅读 OpenVPN 日志文件

# OpenSSL 和 PolarSSL 的加密功能

如前一方案所述，从 OpenVPN 2.3 版本开始，可以使用 OpenSSL 加密库或 PolarSSL 库来构建 OpenVPN。在此方案中，我们将展示这两种加密库的一些关键区别。

## 准备就绪

使用第二章中的第一个方案设置服务器证书，*仅 IP 网络的客户端-服务器*。使用来自上一方案的客户端证书和中介 CA 证书。在此方案中，计算机运行的是 Fedora 22 Linux 和 OpenVPN 2.3.10，支持 OpenSSL 和 PolarSSL 两种构建方式。

## 如何操作...

1.  启动常规版本的 OpenVPN 并使用`--show-ciphers`选项：

    ```
            [root@server]# openvpn --show-ciphers

    ```

1.  OpenVPN 现在将列出所有可用的密码，OpenSSL 1.0+的密码列表可能会超过 50 个。最常用的密码包括：

    ```
            BF-CBC 128 bit default key (variable) 
            BF-CFB 128 bit default key (variable) (TLS client/server...)  
            BF-OFB 128 bit default key (variable) (TLS client/server...)  
            AES-128-CBC 128 bit default key (fixed) 
            AES-128-OFB 128 bit default key (fixed) (TLS client...)  
            AES-128-CFB 128 bit default key (fixed) (TLS client...) 
            AES-256-CBC 256 bit default key (fixed) 
            AES-256-OFB 256 bit default key (fixed) (TLS client...) 
            AES-256-CFB 256 bit default key (fixed) (TLS client...) 
            AES-128-CFB1 128 bit default key (fixed) (TLS client...) 
            AES-192-CFB1 192 bit default key (fixed) (TLS client...) 
            AES-256-CFB1 256 bit default key (fixed) (TLS client...) 
            AES-128-CFB8 128 bit default key (fixed) (TLS client...) 
            AES-192-CFB8 192 bit default key (fixed) (TLS client...) 
            AES-256-CFB8 256 bit default key (fixed) (TLS client...) 

    ```

1.  接下来，切换到使用 PolarSSL 构建的 OpenVPN 版本，并重新运行相同的命令：

    ```
            [root@server]# .../openvpn-2.3.10polarssl/openvpn --show-
            ciphers

    ```

1.  当前的密码列表如下：

    ```
            AES-128-CBC 128 bit default key 
            AES-192-CBC 192 bit default key 
            AES-256-CBC 256 bit default key 
            BF-CBC 128 bit default key 
            CAMELLIA-128-CBC 128 bit default key 
            CAMELLIA-192-CBC 192 bit default key 
            CAMELLIA-256-CBC 256 bit default key 
            DES-CBC 64 bit default key 
            DES-EDE-CBC 128 bit default key 
            DES-EDE3-CBC 192 bit default key 

    ```

1.  启动常规版本的 OpenVPN 并使用`--show-digests`选项：

    ```
            [root@server]# openvpn --show-digests

    ```

1.  OpenVPN 现在将列出所有可用的 HMAC 算法，这些算法可以使用`--auth`选项进行指定。该列表可能会超过 25 个条目，因此只会打印出最常用的：

    ```
            MD5 128 bit digest size 
            SHA 160 bit digest size 
            RIPEMD160 160 bit digest size 
            ecdsa-with-SHA1 160 bit digest size 
            SHA224 224 bit digest size 
            SHA256 256 bit digest size 
            SHA384 384 bit digest size 
            SHA512 512 bit digest size 

    ```

1.  接下来，切换到使用 PolarSSL 构建的 OpenVPN 版本，并重新运行相同的命令：

    ```
            [root@server]# .../openvpn-2.3.10polarssl/openvpn --show-
            digests

    ```

1.  当前的 HMAC 算法列表如下：

    ```
            SHA512 512 bit default key 
            SHA384 384 bit default key 
            SHA256 256 bit default key 
            SHA224 224 bit default key 
            SHA1 160 bit default key 
            RIPEMD160 160 bit default key 
            MD5 128 bit default key 

    ```

## 它是如何工作的...

当 OpenVPN 启动时，加密库会被加载并初始化。仅在此时，才知道可用的加密算法和 HMAC 算法。OpenSSL 和 PolarSSL 都提供了一种机制来获取可用算法的列表，OpenVPN 使用该列表来处理`--show-ciphers`和`--show-digests`选项。

本方案展示了 PolarSSL/mbed-TLS 库不支持 OpenSSL 支持的所有算法。当你需要支持 PolarSSL 构建版本的 OpenVPN（例如 Android 和 iOS 的 OpenVPN Connect 客户端）时，你只能使用两种加密库都支持的密码或摘要（`--auth`参数）。

## 还有更多...

除了数据通道密码和 HMAC 算法外，还有一组可用的算法可以列出。这是用于加密和认证控制通道的 TLS 算法集。要列出 TLS 参数集，请使用以下命令：

```
openvpn --show-tls

```

### AEAD 密码

从 OpenVPN 2.4 开始，支持一组新的密码。这些密码被称为**AEAD**密码，代表**带相关数据的认证加密**。这些密码将加密与认证结合，从而不再需要单独的 HMAC 算法，提升了性能。OpenSSL 1.0+和 mbed-TLS 1.3+都支持这些密码。在 OpenVPN 2.4+中，密码列表将包括：

+   AES-128-GCM

+   AES-192-GCM

+   AES-256-GCM

### 加密速度

OpenSSL 和 PolarSSL 之间的另一个主要区别是算法的加密/解密速度。OpenSSL 包含了为最大加密速度而手工调优的汇编例程，特别是对于新款 Intel CPU 上的 AES 算法。然而，加密速度并不是决定 OpenVPN 网络吞吐量时最重要的因素，正如我们将在第八章中看到的，*性能调优*章节所述。

# 推送密码算法

OpenVPN 2.4+的另一个新特性是能够从服务器“推送”密码算法或 HMAC 算法到客户端。这使得切换加密算法或 HMAC 认证算法变得更加容易，前提是所有客户端都使用 OpenVPN 2.4。这个教程提供了一个明确推送密码算法的设置，并解释了新的密码协商协议。

## 准备工作

本教程使用了第二章中*客户端-服务器 IP 专用网络*教程中创建的 PKI 文件。对于这个教程，服务器计算机运行 CentOS 6 Linux 和 OpenVPN 2.4.0。客户端运行 Fedora 22 Linux 和 OpenVPN 2.4.0。对于服务器，请保留第二章中*服务器端路由*教程中的服务器配置文件`basic-udp-server.conf`。对于 Windows 客户端，请保留第二章中*使用 ifconfig-pool 块*教程中的相应客户端配置文件`basic-udp-client.ovpn`。

## 如何操作...

1.  通过添加以下行来修改服务器配置文件`basic-udp-server.conf`：

    ```
            cipher aes-256-gcm 
            push "cipher aes-256-gcm" 

    ```

    然后将其保存为`example4-10-server.conf`。

1.  启动服务器：

    ```
     [root@server]# openvpn --config example4-10-server.conf

    ```

1.  使用“标准”配置文件启动客户端，但启用详细日志：

    ```
     [root@client]# openvpn --config basic-udp-client.conf --
                verb 4
            Data Channel Encrypt: Cipher 'BF-CBC' initialized with 128 bit 
            key
            Data Channel Encrypt: Using 160 bit message hash 'SHA1' for 
            HMAC authentication
            Data Channel Decrypt: Cipher 'BF-CBC' initialized with 128 bit 
            key
            Data Channel Decrypt: Using 160 bit message hash 'SHA1' for 
            HMAC authentication
            Control Channel: TLSv1.2, cipher TLSv1/SSLv3 ECDHE-RSA-AES256-
            GCM-SHA384, 2048 bit RSA
            [...]
            OPTIONS IMPORT: data channel crypto options modified
            [...]
            Data Channel Encrypt: Cipher '**AES-256-GCM**' initialized with 256 
            bit key
            Data Channel Decrypt: Cipher '**AES-256-GCM**' initialized with 256 
            bit key

    ```

    显示 OpenVPN 当前正在使用 AES-256 密码算法的输出将以**粗体**显示。

1.  使用`ping`命令验证我们是否能连接到服务器：

    ```
     [client]$   ping -c 4  10.200.0.1
    PING 10.200.0.1 (10.200.0.1) 56(84) bytes of data.
            64 bytes from 10.200.0.1: icmp_seq=1 ttl=64 time=9.23 ms
            64 bytes from 10.200.0.1: icmp_seq=2 ttl=64 time=8.78 ms
            64 bytes from 10.200.0.1: icmp_seq=3 ttl=64 time=10.0 ms
            64 bytes from 10.200.0.1: icmp_seq=4 ttl=64 time=9.00 ms
            --- 10.200.0.1 ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3004ms
            rtt min/avg/max/mdev = 8.780/9.259/10.022/0.468 ms

    ```

## 它是如何工作的...

推送密码算法现在和推送其他 OpenVPN 选项一样简单。2.4 之前的版本不支持这一功能。这使得 VPN 管理员可以更改所用的加密参数，而无需修改所有（远程）客户端配置文件。

## 还有更多…

从 OpenVPN 2.4 开始，引入了新的密码协商协议。在启动时，客户端和服务器将检查双方是否都支持新的 GCM 加密协议。然后，从这个列表中选择最强的密码算法作为加密算法。如果没有找到匹配项，OpenVPN 会回退到默认的 BlowFish（BF-CBC）密码算法，以确保向后兼容性。

这个功能可以通过新的指令`ncp-ciphers`和`disable-ncp`进行调节。第一个指令指定协商的密码算法列表，而第二个指令则完全关闭密码算法协商。

当从服务器显式推送密码算法到客户端时，你只能从 NCP 密码列表中指定一个密码。默认的 NCP 密码列表是 AES-256-GCM:AES-128-CGM:BF-CBC。

```
ccp-ciphers 
push "auth SHA512" 

```

### 未来的增强功能

预计未来对这一新功能的增强将包括：

+   一个单独的控制通道 HMAC 算法，使你能够独立切换数据通道算法

+   可以设置“每个客户端”加密密码算法，允许为不同的平台和客户端支持不同的密码算法

# 椭圆曲线支持

在 OpenVPN 的 2.4 版本中，增加了使用**椭圆曲线**（**EC**）证书代替更常见的 RSA 类型证书的支持。**椭圆曲线加密**（**ECC**）提供了一种快速的加密和认证安全连接的方法，但尚未广泛使用。部分原因是一些专利问题。然而，由于大多数现代 OpenSSL 库提供 ECC 支持，OpenVPN 也可以使用 EC 证书。ECC 的主要优势在于，你可以提供更小的密钥来达到与更常见的 RSA 和 DSA 类型加密相同的安全级别。这将提高 VPN 性能，同时不牺牲安全性。正如我们在本示例中看到的，OpenVPN 的控制通道可以使用 EC 算法进行认证。数据通道仍然使用非 EC HMAC 算法，如 SHA1，进行认证。

## 准备工作

对于这个示例，服务器计算机运行的是 CentOS 6 Linux 和 OpenVPN 2.4.0，客户端运行的是 Fedora 22 Linux 和 OpenVPN 2.4.0。

## 如何操作...

1.  我们首先需要生成一个新的基于 EC 的证书颁发机构：

    ```
     $ export KEY_CN=
     $ export KEY_OU=
     $ export KEY_NAME=
     $ export OPENSSL_CONF=/etc/openvpn/cookbook/openssl-
            1.0.0.cnf
     $ openssl ecparam -out cakey_temp.pem \
     -name sect571k1 -text -genkey
     $ openssl ec -in cakey_temp.pem -out ec-ca.key -aes256
     $ openssl req -new -x509 -out ec-ca.crt -key ec-ca.key
     -days 3650 -sha512 -extensions v3_ca
     -subj "/C=US/O=Cookbook 2.4/CN=Elliptic Curve CA"

    ```

    这将生成`ec-ca.crt`和`ec-ca.key`文件，使用`sect571k1`椭圆曲线，我们将用它来签署基于 EC 的客户端和服务器证书。

1.  接下来，生成新的 EC 服务器证书：

    ```
     $ openssl req -nodes -sha512 -newkey ec:ec-ca.crt
     -new -days 400 -out ec-server.req 
     -keyout ec-server.key
     -subj "/C=US/O=Cookbook 2.4/CN=ecserver"
     $ chmod 600 ec-server.key
     $ openssl x509 -req 
     -extfile $OPENSSL_CONF 
     -extensions server
     -out ec-server.crt -sha512 -CA ec-ca.crt 
     -CAkey ec-ca.key  -in ec-server.req 
     -set_serial $RANDOM

    ```

    这将生成`ec-server.crt`和`ec-server.key`文件。

1.  类似地，生成新的 EC 客户端证书：

    ```
     $ openssl req -nodes -sha512 
     -newkey ec:ec-ca.crt
     -new -days 400 
     -out ec-client.req -keyout ec-client.key
     -subj "/C=US/O=Cookbook 2.4/CN=ecclient"
     $ chmod 600 ec-client.key
     $ openssl x509 -req -extfile $OPENSSL_CONF 
     -extensions usr_cert
     -out ec-client.crt -sha512 -CA ec-ca.crt 
     -CAkey ec-ca.key -in ec-client.req 
     -set_serial $RANDOM

    ```

    这将生成`ec-client.crt`和`ec-client.key`文件。

1.  创建服务器配置文件：

    ```
            proto udp 
            port 1194 
            dev tun 
            server 10.200.0.0 255.255.255.0 

            ca   /etc/openvpn/cookbook/ec-ca.crt 
            cert /etc/openvpn/cookbook/ec-server.crt 
            key  /etc/openvpn/cookbook/ec-server.key 
            dh   /etc/openvpn/cookbook/dh2048.pem 

    ```

    将其保存为`example4-11-server.conf`。

1.  启动服务器：

    ```
     [root@server]# openvpn --config example4-11-server.conf

    ```

1.  接下来，创建客户端配置文件：

    ```
            client 
            proto udp 
            remote openvpnserver.example.com 
            port 1194 
            dev tun 
            nobind 

            ca /etc/openvpn/cookbook/ec-ca.crt 
            cert /etc/openvpn/cookbook/ec-client.crt 
            key /etc/openvpn/cookbook/ec-client.key 
            verb 4  

    ```

    然后将其保存为`example4-11-client.conf`。

1.  使用安全通道将文件如`ec-ca.crt`、`ec-client.crt`和`ec-client.key`传输到客户端计算机。

1.  最后，启动客户端：

    ```
     [root@client]# openvpn --config example4-11-client.conf

    ```

    观察所选的控制通道密码算法：

    ```
            Control Channel: TLSv1.2, cipher TLSv1/SSLv3 ECDHE-ECDSA-
            AES256-GCM-SHA384 

    ```

    这表明控制通道使用基于 ECDSA 的密码算法进行保护。

## 它是如何工作的...

通过生成基于 EC 的证书颁发机构并使用基于 EC 的证书，OpenVPN 现在可以在控制通道上支持椭圆曲线加密。数据通道仍然使用默认的 BF-CBC（Blowfish）密码算法和默认的 HMAC 算法 SHA1 进行保护。

应该注意的是，使用基于 RSA 的证书时，控制通道的密码算法看起来非常相似：

```
Control Channel: TLSv1.2, cipher TLSv1/SSLv3 ECDHE-RSA-AES256-GCM-SHA384, 2048 bit RSA 

```

并不是“ECDHE”部分证明了使用了 ECC，而是“ECDSA”。

## 还有更多...

还可以选择不同的 ECDH“曲线”。这是通过首先列出 OpenVPN 服务器上可用的 ECDH 曲线来完成的：

```
[root@server]# openvpn --show-curves
Available Elliptic curves:
[...]
secp112r1
secp112r2
secp521r1
prime192v1
prime192v2
[...]

```

然后通过将选项添加到服务器配置文件中：

```
ecdh-curve secp521r1

```

### 椭圆曲线支持

并非所有 Linux 发行版都提供开箱即用支持椭圆曲线加密的 OpenSSL 库。特别是基于 RedHat 的和源自 RedHat 的发行版，如 RedHat Enterprise Linux、CentOS 和 Fedora，明确禁用了 ECC 支持。RedHat 引用专利问题作为原因，但“默认”OpenSSL 库提供了完整的 ECC 支持。

由于本书中使用的 Linux 发行版是 CentOS 和 Fedora，因此特别为本食谱制作了 OpenSSL 1.0.2 库的自定义版本。

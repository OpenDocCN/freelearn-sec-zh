# 前言

嘿，你好！欢迎来到*Introduction to Kali Purple* – 一个充满乐趣的教育手册，重点介绍集成了防御性安全工具和渗透测试/道德黑客常用的攻击性安全工具的 Kali Linux 操作系统的独特特色。

Kali Purple 独特之处在于它是一套可由攻击性或防御性网络安全人员使用的互操作工具，用于开发教育和培训目的的概念验证用例。这些工具按照**国家标准与技术研究院网络安全框架**（**NIST CSF**）的支柱进行组织。

虽然我们提供了一个高层次概述的入门手册，但我们也包含了一些更高级的概念和大量的额外资源，供那些喜欢探索的人使用，这些人经常分不清现在是黎明还是黄昏，并且真诚地喜欢糟糕的老爸笑话。

对于那些宁愿保持婚姻的人，我们已将内容分为三个逐步阶段，每个阶段都有其各自的章节组，因此您可以逐步消化材料：

+   安装 Kali Purple 及用于获取、存储和展示信息的工具

+   获取数据进行分类和事件响应的分析

+   数字取证、攻击性安全和自动化

在帮助您开始建立自己的 Kali Purple 实例并部署**安全信息与事件管理**（**SIEM**）系统之前，我们简要介绍了网络安全概念与网络攻击的历史。

然后我们向您介绍了数据包和数据分析工具以及入侵检测和预防系统。之后，我们将进入数据收集、丰富化、索引化、存储和分析后所发现恶意活动的应对阶段 – 事件响应。

然后我们深入讨论数字取证、社会工程学和攻击性安全，突出一些被道德黑客和网络犯罪分子广泛使用的知名工具，最后总结自动化和 NIST 框架。

# 本书适合谁

本书适合网络安全爱好者、学生和专注于攻击或防御，或者如何用攻击对付防御以教育目的的初级分析师。

此内容是针对以下受众目标开发的：

+   寻找一个工具来开发使用案例场景以培训初级分析师的 SOC 领导层。

+   寻求更好理解防御安全工具以及攻击工具和技术如何对其造成影响的网络安全学生。

+   初级网络安全分析师希望扩展其专业工具箱，并更深入地理解其领域与当前角色相关性的人。本内容将指导他们朝多个可能个人成就的方向发展。

# 本书涵盖内容

*第一章*，*网络安全导论*，通过探讨新兴技术与相关威胁的平行历史，提供了网络安全的介绍。它讨论了进攻性安全与防御性安全的区别，以及我们今天所处的安全形势是如何形成的。

*第二章*，*Kali Linux 与 ELK 堆栈*，探讨了 Kali 与其他 Linux 发行版的谱系，并介绍了操作系统的核心防御工具之一——一组统称为 ELK 堆栈的应用程序。**Elasticsearch、Logstash 和 Kibana**（**ELK**）与支持数据发货组件 Beats 和 X-Pack 一同呈现。

*第三章*，*安装 Kali Purple Linux 环境*，全面回顾了如何获取、更新和运行 Kali Purple 及其所需的依赖项，无论读者当前使用的主机操作系统是什么。本章通过探索虚拟机，尤其是广泛接受且免费提供的 VirtualBox，来覆盖这一兼容性需求。

*第四章*，*配置 ELK 堆栈*，汇聚前两章所学的内容，引导你搭建 ELK 堆栈的核心组件及其支持技术。本章首先查看 Elasticsearch 数据库和索引应用程序，并将其与 Kibana 可视化界面集成，然后添加 Logstash 进行数据增强。

*第五章*，*将数据发送到 ELK 堆栈*，继续通过探讨 SIEM 解决方案如何通过数据发货器获取信息，并设置它们向 SIEM 报告，进一步构建 ELK 的配置。本章将探索数据流的全貌——信息如何通过 Logstash 进行增强，如何在 Elasticsearch 中索引和存储，并通过 Kibana 呈现给 SIEM 用户。

*第六章*，*流量与日志分析*，深入探讨了可能最终通过 ELK 堆栈或其他 SIEM 解决方案运行的信息，首先简要概述了数据包，然后介绍了 Malcolm 数据收集和分析工具套件，重点介绍了 Arkime——Malcolm 更为突出的数据分析工具之一。

*第七章*，*入侵检测与防御系统*，在上一章介绍的 Malcolm 工具套件的基础上，提供了入侵检测与防御系统的概述。首先对两种入侵管理方式进行对比和分析，然后聚焦于 Suricata IDS/IPS 和 Zeek IDS。

*第八章*，*安全事件与响应*，通过引入**安全编排与自动化响应**（**SOAR**）设置，结合 StrangeBee 的 Cortex 和 TheHive，努力深入解释了事件响应。本章还介绍了与各种情报和信息威胁源的额外集成，如**恶意软件信息共享平台**（**MISP**）、**结构化威胁信息表达**（**STIX**）和**受信自动化指标交换信息**（**TAXII**）。本章最后鼓励您开始独立研究并做出社区贡献。

*第九章*，*数字取证*，回顾了 Kali Purple 在数字取证中的贡献，主要通过恶意软件分析，同时介绍了一些工具，这些工具可能更多地与攻击性安全相关，但却为用户行为和思维方式提供了深刻洞察。

*第十章*，*整合红队与外部工具*，将之前与 Kali Linux 和渗透测试相关的攻击性安全工具与您在本书其他章节中探索和设置的防御性工具结合起来，供您部署并用于防御性工具的测试。本章深入探讨了攻击性安全，涵盖了诸如 OWASP ZAP、Wireshark、Metasploit、Burp Suite、Nmap、sqlmap、Nikto、Nessus、Hydra、Medusa 和 John the Ripper 等流行工具。

*第十一章*，*自动驾驶、Python 和 NIST 控制*，通过自动驾驶自动化脚本等高级功能，总结了*Kali Purple 入门*一书。接着，章节提供了对 Python 脚本语言的独特见解，重点不是学习如何开发代码，而是从网络防御者的角度识别它，以便进行分析。最后，章节介绍了 Kali Purple 所基于的框架，包括最近增加的 Govern 支柱的高级概览。

# 获取本书最大收益

您应该具备基本的安全概念和 Linux 操作系统知识——任何版本，但 Kali 是最理想的——以及信息技术系统和数据流的一般知识。

| **本书中涵盖的常规应用** | **操作系统要求** |
| --- | --- |
| VirtualBox | Windows、macOS 或 Linux |
| Kali Purple | Linux |
| Elasticsearch、Logstash、Kibana、Beats、Elastic Agent（ELK 栈） | Windows、macOS 或 Linux |
| Malcolm 套件，包括 Arkime、Suricata 和 Zeek | Windows、macOS 或 Linux |
| StrangeBee 套件，包括 Cortex 和 TheHive | Windows、macOS 或 Linux |
| 渗透测试套件，包括 OWASP ZAP、Wireshark、Metasploit、Burp Suite、Nmap、sqlmap、Nikto、Nessus、Hydra、Medusa 和 John the Ripper | Windows、macOS 或 Linux |
| Kali 自动驾驶 | Kali Linux |

# 使用的约定

本书中使用了许多文本约定。

**文本中的代码**：表示文本中的代码词、数据库表名、文件夹名称、文件名、文件扩展名、路径名、虚拟网址、用户输入和 Twitter 账户名。以下是一个示例：“输入**community-id**作为搜索词。将该值设置为**true**。”

代码块设置如下：

```
awesomeSauce = "Sweet Baby Ray's"
print("My favorite sauce is: " + awesomeSauce + "!")
# Now it will print – My favorite sauce is: Sweet Baby Ray's!
```

当我们希望特别提醒你关注代码块中的某一部分时，相关行或项会以粗体显示：

```
awesomeSauce = "Sweet Baby Ray's"
print("My favorite sauce is: " + awesomeSauce + "!")
# Now it will print – My favorite sauce is: Sweet Baby Ray's!
```

任何命令行输入或输出都写成如下格式：

```
sudo apt install apt-transport-https ca-certificates curl gnupg lsb-release
```

**粗体**：表示新术语、重要词汇或你在屏幕上看到的文字。例如，菜单或对话框中的文字通常以**粗体**显示。以下是一个示例：“将光标移动到左侧列，悬停在**08 -** **攻击工具**上。”

提示或重要说明

看起来像这样。

# 与我们联系

我们始终欢迎读者的反馈。

**一般反馈**：如果你对本书的任何方面有疑问，请通过 customercare@packtpub.com 与我们联系，并在邮件主题中注明书名。

**勘误表**：尽管我们已尽一切努力确保内容的准确性，但仍可能会出现错误。如果你在本书中发现错误，我们将非常感激你报告给我们。请访问[www.packtpub.com/support/errata](http://www.packtpub.com/support/errata)并填写表格。

**盗版**：如果你在互联网上发现我们作品的任何非法复制版本，我们将非常感激你提供相关位置地址或网站名称。请通过 mailto:copyright@packt.com 联系我们，并附上该材料的链接。

**如果你有兴趣成为作者**：如果你在某个主题上有专业知识，并且有兴趣撰写或参与撰写书籍，请访问[authors.packtpub.com](http://authors.packtpub.com)

# 分享你的想法

阅读完《Kali Purple 简介》后，我们很想听听你的想法！请[点击这里直接进入 Amazon 评价页面](https://packt.link/r/1835088988)并分享你的反馈。

你的评论对我们和技术社区都非常重要，并将帮助我们确保提供优质的内容。

# 下载本书的免费 PDF 副本

感谢你购买本书！

你喜欢随时阅读，但又不能随身携带纸质书籍吗？

你的电子书购买无法与所选设备兼容吗？

不用担心，现在每本 Packt 书籍都附带免费的无 DRM PDF 版本。

随时随地、在任何设备上阅读。直接将你最喜欢的技术书籍中的代码复制粘贴到你的应用程序中。

好处不仅仅这些，你还可以每天在邮箱中独享折扣、新闻通讯以及精彩的免费内容。

按照以下简单步骤获得福利：

1.  扫描二维码或访问以下链接

![下载本书的免费 PDF 副本](img/B21223_QR_Free_PDF.jpg)

[`packt.link/free-ebook/978-1-83508-898-2`](https://packt.link/free-ebook/978-1-83508-898-2)

1.  提交你的购买证明

1.  就这样！我们将直接把免费的 PDF 和其他福利发送到你的电子邮件

# 前言

你好！欢迎阅读《使用 Wazuh 进行安全监控》。在本书中，我们将探索使用 Wazuh 这一开源安全平台进行安全操作和管理的领域——该平台将**安全事件与事件管理**（**SIEM**）和**扩展检测与响应**（**XDR**）功能统一起来——以提升组织内部的威胁检测、事件响应、威胁狩猎和合规管理。

Wazuh 将入侵检测、日志分析、文件完整性监控、漏洞检测和安全配置评估等强大功能结合成一个统一的解决方案。

我将提供相关信息，并指导你通过部署 Wazuh 系统、与多个第三方安全工具的集成以及实际案例的方式，来帮助你掌握这些技能。我在开源领域的专业知识主要来源于两个方面：

+   十年在企业网络中咨询和构建开源安全解决方案的经验

+   从播客、访谈和与行业专家的讨论中获得的洞察

诸如 Wazuh 这样的开源安全工具的需求，由于其价格合理、社区支持和灵活性，得到了推动，帮助组织提升威胁检测、事件响应、安全监控、威胁情报和合规管理。学习并获得像 Wazuh 这样的工具的实际操作经验，能显著帮助有志成为安全分析师或专业人员的人在入侵检测、日志分析、事件响应、漏洞管理和自定义脚本等方面提升技能，且这一切都可以在一个平台上完成。参与开源社区帮助你建立网络机会并进行持续学习，使你在网络安全行业中成为有价值的人才。

# 本书适合的人群

安全分析师、SOC 分析师和安全架构师可以获得关于如何搭建 Wazuh 平台并利用它提升组织安全态势的实际洞察。

本书的三大目标读者群体如下：

+   **安全工程师**：对于安全工程师来说，本书提供了有关如何部署和配置 Wazuh 以进行入侵检测、恶意软件检测、安全监控等的全面指南。

+   **安全架构师**：他们将获得关于如何设计以 Wazuh 为核心组件的安全基础设施的信息，使他们能够构建一个可扩展且合规的安全解决方案，有效降低风险并提供实时警报。

+   **SOC 分析师**：他们将从 Wazuh 平台的实际洞察和真实案例中受益。他们将学习如何分析安全警报，创建自定义 Wazuh 规则和解码器，并迅速响应威胁。

# 本书内容概述

*第一章*，*使用 Wazuh 进行入侵检测系统（IDS）*，提供了 IDS 和 Suricata 的基础知识，介绍了其功能和特性，Wazuh 的安装及 Suricata 的设置，利用 Suricata 进行威胁检测，处理网络扫描探针，识别 Metasploit 漏洞，使用 DVWA 模拟基于 Web 的攻击，以及使用 tmNIDS 衡量 NIDS 的有效性。

*第二章*，*使用 Wazuh 进行恶意软件检测*，介绍了恶意软件，使用 FIM 进行检测，整合 VirusTotal 以增强分析，并整合 Windows Defender 和 Sysmon。

*第三章*，*威胁情报与分析*，讨论了通过整合威胁情报和分析工具，如 MISP、TheHive 和 Cortex，来增强 Wazuh 的能力。本章包括在各种环境中使用威胁情报的实际案例，以及配置和利用 TheHive、Cortex 和 MISP 进行协作威胁分析和响应的指南。

*第四章*，*使用 Shuffle 进行安全自动化与编排*，介绍了**安全编排、自动化与响应**（**SOAR**）与 Wazuh 平台的集成，可以用来简化和增强事件响应过程。本章重点介绍了使用 Wazuh 和 Shuffle 实现自动化工作流、剧本和响应行动的实施。

*第五章*，*使用 Wazuh 进行事件响应*，重点介绍了 Wazuh 的主动响应功能，在实时修复威胁方面的应用，涵盖了多个实际用例，如阻止暴力破解攻击和自动隔离 Windows 机器。

*第六章*，*使用 Wazuh 进行威胁狩猎*，深入探讨了使用 Wazuh 进行主动威胁狩猎的方法，重点是日志分析、攻击映射、Osquery 使用和命令监控。

*第七章*，*漏洞与配置评估*，探讨了使用 Wazuh 进行漏洞和政策评估。内容将涉及寻找漏洞、监控配置和遵循业务中的标准合规框架等重要部分。本章还涵盖了漏洞评估和合规标准的基础知识，如 PCI DSS、NIST 800-53 和 HIPAA。它还提供了如何使用 Wazuh 功能确保您的组织遵循所有安全规则和政策的思路。

*第八章*，*附录*深入探讨了用于增强安全监控的自定义 Wazuh 规则列表。它探讨了在 Windows 环境中创建自定义 PowerShell 规则以检测可疑活动。此外，本章还讨论了为审计 Linux 系统而实施自定义 Auditd 规则，增强防御潜在威胁的能力。此外，它还提供了如何创建自定义 Kaspersky 端点安全规则，从而实现全面的威胁检测和响应。最后，本章介绍了映射到某些 MITRE ATT&CK® 技术的自定义 Sysmon 规则。

*第九章*，*词汇表*，提供了一个全面的词汇表，涵盖了理解安全监控和 Wazuh 功能所需的关键术语和概念。从*主动响应*，自动化响应操作，到*Amazon EC2 实例*等，每个条目都提供了简洁的解释。诸如*合规性*、*IDS*和*漏洞检测模块*等术语也得到了阐明，帮助你理解关键的安全概念。此外，诸如*PowerShell*、*Docker*和*YARA*等工具也有定义，突显了它们在现代网络安全实践中的重要性。本词汇表是对初学者和经验丰富的安全专业人士来说，在浏览复杂的安全监控和威胁检测环境时的宝贵参考。

# 最大化本书的价值

*你需要对网络安全概念有基本了解，例如恶意软件、网络扫描、Web 应用攻击和* *安全合规性。*

| **书中涵盖的** **软件/硬件** | **操作系统** **要求** |
| --- | --- |
| Wazuh OVA | Windows 和 Ubuntu Linux |
| Suricata IDS 和 Osquery |  |
| VirusTotal |  |

# 下载示例代码文件

你可以从 GitHub 仓库下载书中提到的代码，链接如下：[`github.com/PacktPublishing/Security-Monitoring-using-Wazuh`](https://github.com/PacktPublishing/Security-Monitoring-using-Wazuh)

我们还有其他来自我们丰富书籍和视频目录的代码包，您可以在 [`github.com/PacktPublishing/`](https://github.com/PacktPublishing/) 查看。请务必看看！

图片免责声明

本书包含了许多横向较长的截图。这些截图为读者提供了 Wazuh 在各种操作中的执行计划概览。因此，这些图像中的文字在 100% 缩放下可能显得较小。此外，在你通过示例操作时，你也可以更深入地查看 Wazuh 输出中的这些计划。

使用的约定

本书中使用了一些文本约定。

`文本中的代码`：表示文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这里有个例子：“复制 `curl` 命令来下载 Wazuh 模块并启动 Wazuh 代理服务，如下图所示。”

A block of code is set as follows:

```
<rule id="200101" level="1"> 
<if_sid>60009</if_sid> 
<field name="win.system.providerName">^PowerShell$</field> 
<mitre>
```

When we wish to draw your attention to a particular part of a code block, the relevant lines or items are set in bold:

```
policy: 
id: "rdp_audit" 
file: "sca_rdp_audit.yml" 
   name: "System audit for Windows based      system" 
   description: "Guidance for establishing a secure configuration for Unix based systems." 
```

Any command-line input or output is written as follows:

```
$ sudo systemctl restart wazuh-agent
```

**Bold**: Indicates a new term, an important word, or words that you see on screen. For instance, words in menus or dialog boxes appear in **bold**. Here is an example: “**Suricata** is an open-source network **intrusion detection and prevention** **system (IDS/IPS)**.”

Tips or important notes

Appear like this.

# Get in touch

Feedback from our readers is always welcome.

**General feedback**: If you have questions about any aspect of this book, email us at customercare@packtpub.com and mention the book title in the subject of your message.

**Errata**: Although we have taken every care to ensure the accuracy of our content, mistakes do happen. If you have found a mistake in this book, we would be grateful if you would report this to us. Please visit [www.packtpub.com/support/errata](http://www.packtpub.com/support/errata) and fill in the form.

**Piracy**: If you come across any illegal copies of our works in any form on the internet, we would be grateful if you would provide us with the location address or website name. Please contact us at copyright@packt.com with a link to the material.

**If you are interested in becoming an author**: If there is a topic that you have expertise in and you are interested in either writing or contributing to a book, please visit [authors.packtpub.com](http://authors.packtpub.com).

# Share Your Thoughts

Once you’ve read *Security Monitoring with Wazuh*, we’d love to hear your thoughts! Please [click here to go straight to the Amazon review page](https://packt.link/r/1-837-63215-4) for this book and share your feedback.

Your review is important to us and the tech community and will help us make sure we’re delivering excellent quality content.

# Download a free PDF copy of this book

Thanks for purchasing this book!

Do you like to read on the go but are unable to carry your print books everywhere?

Is your eBook purchase not compatible with the device of your choice?

Don’t worry, now with every Packt book you get a DRM-free PDF version of that book at no cost.

Read anywhere, any place, on any device. Search, copy, and paste code from your favorite technical books directly into your application.

The perks don’t stop there, you can get exclusive access to discounts, newsletters, and great free content in your inbox daily

Follow these simple steps to get the benefits:

1.  Scan the QR code or visit the link below

![Download a free PDF copy of this book QR Code](https://packt.link/free-ebook/9781837632152 )

[`packt.link/free-ebook/9781837632152`](https://packt.link/free-ebook/9781837632152)

1.  Submit your proof of purchase

1.  That’s it! We’ll send your free PDF and other benefits to your email directly

# Part 1:Threat Detection

在本部分中，我们将重点介绍如何利用 Wazuh 进行有效的威胁检测。你将学习如何设置一个**入侵检测系统**（**IDS**）来发现可疑流量。除此之外，你还将学习 Wazuh 平台的架构、组件及核心功能。你将了解 Wazuh 检测恶意软件的几个功能，并结合一些实际案例。

本部分包括以下章节：

+   *第一章*，*使用 Wazuh 的入侵检测系统（IDS）*

+   *第二章*，*使用 Wazuh 进行恶意软件检测*

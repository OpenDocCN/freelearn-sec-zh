

# 第八章：词汇表

本章包含了一些与 Wazuh 平台及其相关技术的核心术语词汇表。本章作为学习 Wazuh 技术领域基础知识的全面指南，无论你是经验丰富的安全专家，还是安全领域的新手，都能从中获得 Wazuh 功能及相关概念的有用总结。

词汇表按字母顺序排列。

# A

+   **主动响应**：主动响应是 Wazuh 的一个模块，它根据特定的触发条件自动执行响应操作。这有助于安全专业人员迅速有效地管理安全事件。一些可执行的操作包括防火墙丢弃或阻止、账户封锁、删除恶意文件、阻止可疑网络连接和隔离感染的端点。欲了解更多信息，请查看以下链接：

    +   **Wazuh 官方文档关于主动响应**：[`documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html`](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)

    +   **配置恶意文件的主动响应**：[`wazuh.com/blog/detecting-and-responding-to-malicious-files/`](https://wazuh.com/blog/detecting-and-responding-to-malicious-files/)

    +   **将 Suricata 与 Wazuh 集成以响应网络攻击**：[`wazuh.com/blog/responding-to-network-attacks-with-suricata-and-wazuh-xdr/`](https://wazuh.com/blog/responding-to-network-attacks-with-suricata-and-wazuh-xdr/)

+   **AWS 实例**：AWS 实例是运行基于 AWS 平台的云应用程序的虚拟机。云基础设施使你能够在不购买计算机或服务器的情况下进行各种操作。AWS 实例有多种类型，如通用型、计算优化型、内存优化型和存储优化型。欲了解更多信息，请访问以下网站：

    +   **Amazon EC2 实例 – AWS** **文档**：[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/Instances.html`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Instances.html)

    +   **AWS EC2 实例类型 – AWS**：[`aws.amazon.com/ec2/instance-types/`](https://aws.amazon.com/ec2/instance-types/)

# B

+   **暴力破解攻击**：暴力破解攻击是一种黑客技术，通过试错的方式来破解密码、登录凭证和加密密钥。这是一种直接但有效的策略，用于获取对用户账户、公司网络和系统的未经授权的访问。在找到正确的登录信息之前，黑客会尝试多种用户名和密码，通常会在一台机器上测试大量的组合。欲了解更多信息，请查看以下链接：

    +   **暴力破解攻击**：[`www.crowdstrike.com/cybersecurity-101/brute-force-attacks/`](https://www.crowdstrike.com/cybersecurity-101/brute-force-attacks/)

    +   **OWASP 的暴力破解攻击**: [`owasp.org/www-community/attacks/Brute_force_attack`](https://owasp.org/www-community/attacks/Brute_force_attack)

# C

+   **CDB 列表**: **CDB**（**常量数据库**）列表是 Wazuh 中的文本文件，可以存储用户列表、文件哈希、IP 地址和域名。你还可以在其中存储其他信息，如网络端口。你可以使用 CDB 列表创建“白名单”或“黑名单”来列出用户、文件、IP 地址或域名。通过检查它们的签名是否在 CDB 列表中，还可以用来查找恶意文件。欲了解更多信息，请访问以下网站：

    +   **CDB 列表和威胁** **情报**: [`documentation.wazuh.com/current/user-manual/capabilities/malware-detection/cdb-lists-threat-intelligence.html`](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/cdb-lists-threat-intelligence.html)

    +   **使用 CDB** **列表**: [`documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html`](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html)

+   **ClamAV**: ClamAV 是一款开源的防病毒软件，可以查找并清除恶意软件、病毒以及其他对系统和数据库有害的网络活动。它兼容 Windows、Linux 和 Mac 设备。欲了解更多信息，请访问以下网站：

    +   **ClamAV – 官方** **文档**: [`docs.clamav.net/`](https://docs.clamav.net/)

    +   **Wazuh 上的 ClamAV 日志收集**: [`documentation.wazuh.com/current/user-manual/capabilities/malware-detection/clam-av-logs-collection.html`](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/clam-av-logs-collection.html)

+   **命令监控**: 命令监控允许你监控多个事项，如磁盘空间使用情况、平均负载、网络监听器变化和正在运行的进程。命令监控适用于安装了 Wazuh 代理的所有终端。欲了解更多信息，请访问以下网站：

    +   **Wazuh – 命令** **监控**: [`documentation.wazuh.com/current/user-manual/capabilities/command-monitoring/index.html`](https://documentation.wazuh.com/current/user-manual/capabilities/command-monitoring/index.html)

    +   **使用 Auditd 和** **Wazuh** 监控 Linux 上的 root 操作: [`wazuh.com/blog/monitoring-root-actions-on-linux-using-auditd-and-wazuh/`](https://wazuh.com/blog/monitoring-root-actions-on-linux-using-auditd-and-wazuh/)

+   **合规性（监管）**: 合规性（即安全合规性）是企业用来确保其遵循安全规则、标准和框架的过程。安全合规性的目的是遵守法律、政府规则、商业最佳实践以及书面协议。一些流行的安全合规性如下：

    +   **支付卡行业数据安全标准** (**PCI DSS**)

    +   **健康保险流通与问责法案** (**HIPAA**)

    +   **联邦信息安全管理** **法案** (**FISMA**)

    +   **萨班斯-奥克斯利** **法案** (**SOX**)

    +   欧盟的 **通用数据保护** **条例** (**GDPR**)

    欲了解更多信息，请查看以下链接：

    +   **什么是 PCI DSS** **合规性？**: [`www.imperva.com/learn/data-security/pci-dss-certification/`](https://www.imperva.com/learn/data-security/pci-dss-certification/)

    +   **使用 Wazuh 实现 GDPR** **合规性**: [`documentation.wazuh.com/current/compliance/gdpr/index.html`](https://documentation.wazuh.com/current/compliance/gdpr/index.html)

+   **容器**: 容器将软件与其不同的环境（例如开发和预发布环境）分开。它们还帮助使用相同基础设施但不同软件的团队更顺畅地协作。容器镜像是一个轻量级、独立的软件单元，可以在应用程序上运行。它包含了程序运行所需的所有代码、运行时、系统工具、系统库和设置。欲了解更多信息，请查看以下链接：

    +   **什么是** **容器？**: [`www.ibm.com/topics/containers`](https://www.ibm.com/topics/containers)

    +   **由 Wazuh 提供的容器安全**: [`documentation.wazuh.com/current/getting-started/use-cases/container-security.html`](https://documentation.wazuh.com/current/getting-started/use-cases/container-security.html)

# D

+   **Docker**: Docker 是一个免费的工具，用于创建应用、分发应用和运行应用。Docker 帮助你将应用与基础设施分开，这加速了软件交付。你可以像运行应用一样使用 Docker 管理基础设施。欲了解更多信息，请查看以下链接：

    +   **Docker 官方** **文档**: [`docs.docker.com/`](https://docs.docker.com/)

    +   **在 Wazuh 上监控 Docker 事件**: [`documentation.wazuh.com/current/proof-of-concept-guide/monitoring-docker.html`](https://documentation.wazuh.com/current/proof-of-concept-guide/monitoring-docker.html)

# E

+   **端点**: 端点是网络中的设备或节点，例如计算机或服务器，Wazuh 代理会监控这些端点以确保安全。你可以通过以下链接了解更多关于端点的信息：

    +   **什么是** **端点？**: [`www.paloaltonetworks.com/cyberpedia/what-is-an-endpoint`](https://www.paloaltonetworks.com/cyberpedia/what-is-an-endpoint)

# F

+   **文件完整性监控 (FIM)**: FIM 是一种 IT 安全程序和实践，检查和验证应用软件、数据库和 **操作系统** (**OS**) 文件是否已被更改或损坏。如果 FIM 发现文件已被更改、更新或损坏，它可以发出警报，以便进行进一步调查，并在必要时进行修复。欲了解更多信息，请查看以下链接：

    +   **什么是** **FIM？**: [`www.crowdstrike.com/cybersecurity-101/file-integrity-monitoring/`](https://www.crowdstrike.com/cybersecurity-101/file-integrity-monitoring/)

    +   **在 Wazuh 上设置 FIM**: [`documentation.wazuh.com/current/getting-started/use-cases/file-integrity.html`](https://documentation.wazuh.com/current/getting-started/use-cases/file-integrity.html)

# G

+   **GDPR 合规性**: **通用数据保护条例**（**GDPR**）是一项关于数字隐私的立法，告知企业如何收集、使用和保存关于生活在**欧盟**（**EU**）的个人数据。这项法律还控制着个人数据向欧盟外部的传输。通过赋予用户（通常称为数据主体）对其个人数据收集、共享和使用的控制权，GDPR 合规性增强了隐私权。要了解更多内容，请查看以下链接：

    +   **什么是** **GDPR？**: [`www.cloudflare.com/learning/privacy/what-is-the-gdpr/`](https://www.cloudflare.com/learning/privacy/what-is-the-gdpr/)

    +   **使用 Wazuh 进行 GDPR** **合规性**: [`documentation.wazuh.com/current/compliance/gdpr/index.html`](https://documentation.wazuh.com/current/compliance/gdpr/index.html)

+   **GitHub**: GitHub 使用 Git，这是一款开源版本控制软件，允许多人同时对网页进行修改。这使得团队能够在创建和编辑其网站内容时实时协作。要了解更多内容，请查看以下链接：

    +   **什么是 GitHub 以及如何使用** **它？**: [`www.geeksforgeeks.org/what-is-github-and-how-to-use-it/`](https://www.geeksforgeeks.org/what-is-github-and-how-to-use-it/)

    +   **使用 Wazuh 监控** **GitHub**: [`documentation.wazuh.com/current/cloud-security/github/index.html`](https://documentation.wazuh.com/current/cloud-security/github/index.html)

# H

+   **HIPAA 合规性**: HIPAA 合规性是一套医疗保健组织必须遵循的标准和协议，用以保护敏感患者数据的隐私和安全。如果一个组织处理**受保护的健康信息**（**PHI**），它需要确保遵循关于物理、安全网络和过程安全的 HIPAA 规则。要了解更多内容，请查看以下链接：

    +   **什么是 HIPAA** **合规性？**: [`www.proofpoint.com/us/threat-reference/hipaa-compliance`](https://www.proofpoint.com/us/threat-reference/hipaa-compliance)

    +   **使用 Wazuh 进行 HIPAA** **合规性**: [`documentation.wazuh.com/current/compliance/hipaa/index.html`](https://documentation.wazuh.com/current/compliance/hipaa/index.html)

# I

+   **IDS（入侵检测系统）**: IDS 是一种网络安全解决方案，用于检查网络数据和设备是否存在已知的恶意活动、异常活动或安全策略违规行为。当有已知或潜在的威胁时，IDS 会检测并向中央安全工具（如**安全信息与事件管理**（**SIEM**）系统）发出警报。要了解更多，请查看以下链接：

    +   **什么是** **IDS?**: [`www.geeksforgeeks.org/intrusion-detection-system-ids/`](https://www.geeksforgeeks.org/intrusion-detection-system-ids/)

    +   **网络 IDS 与** **Wazuh**的集成: [`documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html`](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)

# J

+   **JSON（JavaScript 对象表示法）**: JSON 是一种简单的基于文本的格式，用于发送和存储信息。当数据从计算机发送到网页时，JSON 常常被使用。它是一种数据序列化格式，能够在多个平台、应用程序和系统之间进行一致的数据传输。要了解更多，请查看以下链接：

    +   **什么是** **JSON?**: [`www.w3schools.com/whatis/whatis_json.asp`](https://www.w3schools.com/whatis/whatis_json.asp)

# K

+   **Kubernetes**: Kubernetes 是一个便捷、可扩展、开源的平台，旨在简化自动化和声明性配置，从而更好地管理容器化工作负载和服务。在生产环境中，你需要关注运行应用程序的容器，确保它们不会宕机。容器是打包和运行应用程序的好方法。要了解更多，请查看以下链接：

    +   **什么是** **Kubernetes?**: [`cloud.google.com/learn/what-is-kubernetes`](https://cloud.google.com/learn/what-is-kubernetes)

    +   **如何在** **Kubernetes**上部署 Wazuh? [`documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html`](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html)

# L

+   **日志数据收集**: 日志数据收集是从不同网络源获取日志并将它们集中在一个地方的过程。收集日志数据有助于安全团队维持合规性、识别并修复威胁，找出应用程序中的故障以及其他安全问题。

+   要了解更多，请查看以下链接：

    +   **日志数据收集** **如何工作**: [`documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html`](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html)

# M

+   **恶意软件 IOC（妥协指标）**: 这是展示攻击已在组织的网络或终端执行的取证数据。IOC 可以是 IP 地址、域名、恶意软件文件的哈希值等。IOC 还可以包括文件的元数据，如作者、创建日期和文件版本。欲了解更多信息，请查看以下链接：

    +   **什么是** **IOC？**: [`www.crowdstrike.com/cybersecurity-101/indicators-of-compromise/`](https://www.crowdstrike.com/cybersecurity-101/indicators-of-compromise/)

    +   **恶意软件检测使用** **Wazuh**: [`documentation.wazuh.com/current/user-manual/capabilities/malware-detection/index.html`](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/index.html)

+   **MITRE ATT&CK**: **MITRE ATT&CK**（**MITRE 对抗性战术、技术与常识**）是一个帮助组织评估其安全准备度并定位防御漏洞的框架。MITRE ATT&CK 框架提供了对对手技术和战术的详尽分类，特点是其高细节水平。该框架建立在对现实世界网络安全威胁的观察基础上。欲了解更多信息，请查看以下链接：

    +   **什么是 MITRE ATT&CK** **框架？**: [`www.ibm.com/topics/mitre-attack`](https://www.ibm.com/topics/mitre-attack)

    +   **通过 MITRE ATT&CK** **框架增强 Wazuh 的检测**: [`documentation.wazuh.com/current/user-manual/ruleset/mitre.html`](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)

# N

+   **NIST 800-53 框架**: **国家标准与技术研究院**（**NIST**）**800-53** 是一项网络安全标准和合规框架。它是一组准则，规定了所有美国联邦信息系统的最低安全控制要求，但不包括对国家安全至关重要的系统。欲了解更多信息，请查看以下链接：

    +   **什么是 NIST SP 800-53** **框架？**: [`www.forcepoint.com/cyber-edu/nist-sp-800-53`](https://www.forcepoint.com/cyber-edu/nist-sp-800-53)

    +   **Wazuh 与 NIST** **800-53** 合规性: [`documentation.wazuh.com/current/compliance/nist/index.html`](https://documentation.wazuh.com/current/compliance/nist/index.html)

# O

+   **OpenSearch**: OpenSearch 是一个开源搜索引擎和分析套件，用于日志分析、网站信息搜索和实时应用监控。OpenSearch 是 Elasticsearch 和 Kibana 的一个分支，发布于 2021 年。它采用 Apache 2.0 许可证，并基于 Lucene。OpenSearch 提供了使用关键词、多语言、自然语言和同义词进行搜索的功能。欲了解更多信息，请查看以下链接：

    +   **OpenSearch 官方** **文档**: [`opensearch.org/docs/latest/`](https://opensearch.org/docs/latest/)

    +   **Wazuh 和 OpenSearch** **集成**：[`documentation.wazuh.com/current/integrations-guide/opensearch/index.html`](https://documentation.wazuh.com/current/integrations-guide/opensearch/index.html)

+   **OSSEC**：OSSEC 是一个开源的 **基于主机的入侵检测系统** (**HIDS**)，与多种操作系统兼容。它是一个可扩展的程序，能够检查日志、确保文件的正确性、监视 Windows 系统、集中执行策略、查找 rootkit、发送实时警报等功能。欲了解更多信息，请查看以下链接：

    +   **什么是** **OSSEC？**：[`www.ossec.net/ossec-downloads/`](https://www.ossec.net/ossec-downloads/)

    +   **如何从 OSSEC 迁移到** **Wazuh**：[`wazuh.com/blog/migrating-from-ossec-to-wazuh/`](https://wazuh.com/blog/migrating-from-ossec-to-wazuh/)

+   **Osquery**：Osquery 是一个用于查询和监控系统的工具，使用类似 SQL 的语法。它支持 Windows、Linux 和 macOS 系统。通过 Osquery，你可以查询成千上万的数据点，并接收结构化的数据返回。由于它可以以机器可读格式（如 JSON）返回数据，因此非常适合与现有的安全或监控工具和脚本进行集成。欲了解更多信息，请查看以下链接：

    +   **什么是** **Osquery？**：[`www.uptycs.com/blog/osquery-what-it-is-how-it-works-and-how-to-use-it`](https://www.uptycs.com/blog/osquery-what-it-is-how-it-works-and-how-to-use-it)

    +   **使用 Osquery 和** **Wazuh** **进行威胁狩猎**：[`documentation.wazuh.com/current/getting-started/use-cases/threat-hunting.html`](https://documentation.wazuh.com/current/getting-started/use-cases/threat-hunting.html)

# P

+   **PCI DSS 合规性**：**PCI DSS** (**支付卡行业数据安全标准**) 合规性是一套要求，描述了组织如何存储、处理或传输信用卡信息，以实现安全环境。这是一个国际安全标准，有助于防止欺诈和数据泄露，同时为消费者提供基本的保护标准。PCI DSS 合规性并非一次性的活动；它是一个持续的过程，涉及评估处理持卡人数据的基础设施、分析系统漏洞，并修复可利用的漏洞以确保网络安全。

+   欲了解更多信息，请查看以下链接：

    +   **什么是 PCI DSS** **合规性？**：[`www.techtarget.com/searchsecurity/definition/PCI-DSS-Payment-Card-Industry-Data-Security-Standard`](https://www.techtarget.com/searchsecurity/definition/PCI-DSS-Payment-Card-Industry-Data-Security-Standard)

    +   **使用 Wazuh 实现 PCI DSS** **合规性**：[`documentation.wazuh.com/current/compliance/pci-dss/index.html`](https://documentation.wazuh.com/current/compliance/pci-dss/index.html)

+   **PowerShell**: 基于.NET，PowerShell 是一个基于任务的命令行外壳和脚本语言，可以为你节省大量时间和精力，同时还能帮助你提高 IT 基础设施的效率。要了解更多内容，请查看以下链接：

    +   **什么是** **PowerShell?**: [`learn.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.4`](https://learn.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.4)

    +   **如何使用 Wazuh 监控 Sysmon** **事件**: [`wazuh.com/blog/using-wazuh-to-monitor-sysmon-events/`](https://wazuh.com/blog/using-wazuh-to-monitor-sysmon-events/)

# R

+   **Rootkit**: Rootkit 是一种允许黑客未经授权访问网络或计算机并隐藏其存在的软件类型。Rootkit 可能很难被发现，并且能够长时间隐藏。要了解更多内容，请查看以下链接：

    +   **什么是** **Rootkit?**: [`www.fortinet.com/resources/cyberglossary/rootkit`](https://www.fortinet.com/resources/cyberglossary/rootkit)

    +   **使用** **Wazuh** 检测 Rootkit: [`documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html`](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html)

# S

+   **SCA 策略**: 在 Wazuh 平台版本 3.9.0 中，添加了 SCA 模块。该模块提供了应用于加固系统的独特测试。Wazuh 支持的所有平台（Linux、macOS、Windows、Solaris、AIX 和 HP-UX）都可以运行该模块。SCA 工具提供了一种方法来读取和运行以 YAML 格式编写的配置检查。此外，预先设置策略使得遵循如 HIPAA 或 PCI DSS 等规则，以及**CIS**（**互联网安全中心**）等准则变得更加容易。要了解更多内容，请查看以下链接：

    +   **Wazuh 的 SCA**: [`documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html`](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html)

+   **SSH（安全外壳协议）**: SSH 协议是一种通过不安全的网络安全地发送远程命令到计算机的协议。SSH 使用加密技术来加密并验证设备连接。要了解更多内容，请查看以下链接：

    +   **什么是** **SSH?**: [`www.geeksforgeeks.org/introduction-to-sshsecure-shell-keys/`](https://www.geeksforgeeks.org/introduction-to-sshsecure-shell-keys/)

+   **Syslog**: Syslog 用于发送信息性、分析性和调试消息，以及一般的通知、分析和调试消息。你可以使用它来跟踪各种事件，例如系统关闭、网络连接不稳定、系统重启或端口状态变化等。要了解更多内容，请查看以下链接：

    +   **Syslog 是如何** **工作的？**：[`www.solarwinds.com/resources/it-glossary/syslog`](https://www.solarwinds.com/resources/it-glossary/syslog)

    +   **在 Wazuh** **服务器上配置 syslog**：[`documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html`](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html)

+   **系统调用**：系统调用是操作系统软件在计算机上运行时，通过程序化方法请求内核提供服务的一种方式。程序可以通过系统调用与操作系统进行通信。当计算机软件向操作系统的内核请求任何服务时，就会触发系统调用。通过**应用程序接口**（**API**），系统调用使用户程序能够访问操作系统的服务。欲了解更多信息，请访问以下链接：

    +   **什么是系统** **调用？**：[`www.geeksforgeeks.org/introduction-of-system-call/`](https://www.geeksforgeeks.org/introduction-of-system-call/)

    +   **使用** **Wazuh** 监控系统调用：[`documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/index.html`](https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/index.html)

+   **系统清单**：Wazuh 的系统清单模块收集有关被监控终端的数据。该数据包括硬件、操作系统、网络和正在运行的进程等详细信息。欲了解更多信息，请访问以下链接：

    +   **Wazuh 的系统** **清单**：[`documentation.wazuh.com/current/user-manual/capabilities/system-inventory/index.html`](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/index.html)

# T

+   **威胁情报**：威胁情报是收集、处理和研究的数据，用以了解威胁行为者的动机、攻击对象和攻击方式。威胁情报帮助我们做出更快速、更加智能的基于数据的安全决策。它还改变了威胁行为者的行动方式，从被动应对转变为主动应对，从而增强了我们与威胁行为者斗争的能力。欲了解更多信息，请访问以下链接：

    +   **什么是网络威胁** **情报？**：[`www.crowdstrike.com/cybersecurity-101/threat-intelligence/`](https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/)

    +   **使用** **Wazuh** 构建威胁情报的 IOC 文件：[`wazuh.com/blog/building-ioc-files-for-threat-intelligence-with-wazuh-xdr/`](https://wazuh.com/blog/building-ioc-files-for-threat-intelligence-with-wazuh-xdr/)

+   **信任服务标准（TSC）合规性**：AICPA 的**保证服务执行委员会**（**ASEC**）制定了**信任服务标准**（**TSC**），该标准用于评估控制目标。这些标准包括关于组织信息和系统的安全性、可用性、处理完整性、隐私性和机密性的措施。这些措施还涉及实体的具体部分，如某个部门、某个流程或实体使用的特定信息类型。欲了解更多，请查看以下链接：

    +   **什么是** **TSC？**：[`drata.com/glossary/trust-services-criteria`](https://drata.com/glossary/trust-services-criteria)

    +   **使用 Wazuh 进行 TSC** **合规性**：[`documentation.wazuh.com/current/compliance/tsc/index.html`](https://documentation.wazuh.com/current/compliance/tsc/index.html)

# V

+   **漏洞**：信息系统漏洞是黑客可以利用的弱点或机会，借此未经允许进入计算机系统。漏洞使系统的防御能力变弱，允许黑客发动攻击。欲了解更多，请查看以下链接：

    +   **什么是** **漏洞？**：[`www.upguard.com/blog/vulnerability`](https://www.upguard.com/blog/vulnerability)

+   **漏洞检测模块**：Wazuh 漏洞检测模块帮助用户发现操作系统和已安装应用程序中的弱点，这些系统和应用程序会在监控的终端上运行。该模块通过将 Wazuh 与来自 Microsoft、**Amazon Linux Advisories Security**（**ALAS**）、Canonical、Debian、Red Hat、Arch Linux 以及**国家漏洞数据库**（**NVD**）的外部漏洞源集成，来工作。欲了解更多，请查看以下链接：

    +   **漏洞检测是如何** **工作的**：[`documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/`](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)

+   **Windows Defender**：Windows Defender 是微软 Windows 内置的防病毒和防恶意软件解决方案。它会扫描计算机中的恶意软件，并检查系统中的任何异常行为。欲了解更多，请查看以下链接：

    +   **Windows Defender 日志** **收集**：[`documentation.wazuh.com/current/user-manual/capabilities/malware-detection/win-defender-logs-collection.html`](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/win-defender-logs-collection.html)

# Y

+   **YARA**：YARA 是一种帮助恶意软件分析师检测和分类恶意软件样本的工具。YARA 规则是描述某种类型恶意软件或威胁外观的指令。YARA 规则检查文件和网络中的模式、脚本和特征，找出恶意软件的存在。欲了解更多，请查看以下链接：

    +   **什么是** **YARA？**：[`virustotal.github.io/yara/`](https://virustotal.github.io/yara/)

    +   **使用 YARA 检测恶意软件** **集成**: [`documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html`](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html)

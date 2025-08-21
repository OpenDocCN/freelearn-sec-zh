# 序言

*Windows 取证实战*提供了解决挑战并在 Windows 平台上轻松开展有效调查的“取证配方”。你将从*数字取证与证据获取*的复习开始，这将帮助你理解在从 Windows 系统获取证据时所面临的挑战。接下来，你将学习如何获取 Windows 内存并使用现代取证工具分析 Windows 系统。本书还将深入讨论取证分析的其他元素，例如如何分析 Windows 系统数据、解析最常用的网页浏览器和电子邮件客户端数据，以及如何在数字取证调查中进行有效报告。

你将了解 Windows 10 与以前版本的不同之处，以及如何克服它带来的特定挑战。最后，你将学习如何排查在进行数字取证调查时遇到的问题。

本书结束时，你将能够高效地进行取证调查。

# 本书涵盖的内容

第一章，*数字取证与证据获取*，将简要介绍数字取证作为一门学科，并涵盖数字证据获取、检查和报告的基础知识。

第二章，*Windows 内存获取与分析*，将引导你使用 Belkasoft RAM Capturer 和 DumpIt 获取 Windows 内存。之后，你将学习如何使用 Belkasoft Evidence Center 和 Volatility 分析内存映像。

第三章，*Windows 驱动器获取*，将引导你获取 Windows 取证数据的主要来源——硬盘和固态硬盘。你将学习如何使用 FTK Imager 和 DC3DD 创建取证映像，并学习如何使用 Arsenal Image Mounter 挂载这些映像。

第四章，*Windows 文件系统分析*，将引导你分析最常见的 Windows 文件系统——新技术文件系统（NTFS），并使用 Sleuth Kit 进行操作。此外，你将学习如何使用 Autopsy、ReclaiMe Pro 和 PhotoRec 从 NTFS 及其后代 ReFS 中恢复已删除的文件。

第五章，*Windows 快照复制分析*，将展示如何使用 ShadowCopyView 浏览和复制 VSC 中的文件。你还将学习如何使用 VSSADMIN 和 MKLINK 挂载这些快照，并使用 Magnet AXIOM 分析其中的数据。

第六章，*Windows 注册表分析*，将展示如何使用 Magnet AXIOM 和 RegRipper 从 Windows 注册表中提取数据。此外，你还将学习如何使用注册表浏览器恢复已删除的注册表数据。

第七章，*主要 Windows 操作系统遗留物*，将介绍 Windows 取证中的主要遗留物，包括回收站项目、Windows 事件日志、LNK 文件和预取文件。你将学习如何使用 EnCase Forensic、Rifiuti2、Magnet AXIOM、FullEventLogView、EVTXtract、LECmd、Link Parser、PECmd 和 Windows Prefetch Carver 分析这些遗留物。

第八章，*网页浏览器取证*，将带你通过 BlackBagBlackLight、Magnet Axiom 和 Belkasoft Evidence Center 分析最流行的 Windows 网页浏览器。同时，你将学习如何从分页文件中提取浏览器数据。

第九章，*电子邮件和即时消息取证*，将教你如何分析最流行的 Windows 邮件客户端 Microsoft Outlook 和 Mozilla Thunderbird，以及即时消息应用 Skype 的遗留物。同时，你将学习如何从取证镜像中提取 Web 邮件遗留物。

第十章，*Windows 10 取证*，将介绍 Windows 10 特有的遗留物，如 Cortana、邮件应用、Xbox 应用和通知。你将学习数据存储位置、格式以及如何提取和分析这些数据。

第十一章，*数据可视化*，将展示如何通过数据可视化技术改善你的取证报告。你将学习如何在 Forensic Toolkit (FTK)、Autopsy 和 Nuix 中使用这些技术。

第十二章，*Windows 取证分析中的故障排除*，将教你如何解决取证软件的问题，包括商业软件和免费/开源软件；展示在进程失败时该怎么做，为什么分析假阳性非常重要；给出数字取证的初步建议；并提供进一步阅读的优质资源清单。

# 本书所需工具

本书需要以下软件：

+   Arsenal Image Mounter

+   Autopsy

+   Belkasoft Evidence Center

+   Belkasoft RAM Capturer

+   BlackBagBlackLight

+   dc3dd

+   DumpIt

+   EnCase Forensic

+   EVTXtract

+   FTK

+   FTK Imager

+   FullEventLogView

+   Intella

+   LECmd

+   Link Parser

+   Magnet AXIOM

+   Nuix

+   PECmd

+   PhotoRec

+   ReclaiMe Pro

+   Registry Explorer

+   RegRipper

+   Rifiuti2

+   ShadowCopyView

+   SkypeLogView

+   The Sleuth Kit

+   Volatility

+   Windows Prefetch Carver

本书中列出的许多商业工具都提供了可以免费下载的试用版本。下载链接将在章节中提供。

# 本书适用对象

如果你是一个取证分析师和事故响应专业人员，想要解决 Windows 平台的计算机取证调查，那么本书适合你。

# 各章节

本书中，你将找到一些频繁出现的章节标题（准备工作、如何操作、原理解析、更多内容以及参见）。

为了清晰地说明如何完成食谱，我们使用以下几节内容：

# 准备工作

本节告知您该食谱的预期内容，并描述了设置任何所需软件或初步设置的步骤。

# 如何操作…

本节包含遵循食谱所需的步骤。

# 它是如何工作的…

本节通常包含对前一节内容的详细解释。

# 还有更多……

本节包含关于食谱的额外信息，旨在让读者对食谱有更深入的了解。

# 另请参见

本节提供与食谱相关的其他有用信息链接。

# 约定

本书中有多种文本风格，用于区分不同类型的信息。以下是这些风格的几个示例及其含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟网址、用户输入和 Twitter 账号等如下所示：“所以在我们的例子中是`D:\Belkasoft Memory Forensics Test.`”

任何命令行输入或输出都如下所示：

```
volatility_2.6_win64_standalone.exe -f X:stuxnet.vmem
--
profile=WinXPSP3x86 malfind -p 868 --dump-dir
X:Stuxnet

```

新术语和重要单词用粗体显示。您在屏幕、菜单或对话框中看到的单词也会以这种方式出现在文本中：“第一个窗格显示有关检测到的影像副本的信息，包括名称、Explorer 路径、卷路径、创建时间等。”

警告或重要提示会以框框的形式显示。

小贴士和技巧会以这种形式出现。

# 客户支持

现在您是一本 Packt 书籍的骄傲拥有者，我们为您提供了许多帮助，帮助您最大限度地发挥购买的价值。

# 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的截图/图表的彩色图片。这些彩色图片将帮助您更好地理解输出中的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/WindowsForensicsCookbook_ColorImages.pdf.`](https://www.packtpub.com/sites/default/files/downloads/WindowsForensicsCookbook_ColorImages.pdf)下载该文件。

# 勘误

虽然我们已尽力确保内容的准确性，但错误难免发生。如果您在我们的书籍中发现错误——可能是文本或代码中的错误——我们将非常感激您能向我们报告。通过这样做，您可以帮助其他读者避免困扰，并帮助我们改进后续版本的书籍。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，点击“Errata Submission Form”链接，并输入勘误的详细信息。一旦您的勘误被验证，我们将接受您的提交，勘误将上传到我们的网站，或加入该书籍的勘误列表。

要查看先前提交的勘误表，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将显示在勘误部分下。

# 盗版

互联网上盗版版权材料是所有媒体的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上发现我们作品的任何形式的非法复制，请立即提供位置地址或网站名称，以便我们采取措施。

请通过`copyright@packtpub.com`联系我们，并提供涉嫌侵权材料的链接。

我们感谢您帮助保护我们的作者以及我们为您带来宝贵内容的能力。

# 问题

如果您对本书的任何方面有问题，请联系我们，邮箱为`questions@packtpub.com`，我们将尽力解决问题。

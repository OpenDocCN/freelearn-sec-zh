# 前言

移动设备（如手机、智能手机、平板电脑及其他电子设备）在我们的生活中无处不在。我们每天都在使用它们。用户越来越多地将移动设备作为与他人沟通的手段。这不仅仅是语音通话，还包括通过各种即时通讯（如 Skype、iChat、WhatsApp 和 Viber）和社交网络应用程序（如 Facebook）进行的交流。

通常，移动设备包含很多关于其所有者的个人数据。

本书将涉及移动取证的取证工具及其成功使用的实际技巧和方法。

# 本书内容涵盖

第一章，*SIM 卡获取与分析*，将引导你通过 TULP2G、MOBILedit Forensic、Oxygen Forensic 和 Simcon 进行 SIM 卡的获取与分析。你还将学习如何使用 TULP2G、MOBILedit Forensic、Oxygen Forensic 和 Simcon 分析 SIM 卡。

第二章，*安卓设备获取*，将教你如何使用 Oxygen Forensic、MOBILedit Forensic、Belkasoft Acquisition Tool、Magnet Aсquire 和 Smart Switch 从安卓设备中获取数据。

第三章，*苹果设备获取*，将教你如何获取不同的 iOS 设备数据。你将学习如何使用 Oxygen Forensic、libmobiledevice、Elcomsoft iOS Toolkit 和 iTunes 从 iOS 设备中获取数据。

第四章，*Windows Phone 与 BlackBerry 设备获取*，将解释如何获取不同的 Windows Phone 和 BlackBerry 设备的数据。你还将学习如何使用 Oxygen Forensic、BlackBerry Desktop Software 和 UFED 4PC 从 Windows Phone 和 BlackBerry 设备中获取数据。

第五章，*云端作为替代数据来源*，将讨论如何获取云端数据。在这一章中，你还将学习如何使用 Cloud Extractor、Electronic Evidence Examiner、Elcomsoft Phone Breaker 和 Belkasoft Evidence Center 从云端获取数据。

第六章，*SQLite 取证解析*，将教你如何分析 SQLite 数据库。同时，你将学习如何使用 Belkasoft Evidence Center、DB Browser for SQLite、Oxygen Forensic SQLite Viewer 和 SQLite Wizard 从 SQLite 数据库中提取和分析数据。

第七章，*Plist 取证解析*，将帮助你分析 plist 文件。你将学习如何使用 Apple Plist Viewer、Belkasoft Evidence Center、plist Editor Pro 和 Plist Explorer 从 plist 文件中提取和分析数据。

第八章，*分析 Android 设备的物理转储和备份*，将教你如何分析来自 Android 设备的数据（物理转储、备份等）。同时，你将学到如何使用 Autopsy、Oxygen Forensic、Belkasoft Evidence Center、Magnet AXIOM 和 Encase Forensic 提取和分析数据。  

第九章，*iOS 取证*，将解释如何分析 iOS 设备中的数据。你将学到如何使用 iPhone Backup Extractor、UFED Physical Analyzer、BlackLight、Oxygen Forensic、Belkasoft Evidence Center、Magnet AXIOM、Encase Forensic 和 Elcomsoft Phone Viewer 提取和分析数据。  

第十章，*Windows Phone 和 BlackBerry 取证*，将教你如何分析 Windows Phone 和 BlackBerry 设备中的数据。你将学到如何使用 Elcomsoft Blackberry Backup Explorer Pro、Oxygen Forensic 和 UFED Physical Analyzer 提取和分析数据。  

第十一章，*JTAG 和芯片拆卸技术*，将向你展示如何从锁定或损坏的 Android 设备、Windows Phone 设备和 Apple 设备中提取数据。  

# 本书所需的工具  

本书所需的软件如下：  

+   AccessData FTK Imager  

+   Autopsy  

+   Belkasoft Acquisition  

+   Belkasoft Evidence Center  

+   BlackBerry 桌面软件  

+   BlackLight  

+   Cellebrite UFED4PC  

+   DB Browser for SQLite

+   Elcomsoft Blackberry Backup Explorer Pro  

+   Elcomsoft iOS Toolkit  

+   Elcomsoft Phone Breaker  

+   Elcomsoft Phone Viewer  

+   Encase Forensic  

+   iPhone Backup Extractor  

+   iThmb Converter  

+   iTunes  

+   libmobiledevice  

+   Magnet AXIOM  

+   Magnet Aсquire  

+   MobilEdit Forensics  

+   Oxygen Software  

+   Paraben 电子证据检查员  

+   PC 3000 Flash  

+   Plist Editor Pro  

+   Plist Explorer  

+   SIMCon  

+   Smart Switch  

+   ThumbExpert  

+   TULP2G  

+   UFED Physical Analyzer  

+   Z3X EasyJtag BOX JTAG Classic Suite  

本书中大多数商业工具都有试用版本，可以免费下载。下载链接将在章节中提供。  

# 本书适合谁阅读  

如果你是移动取证分析师、数字取证分析师或数字取证学生，想要对不同平台（如 Android、iOS、Windows Phone 或 BlackBerry 操作系统）进行移动取证调查，那么这本书适合你。  

# 各章  

本书中有几个标题会经常出现（*准备工作*、*如何操作…*、*如何工作…*、*还有更多…*和*另见*）。为了清楚地指导你完成食谱，我们将按如下方式使用这些部分：  

# 准备工作  

本节告诉你在本食谱中可以期待什么，并描述如何设置任何所需的软件或初步设置。  

# 如何操作…  

本节包含执行该步骤所需的操作。  

# 如何工作…  

本节通常包含对上一节内容的详细解释。  

# 还有更多…  

本节包含了关于该配方的附加信息，旨在让读者对配方有更深入的了解。

# 另见

本节提供了有助于理解该配方的其他有用链接。

# 约定

在本书中，您会看到多种文本样式，用于区分不同类型的信息。以下是一些样式示例及其含义的解释。文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 账户名如下所示：“在 TULP2G 下载页面（[`sourceforge.net/projects/tulp2g/files/`](https://sourceforge.net/projects/tulp2g/files/)），选择 `TULP2G-installer-1.4.0.4.msi` 文件并下载。”

代码块如下所示：

```
;Google Nexus One
%SingleAdbInterface%        = USB_Install, USB\VID_18D1&PID_0D02
%CompositeAdbInterface%     = USB_Install, USB\VID_18D1&PID_0D02&MI_01
%SingleAdbInterface%        = USB_Install, USB\VID_18D1&PID_4E11
%CompositeAdbInterface%     = USB_Install, USB\VID_18D1&PID_4E12&MI_01
```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的词汇，例如菜单或对话框中的内容，文本中会以这种方式呈现：“当程序启动时，点击 Open Profile... 按钮。”

警告或重要提示如下所示。

提示和技巧如下所示。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法——喜欢或不喜欢的地方。读者反馈对我们来说非常重要，因为它帮助我们开发您真正能够从中受益的书籍。如果您希望提供一般反馈，请通过电子邮件发送至 `feedback@packtpub.com`，并在邮件主题中注明书名。如果您在某个领域有专长，并且有兴趣撰写或参与书籍的编写，请参阅我们的作者指南：[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经成为一本 Packt 书籍的骄傲拥有者，我们提供了一些帮助您充分利用购买内容的资源。

# 勘误

虽然我们已经尽力确保内容的准确性，但错误仍然会发生。如果您在我们的书籍中发现错误——可能是文本或代码中的错误——我们将不胜感激，如果您能报告此问题。这样，您可以帮助其他读者避免困扰，并帮助我们改进后续版本。如果您发现任何勘误，请通过访问 [`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata) 报告，选择您的书籍，点击“Errata 提交表单”链接，填写勘误详情。一旦您的勘误得到验证，您的提交将被接受，并且勘误将上传到我们的网站或添加到该书籍的勘误列表中。要查看之前提交的勘误，请访问 [`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书名。所需的信息将在勘误部分显示。

# 盗版

网络上侵犯版权的行为是一个普遍存在的问题，涵盖所有媒体。在 Packt，我们非常重视保护我们的版权和许可证。如果你在网络上遇到任何形式的非法复制作品，请立即提供该地址或网站名称，以便我们采取措施。请通过`copyright@packtpub.com`与我们联系，并附上涉嫌盗版材料的链接。感谢你帮助我们保护作者的权益，并支持我们为你提供有价值的内容。

# 问题

如果你在本书的任何部分遇到问题，可以通过`questions@packtpub.com`与我们联系，我们将尽力解决问题。

# 序言

逆向工程是一种用于分析软件、发现其弱点并加强防御的工具。黑客使用逆向工程作为工具来暴露安全漏洞和可疑的隐私实践。本书将帮助您掌握使用逆向工程的技巧。

# 本书适合的人群

如果您是安全工程师、分析师或系统程序员，并且想使用逆向工程来改善软件和硬件，那么本书非常适合您。如果您是想探索和学习逆向工程的开发者，本书对您也非常有用。

# 为了最大化地利用本书

+   具备一些编程/脚本编写知识会是一个额外的加分项。

+   了解信息安全和 x86 汇编语言将是一个优势。

+   使用的操作系统：Windows 和 Linux（版本将取决于 VirtualBox 的要求）

+   至少四核处理器，4 GB 内存，和 250 GB 硬盘空间。

+   您可能需要提前从微软下载虚拟机，因为这些文件可能需要一些时间才能下载。请参阅开发者页面：[`developer.microsoft.com/en-us/microsoft-edge/tools/vms/`](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)。

# 下载示例代码文件

您可以从您的帐户下载本书的示例代码文件，网址是[www.packt.com](http://www.packt.com)。如果您在其他地方购买了本书，可以访问[www.packt.com/support](http://www.packt.com/support)，并注册以直接将文件发送到您的电子邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册到[www.packt.com](http://www.packt.com)。

1.  选择“SUPPORT”选项卡。

1.  点击“代码下载与勘误”。

1.  在搜索框中输入书名，并按照屏幕上的指示操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，地址为：[`github.com/PacktPublishing/Mastering-Reverse-Engineering`](https://github.com/PacktPublishing/Mastering-Reverse-Engineering)。如果代码有更新，它将在现有的 GitHub 库中更新。

我们还提供了来自丰富书籍和视频目录的其他代码包，您可以在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到它们。快来看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书使用的截图/图示的彩色图片。您可以在此下载：`www.packtpub.com/sites/default/files/downloads/9781788838849_ColorImages.pdf`

# 使用的约定

本书中使用了多种文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟网址、用户输入和 Twitter 句柄。以下是一个示例：“`hkResult`用于由`RegEnumValueA`开始枚举注册表键下的每个注册表值。”

代码块设置如下：

```
 while (true) {
    for (char i = 1; i <= 255; i++) {
      if (GetAsyncKeyState(i) & 1) {
        sprintf_s(lpBuffer, "\\x%02x", i);
        LogFile(lpBuffer, (char*)"log.txt");
      }
    }
```

当我们希望引起您对代码块特定部分的注意时，相关行或项目将用粗体标记：

```
87 to base-2
87 divided by 2 is 43 remainder 1.
43 divided by 2 is 21 remainder 1.
21 divided by 2 is 10 remainder 1.
10 divided by 2 is 5 remainder 0.
5 divided by 2 is 2 remainder 1.
```

**粗体**：表示新术语、重要词汇或屏幕上可见的单词。例如，菜单或对话框中的单词在文本中显示如此。以下是一个示例：“在 VirtualBox 中，单击 File|Import Appliance。”

警告或重要注释如下。

提示和技巧出现如下。

# 联系我们

我们始终欢迎读者的反馈。

**总体反馈**：如果您对本书的任何方面有疑问，请在消息主题中提及书名，并通过电子邮件联系我们，邮箱为`customercare@packtpub.com`。

**勘误**：尽管我们已经尽最大努力确保内容准确性，错误确实偶尔会发生。如果您在本书中发现错误，我们将不胜感激您向我们报告。请访问[www.packt.com/submit-errata](http://www.packt.com/submit-errata)，选择您的书籍，点击错误提交表格链接并填写详细信息。

**盗版**：如果您在互联网上发现我们作品的任何形式的非法副本，请提供给我们位置地址或网站名称将不胜感激。请通过链接联系我们，链接为`copyright@packt.com`。

**如果您有兴趣成为作者**：如果您精通某个主题，并且有意撰写或为书籍做出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下您的评价。一旦您阅读并使用了本书，为什么不在购买的网站上留下您的评论呢？潜在的读者可以通过您公正的意见来做出购买决定，我们在 Packt 可以了解到您对我们产品的看法，我们的作者可以看到您对他们书籍的反馈。谢谢！

有关 Packt 的更多信息，请访问[packt.com](http://www.packt.com/)。

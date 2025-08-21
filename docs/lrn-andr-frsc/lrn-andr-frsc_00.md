# 序言

许多取证检查员依赖于商业的、一键式工具来检索和分析数据，尽管没有任何工具能够完美完成这两项任务。

*学习 Android 取证* 将向你介绍最新的 Android 平台及其架构，并提供 Android 取证概述。你将了解 Android 设备如何存储数据，并学习如何设置数字取证环境。在你阅读各章节时，将学习各种物理和逻辑技术，从设备中提取数据以获取取证证据。你还将学习如何恢复已删除的数据，并借助各种开源和商业工具进行应用数据的取证分析。在最后几章中，你将探索恶意软件分析，以便能够调查涉及 Android 恶意软件的网络安全事件。

到本书结束时，你将完全理解 Android 取证流程，探索开源取证工具，并调查移动网络安全事件。

# 本书的目标读者

如果你是取证分析师或信息安全专业人员，想要提升你对 Android 取证的知识，那么这本书适合你。期望你具备一些 Android 移动平台的基础知识。

# 如何最大化阅读此书的收益

本书涵盖了 Android 设备上的各种取证方法和技术。内容组织方式使任何用户都可以检查 Android 设备并进行取证调查。不需要任何先决知识。

因为所有主题都已解释，从基础到深入。对移动平台，特别是 Android 的了解，绝对会是一个优势。只要可能，使用工具执行各种取证活动所需的步骤都被详细说明。

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图示的彩色图像。你可以在此下载：`www.packtpub.com/sites/default/files/downloads/9781789131017_ColorImages.pdf`。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名称、文件名、文件扩展名、路径名、虚拟网址、用户输入和 Twitter 用户名。这里有一个例子：“启动恢复模式不会解密`/data`分区。”

一段代码如下所示：

```
from subprocess import Popen
from os import getcwd
command = "adb pull /data/data " + getcwd() + "\data_from_device"
p = Popen(command)
p.communicate()
```

当我们希望引起你对代码块中特定部分的注意时，相关的行或项会用粗体显示：

```
from subprocess import Popen
from os import getcwd
command = "adb pull /data/data " + getcwd() + "\data_from_device"
p = Popen(command)
p.communicate()
```

任何命令行输入或输出都如下所示：

```
j7xelte:/ # cat /proc/filesystems
```

**粗体**：表示新术语、重要单词或在屏幕上看到的单词。例如，菜单或对话框中的单词在文本中会像这样显示。这里有一个例子：“从主恢复界面，选择挂载。”

警告或重要提示如下所示。

提示和技巧如下所示。

# 联系我们

我们始终欢迎读者的反馈。

**一般反馈**：如果您对本书的任何内容有疑问，请在邮件主题中注明书名，并通过`customercare@packtpub.com`与我们联系。

**勘误**：尽管我们已尽力确保内容的准确性，但错误难免。如果您发现本书中的错误，我们将不胜感激，恳请您报告给我们。请访问[www.packt.com/submit-errata](http://www.packt.com/submit-errata)，选择您的书籍，点击“勘误提交表格”链接，并填写相关详情。

**盗版**：如果您在互联网上发现我们作品的任何非法复制品，敬请提供其位置或网站名称。请通过`copyright@packt.com`与我们联系，并附上该材料的链接。

**如果您有兴趣成为作者**：如果您在某个领域拥有专业知识，并且有兴趣写书或为书籍做贡献，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 书评

请留下评论。阅读并使用本书后，为什么不在您购买书籍的网站上留下评论呢？潜在读者可以看到并参考您的客观评价来做出购买决策，我们 Packt 公司可以了解您对我们产品的看法，而我们的作者也能看到您对其书籍的反馈。谢谢！

欲了解更多关于 Packt 的信息，请访问[packt.com](http://www.packt.com/)。

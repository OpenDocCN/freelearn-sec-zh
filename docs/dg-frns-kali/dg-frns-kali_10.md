# 第十章：使用 DFF 揭示证据

欢迎来到最后一章；你成功了。我们将使用的最后一个工具是**数字取证框架**（**DFF**）。DFF 使用模块化模型在一个简单和用户友好的图形用户界面中执行图像的自动化分析。DFF 支持多种图像文件格式，包括`.dd`、`.raw`、`.img`、`.bin`、E01、EWF 和 AFF。模块可以应用于使用嵌入式查看器查看各种文件格式，包括视频、音频、PDF、文档、图像和注册表文件。

DFF 还支持以下内容：

+   浏览器历史分析

+   文件恢复

+   元数据和 EXIF 数据分析

+   内存/RAM 分析

将所有这些功能集成到一个 GUI 中，可以轻松调查和分析获取的图像。在本章的练习中，我们将使用已经获取并可供下载的图像。这并不意味着我们应该只使用一个工具（如 DFF）进行分析。我建议至少使用两种工具进行所有调查任务，以便可以比较结果，增加调查的准确性和完整性。

请记住，在获取自己的图像时，始终确保通过使用写入阻断器和哈希工具来维护设备和证据的完整性。同样重要的是，除非情况需要，否则我们只能使用取证副本来保留证据。

让我们看看本章将涵盖的主题：

+   安装 DFF

+   启动 DFF GUI

+   使用 DFF 恢复已删除的文件

+   使用 DFF 进行文件分析

# 安装 DFF

要使用 DFF 进行调查，我们首先需要 Kali Linux 2016.1 ISO 镜像。我选择使用 64 位版本，并在 VirtualBox 中作为虚拟主机运行。

可以从[`www.kali.org/downloads/`](https://www.kali.org/downloads/)下载 Kali Linux 2016.1 ISO 镜像：

1.  安装 Kali 2016.1 作为虚拟主机后，我们可以使用`uname -a`命令查看版本详细信息：

![](img/61a6eca2-38f5-45d1-b8b5-765baae25a30.png)

1.  要开始安装 DFF，我们首先需要使用 Kali Sana 中使用的存储库更新`sources.list`。虽然在上一章中我们直接浏览到了`sources.list`文件，但是我们还可以使用终端以两种其他方式执行此任务。

在新的终端中，我们可以输入以下内容：

```
echo "deb http://old.kali.org/kali sana main non-free contrib" >
 /etc/apt/sources.list
```

![](img/f53b6707-3dd3-416b-9f58-c5af515138ca.png)

或者，我们可以使用第二种方法，输入以下内容：

```
 nano /etc/apt/sources.list
```

![](img/5882fb51-c64a-4b53-a1f5-ab3e6e718c47.png)

然后是存储库的详细信息：

```
deb http://http.kali.org/kali kali-rolling main contrib non-free
deb src http://http.kali.org/kali kali-rolling main contrib non-free
deb http://http.kali.org/kali sana main contrib 
```

1.  然后，按*Ctrl* + *X*退出，按*Y*保存更改到`sources.list`文件中：

![](img/0708ade5-df84-4d15-8476-21b732bcc1af.png)

1.  接下来，我们通过输入`apt-get update`来更新 Kali：

![](img/e6987292-6930-41a3-a7f0-cf7ba939151b.png)

1.  现在，我们通过输入以下内容来安装高级取证格式库：

```
apt-get install libafflib0
```

![](img/f47ff4ae-abfc-4c3d-b1c5-f41810c9d2a1.png)

如前面的屏幕截图所示，按*Y*继续。这是一个相当冗长的过程，因为它安装了几个取证工具的组件，包括 Autopsy、Sleuthkit、Bulk_extractor 和 DFF，如下一张屏幕截图所示：

![](img/91e792f0-8e05-42d4-867b-4b3a8725de94.png)

1.  安装库成功后，我们可以通过输入以下内容来安装 DFF：

```
apt-get install dff
```

![](img/90cc48fa-8298-4ed2-bd3c-b0d3d3bdfcc7.png)

1.  按*Y*继续，以允许安装 DFF 1.3.3 继续：

![](img/9f85671d-2935-44f7-b319-155d619aa87a.png)

1.  为了确保 DFF 已成功安装，我们可以在终端中输入`dff`，这将加载 DFF 中可用的模块：

![](img/e42cd730-0475-4c05-b6f3-fe3849d4a0ba.png)

一旦显示`欢迎使用数字取证框架`横幅，这意味着我们的 DFF 安装成功。现在我们可以通过运行 DFF GUI 来开始我们的调查：

![](img/b2f59e5e-d0e4-4e24-9ad5-83c24585833d.png)

# 启动 DFF GUI

现在我们已经安装了 DFF，我们可以首先验证 DFF 的版本，还可以使用 CLI 查看 DFF 中的一些命令：

1.  要查看已安装的 DFF 版本，在新的终端中，输入`dff -v`。在下面的屏幕截图中，我们可以看到版本是 1.3.0：

![](img/8a1ec99e-182f-4279-a542-2629957476fa.png)

1.  要查看可用选项，我们输入`dff -h`：

![](img/769c2d26-175b-44a6-aa29-1889e42d0cb9.png)

1.  要启动图形界面，我们输入`dff -g`：

![](img/8623fdd5-61b0-4eb3-8243-98eaa5d0dfa5.png)

1.  也可以通过单击应用程序 | 取证 | dff gui 来启动图形界面：

![](img/6291339b-ea1a-4cf8-89d5-b11b45a0df3f.png)

1.  使用任一方法打开后，我们将看到 DFF GUI：

![](img/4214917f-4175-4425-a254-6854c0ccaf3c.png)

# 使用 DFF 恢复已删除的文件

在本练习中，我们将使用使用 DD 创建的一个非常小的`.raw`图像。这个文件大约 6MB，可以在[`dftt.sourceforge.net/test7/index.html`](http://dftt.sourceforge.net/test7/index.html)上公开获取：

1.  单击 ZIP 文件进行下载并将其提取到默认位置。提取后，文件名显示为`7-ntfs-undel.dd`。在导入图像之前，花点时间观察主窗口区域条目旁的图标。逻辑文件字段的图标是一个带有一丝蓝色的白色文件夹：

![](img/087fcb19-5eed-430b-a368-ffdb576a7e5b.png)

在接下来的步骤中，当我们添加图像时，文件夹图标上会出现蓝色加号。

1.  要在 DFF 中打开我们下载的 DD 图像，单击文件 | 打开证据或单击打开证据按钮，如下图所示：

![](img/73ee2610-3cec-4fa3-901f-1897c6dd17f8.png)

1.  在选择证据类型框中，确保选中了 RAW 格式选项，并且在下拉框中选择了文件选项。单击绿色加号（+）以浏览`7-ntfs-undel.dd`文件。单击确定以继续：

![](img/21ea2feb-12d8-4966-933d-efb44a97aaf6.png)

在 DFF 的左窗格和主窗口中，观察逻辑文件图标旁边的加号。这告诉我们，虽然大小、标签和路径没有条目，但图像已成功添加，我们可以浏览逻辑文件部分：

![](img/f8439d1a-7532-4952-8b1b-f05b00e00da0.png)

1.  在左窗格中，单击逻辑文件类别。在主窗口中，显示图像名称：

![](img/7f6b684c-35d9-4086-bbce-aef08f25422d.png)

1.  在主窗口中双击图像名称。在应用模块框中，单击是：

![](img/8fdbe6b2-1eec-4755-99f0-c56ce9a47fdc.png)

应用模块后，在左窗格的逻辑文件下显示图像名称（`7-ntfs-undel.dd`）：

![](img/65ce173e-dadd-4566-a0de-f0ad80859809.png)

1.  单击左窗格中图像名称左侧的加号，展开菜单并查看图像内容。展开后，我们可以看到有两个文件夹，即`NTFS`和`NTFS 未分配`：

![](img/bb9f6fb5-b2fe-4700-843f-bbc68ef6f77f.png)

红色标记的条目（`dir1`和`$Orphans`）是已删除的文件。

1.  要查看文件内容，双击主窗口中的`NTFS`条目：

![](img/c480895b-ca22-4c6f-bb5d-45eee6dd5eae.png)

1.  单击`frag1.dat`已删除文件。右窗格显示有关文件的信息，包括以下内容：

+   名称：`frag1.dat`

+   节点类型：已删除文件

+   生成者：ntfs

+   创建时间：2004-02-29 20:00:17

+   文件访问时间：2004-02-29 20:00:17

+   文件修改时间：2004-02-29 20:00:17

+   MFT 修改时间：2004-02-29 20:00:17

![](img/50e58b32-45a4-4f85-a307-ed15b8e4a8d6.png)

1.  让我们检查另一个已删除的文件。单击`mult1.dat:ADS`流并查看其详细信息：

![](img/faa253f8-5683-4ea5-8c9f-60505dbe3ae6.png)

根据[`dftt.sourceforge.net/test7/index.html`](http://dftt.sourceforge.net/test7/index.html)上的文件列表，该图像包含 11 个已删除的文件，包括`mult1.dat:ADS`，其中包含 NTFS 备用数据流中的隐藏内容。DFF 已找到所有 11 个文件。请访问前面的网站或查看下面的截图以查看已删除文件的名称进行比较：

![](img/994cb6ef-3a48-469e-aea7-14bccb93e23a.png)

# 使用 DFF 进行文件分析

现在我们已经查看了文件恢复过程，让我们继续使用 DFF 来检查一个内容更多的图像文件。

在这个练习中，我们将使用另一个公开可用的图像，名为*JPEG 搜索测试#1（Jun'04）*。可以在[`dftt.sourceforge.net/test8/index.html`](http://dftt.sourceforge.net/test8/index.html)下载 ZIP 文件：

1.  下载 ZIP 文件后，将其解压到默认位置。解压后的文件名为`8-jpeg-search.dd`。

1.  通过重复上一个练习中的步骤，在 DFF 中打开证据文件：

1.  通过点击“应用程序”|“取证”|“ddf gui”来启动 DFF。

1.  点击“打开证据”按钮。

1.  浏览到`8-jpeg-search.dd`图像文件（如下截图所示）。

1.  点击“确定”：

![](img/22d3428b-6bd0-42a1-8f2d-6045b5932389.png)

1.  点击左窗格中的逻辑文件，然后在主窗口中双击文件名（`8-jpeg-search.dd`）：

![](img/a1ccd804-9677-4365-8fc9-6365b8999c05.png)

1.  在应用模块框中，当提示应用 NTFS 模块到节点时选择“是”：

![](img/96bcc88d-8e93-4d17-856b-3f4429898cb3.png)

1.  点击左窗格中的加号（+），旁边是逻辑文件，展开菜单。

1.  点击`8-jpeg-search.dd`文件名旁边的加号（+）以展开菜单。

在这个练习中，我们还发现了两个名为`NTFS`和`NTFS 未分配`的 NTFS 文件夹：

![](img/9158e9e5-b50b-437e-8146-342b2bbb8ec6.png)

1.  点击左窗格中的`NTFS`以查看子文件夹和文件（显示在主窗口中）：

![](img/14aba8ba-038b-4232-9e9e-aa2223c80f34.png)

1.  点击`alloc`文件夹查看其内容。在`alloc`文件夹中，主窗口中有两个带有彩色图标的文件：

+   `file1.jpg`

+   `file2.dat`

1.  如果尚未选择，请点击`file1.jpg`：

![](img/d31ef5fe-18bb-45f0-80a1-a6696a3f2e08.png)

1.  在右侧的属性列中，向下滚动到类型字段。请注意以下属性值，如下截图所示：

+   魔术：JPEG 图像数据，JFIF 标准 1.01

+   魔术 mime：image/jpeg

![](img/a768b7a0-cf18-4d3b-8f0c-bafedc993ae4.png)

1.  双击`file1.jpg`，在提示应用图片模块到节点时点击“是”，这将允许我们查看图片：

![](img/f83e4190-a834-4b0f-8555-94de03760c4d.png)

预览窗口打开，显示图像，并在图像下方显示文件路径为`/逻辑文件/8-jpeg-search.dd/NTFS/alloc/file1.jpg`：

![](img/3668cfde-b83a-41be-8279-f67c88c34415.png)

1.  通过点击“打开证据”按钮下的“浏览器”按钮返回到 DFF 浏览器界面：

![](img/b43b3c76-2686-4a63-9832-870e07148eb3.png)

1.  点击`file2.dat`并向下滚动到类型属性，并注意魔术和魔术 mime 值：

+   魔术：JPEG 图像数据，JFIF 标准 1.01

+   魔术 mime：image/jpeg

请注意，即使`file2`的扩展名是`.dat`，DFF 也读取了头文件，并将文件的真实类型列为 JPEG/JFIF 文件：

>![](img/6006eba0-094e-47db-bae4-24edc3c1fe57.png)

1.  双击`alloc`文件夹中的`file2.dat`（在`file1.jpg`文件下），在提示应用图片模块时点击“是”：

![](img/fc468863-39af-4480-9b3a-2a5a36e932ba.png)

1.  单击“浏览”按钮返回 DFF 界面。在左侧窗格中单击`del1`文件夹以查看其内容。在`del1`文件夹中有一个名为`file6.jpg`的单个文件，在属性列中列为已删除，如下截图所示。属性列中值得注意的值包括：

+   名称：`file6.jpg`

+   节点类型：已删除

+   magic: JPEG 图像数据，JFIF 标准。

+   magic mime: image/jpeg;

1.  双击`file6.jpg`并应用模块以预览文件（确保单击“浏览”按钮返回 DFF 浏览器界面）：

![](img/7f2b3dd3-d4f9-4910-9584-15bebbe45bb0.png)

1.  在左侧窗格中单击`del2`文件夹。主窗口显示一个带有奇怪扩展名`file7.hmm`的单个文件。属性列将文件列为已删除；但是，类型属性显示如下内容：

![](img/47e35c98-2ead-4d86-8e54-c86b69ce3b1e.png)

1.  双击`file7.hmm`文件并应用图片模块以预览`.jpg`图像：

![](img/112ad120-33ca-4bb9-b595-2a74587eab3d.png)

# 总结

恭喜，您已经到达了结尾。在这最后一章中，我们看了非常多功能的 DFF。使用 DFF，我们进行了文件恢复，文件夹探索，文件分析，并且还能够使用各种模块预览文件。

重要的是要记住，尽管 DFF 可以执行多项任务，但应该使用在前几章中使用的其他工具来验证发现的准确性。在调查过程中，记录您的步骤也很重要，以防必须重新创建调查过程或重迹您的步骤。

我本人，审阅者，编辑以及整个 Packt 家族代表，感谢您购买本书。请务必查看[`www.packtpub.com/`](https://www.packtpub.com/)上提供的其他优秀书籍。

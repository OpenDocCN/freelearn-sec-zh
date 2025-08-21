# 第七章. 使用 Python 进行内存取证

现在你已经在基础设施中进行了调查（参见第四章，*使用 Python 进行网络取证*），常见的 IT 设备（参见第三章，*使用 Python 进行 Windows 和 Linux 取证*），甚至在虚拟化环境（参见第五章，*使用 Python 进行虚拟化取证*）和移动世界（参见第六章，*使用 Python 进行移动取证*）中进行了调查，在本章中，我们将向你展示如何使用基于 Python 的取证框架 Volatility，在以下平台上对易失性内存进行调查：

+   Android

+   Linux

在向你展示了一些适用于 Android 和 Linux 的基本 Volatility 插件，并说明如何获取所需的 RAM 转储进行分析之后，我们将开始在 RAM 中寻找恶意软件。因此，我们将使用基于模式匹配的 YARA 规则，并将其与 Volatility 的强大功能结合起来。

# 理解 Volatility 基础

一般来说，内存取证遵循与其他取证调查相同的模式：

1.  选择调查目标。

1.  获取取证数据。

1.  取证分析。

在前面的章节中，我们已经介绍了多种选择调查目标的技术，例如，从虚拟化层中具有异常设置的系统开始。

内存分析的取证数据获取高度依赖于环境，我们将在本章的*在 Linux 上使用 Volatility*和*在 Android 上使用 Volatility*部分进行讨论。

### 提示

**始终将虚拟化层视为数据源**

从正在运行的操作系统中获取内存始终需要对该系统的管理员权限，并且这是一个侵入性的过程，也就是说，数据获取过程会改变内存数据。此外，先进的恶意软件能够操控操作系统的内存管理，以防止其被获取。因此，始终按照第五章，*使用 Python 进行虚拟化取证*中所描述的方法，检查并尽量在虚拟机监控程序层面获取内存。

到目前为止，用于内存数据分析的最重要工具是**Volatility**。Volatility 可在[Volatility Foundation](http://www.volatilityfoundation.org/)网站上获取。

该工具用 Python 编写，可以在 GNU **通用公共许可证**（**GPL**）第 2 版的条款下免费使用。Volatility 能够读取多种文件格式的内存转储，例如，休眠文件、原始内存转储、VMware 内存快照文件，以及将会在本章后面讨论的由 LiME 模块生成的 **Linux 内存提取器**（**LiME**）格式。

Volatility 世界中最重要的术语如下：

+   **配置文件**：配置文件帮助 Volatility 解释内存偏移量和内存结构。配置文件取决于操作系统，尤其是操作系统内核、机器和 CPU 架构。Volatility 包含许多适用于最常见用例的配置文件。在本章的 *在 Linux 上使用 Volatility* 部分中，我们将介绍如何创建您的配置文件。

+   **插件**：插件用于对内存转储执行操作。您使用的每个 Volatility 命令都会调用一个插件来执行相应的操作。例如，要获取在 Linux 系统内存转储期间运行的所有进程的列表，可以使用 `linux_pslist` 插件。

Volatility 提供了全面的文档，我们建议您熟悉所有模块描述，以便充分利用 Volatility。

# 在 Android 上使用 Volatility

要分析 Android 设备的易失性内存，首先需要 LiME。LiME 是一个**可加载内核模块**（**LKM**），它可以访问设备的整个 RAM，并将其转储到物理 SD 卡或网络中。在使用 LiME 获取易失性内存转储后，我们将向您展示如何安装和配置 Volatility 以解析 RAM 转储。在最后一节中，我们将演示如何从 RAM 转储中提取特定信息。

## LiME 和恢复映像

LiME 是一个可加载内核模块（LKM），它允许从 Linux 和基于 Linux 的设备（如 Android）获取易失性内存。这使得 LiME 非常独特，因为它是第一个可以在 Android 设备上进行完整内存捕获的工具。它还最小化了在获取过程中用户空间和内核空间进程之间的交互，从而使其生成的内存捕获比其他为 Linux 内存获取设计的工具更加法医可靠。

为了在 Android 上使用 LiME，必须为设备上使用的内核进行交叉编译。在接下来的章节中，我们将展示如何在 Nexus 4 上为 Android 4.4.4 执行这些步骤（不过，这种方法可以适配到任何 Android 设备，只要该设备的内核——或者至少是内核配置——作为开源提供）。

首先，我们需要在实验室系统上安装一些额外的软件包，具体如下：

```
user@lab:~$ sudo apt-get install bison g++-multilib git gperf libxml2-utils make python-networkx zlib1g-dev:i386 zip openjdk-7-jdk

```

安装完所有必要的软件包后，我们现在需要配置对 USB 设备的访问。在 GNU/Linux 系统下，普通用户默认无法直接访问 USB 设备。系统需要配置以允许这种访问。通过以 root 用户身份创建名为 `/etc/udev/rules.d/51-android.rules` 的文件，并在其中插入以下内容来实现这一点：

```
# adb protocol on passion (Nexus One)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4e12", MODE="0600", OWNER="user"
# fastboot protocol on passion (Nexus One)
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", ATTR{idProduct}=="0fff", MODE="0600", OWNER="user"
# adb protocol on crespo/crespo4g (Nexus S)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4e22", MODE="0600", OWNER="user"
# fastboot protocol on crespo/crespo4g (Nexus S)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4e20", MODE="0600", OWNER="user"
# adb protocol on stingray/wingray (Xoom)
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", ATTR{idProduct}=="70a9", MODE="0600", OWNER="user"
# fastboot protocol on stingray/wingray (Xoom)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="708c", MODE="0600", OWNER="user"
# adb protocol on maguro/toro (Galaxy Nexus)
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", ATTR{idProduct}=="6860", MODE="0600", OWNER="user"
# fastboot protocol on maguro/toro (Galaxy Nexus)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4e30", MODE="0600", OWNER="user"
# adb protocol on panda (PandaBoard)
SUBSYSTEM=="usb", ATTR{idVendor}=="0451", ATTR{idProduct}=="d101", MODE="0600", OWNER="user"
# adb protocol on panda (PandaBoard ES)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="d002", MODE="0600", OWNER="user"
# fastboot protocol on panda (PandaBoard)
SUBSYSTEM=="usb", ATTR{idVendor}=="0451", ATTR{idProduct}=="d022", MODE="0600", OWNER="user"
# usbboot protocol on panda (PandaBoard)
SUBSYSTEM=="usb", ATTR{idVendor}=="0451", ATTR{idProduct}=="d00f", MODE="0600", OWNER="user"
# usbboot protocol on panda (PandaBoard ES)
SUBSYSTEM=="usb", ATTR{idVendor}=="0451", ATTR{idProduct}=="d010", MODE="0600", OWNER="user"
# adb protocol on grouper/tilapia (Nexus 7)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4e42", MODE="0600", OWNER="user"
# fastboot protocol on grouper/tilapia (Nexus 7)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4e40", MODE="0600", OWNER="user"
# adb protocol on manta (Nexus 10)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4ee2", MODE="0600", OWNER="user"
# fastboot protocol on manta (Nexus 10)
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4ee0", MODE="0600", OWNER="user"
```

现在最耗时的部分来了——检查正在使用的 Android 版本的源代码。根据硬盘和互联网连接的速度，这一步可能需要几个小时，因此请提前规划。此外，请记住源代码文件非常大，所以请使用至少 40 GB 空闲空间的第二个分区。我们按如下方式安装 Android 4.4.4 的源代码：

```
user@lab:~$ mkdir ~/bin

user@lab:~$ PATH=~/bin:$PATH

user@lab:~$ curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo

user@lab:~$ chmod a+x ~/bin/repo

user@lab:~$ repo init -u https://android.googlesource.com/platform/manifest -b android-4.4.4_r1

user@lab:~$ repo sync

```

在我们安装了 Android 4.4.4 的源代码之后，我们现在需要设备上运行的内核源代码。对于我们在此使用的 Nexus 4，正确的内核是 **mako** 内核。可以在 [`source.android.com/source/building-kernels.html`](http://source.android.com/source/building-kernels.html) 找到所有可用的 Google 手机内核的列表。

```
user@lab:~$ git clone https://android.googlesource.com/device/lge/mako-kernel/kernel

user@lab:~$ git clone https://android.googlesource.com/kernel/msm.git

```

现在我们已经获得了交叉编译 LiME 所需的所有源代码，接下来是获取 LiME 本身：

```
user@lab:~$ git clone https://github.com/504ensicsLabs/LiME.git

```

在将 `git` 仓库克隆到实验机器上之后，我们需要设置一些在构建过程中需要的环境变量：

```
user@lab:~$ export SDK_PATH=/path/to/android-sdk-linux/

user@lab:~$ export NDK_PATH=/path/to/android-ndk/

user@lab:~$ export KSRC_PATH=/path/to/kernel-source/

user@lab:~$ export CC_PATH=$NDK_PATH/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86/bin/

user@lab:~$ export LIME_SRC=/path/to/lime/src

```

接下来，我们需要获取目标设备的当前内核配置，并将其复制到 LiME 源代码的正确位置。在我们的 Nexus 4 上，可以通过输入以下命令来完成：

```
user@lab:~$ adb pull /proc/config.gz

user@lab:~$ gunzip ./config.gz

user@lab:~$ cp config $KSRC_PATH/.config

user@lab:~$ cd $KSRC_PATH 

user@lab:~$ make ARCH=arm CROSS_COMPILE=$CC_PATH/arm-eabi-modules_prepare

```

在我们构建 LiME 内核模块之前，我们需要编写我们定制的 Makefile：

```
obj-m := lime.o
lime-objs := main.o tcp.o disk.o
KDIR := /path/to/kernel-source
PWD := $(shell pwd)
CCPATH := /path/to/android-ndk/toolchains/arm-linux-androideabi-4.4.4/prebuilt/linux-x86/bin/
default:
 $(MAKE) ARCH=arm CROSS_COMPILE=$(CCPATH)/arm-eabi- -C $(KDIR) M=$(PWD) modules
```

借助这个 Makefile，我们可以构建从 Android 设备中提取易失性内存所需的内核模块。输入 `make` 可以启动该过程。

在接下来的示例中，我们将演示如何将我们新生成的内核模块推送到目标设备，并通过 TCP 将整个易失性内存转储到我们的实验环境中。

如果你的设备的内核不允许动态加载模块，你应该考虑创建自己的恢复镜像（例如，定制版的 **TWRP** 或 **CWM**），将 LiME 内核模块包含其中，并将其刷入相关设备。如果在刷机操作过程中足够快速，几乎不会丢失数据（更多信息，请参考 [`www1.informatik.uni-erlangen.de/frost`](https://www1.informatik.uni-erlangen.de/frost)）。

LiME 模块提供了三种不同的镜像格式，可用于将捕获的内存镜像保存到磁盘上：raw、padded 和 lime。第三种格式——lime——在本文中将详细讨论，因为它是我们首选的格式。lime 格式专门开发用于与 Volatility 配合使用，旨在使得使用 Volatility 进行分析变得更加简便，且为处理该格式，增加了特定的地址空间。基于 lime 格式的每个内存转储都有一个固定大小的头部，包含每个内存范围的特定地址空间信息。这消除了仅为了填充未映射或内存映射 I/O 区域而需要额外填充的需求。LiME 头部规范如下所示：

```
typedef struct {
  unsigned int magic;         // Always 0x4C694D45 (LiME)
  unsigned int version;         // Header version number
  unsigned long long s_addr;     // Starting address of physical RAM
  unsigned long long e_addr;     // Ending address of physical RAM
  unsigned char reserved[8];     // Currently all zeros
  } __attribute__ ((__packed__)) lime_mem_range_header;
```

要从相关 Android 设备获取这样的转储，首先通过`adb`连接到 Android 设备，然后输入以下命令：

```
user@lab:~$ adb push lime.ko /sdcard/lime.ko
user@lab:~$ adb forward tcp:4444 tcp:4444
user@lab:~$ adb shell
nexus4:~$ su
nexus4:~$ insmod /sdcard/lime.ko "path=tcp:4444 format=lime"

```

在实验室机器上，输入以下命令，以接受通过 TCP 端口 4444 从 Android 设备发送到本地实验室机器的数据：

```
user@lab:~$ nc localhost 4444 > nexus4_ram.lime

```

如果前述命令执行成功，您将得到一个 RAM 转储文件，可以借助 Volatility 或其他工具进行进一步分析（请参见下一节）。

## Android 的 Volatility

在通过我们在上一节中创建的工具获取表示目标系统物理内存的转储文件后，我们打算从中提取数据工件。如果不对 Android 的内存结构进行深入分析，我们只能提取已知的文件格式，如 JPEG，或仅提取包含 EXIF 数据的 JPEG 头部（使用工具如**PhotoRec**），或者提取存储为连续格式的简单 ASCII 字符串（使用常见的 Linux 工具如**strings**），这些字符串可以用来对相关设备的密码进行暴力破解。这种方法非常有限，因为它适用于任何磁盘或内存转储，但并不专注于操作系统和应用程序特定的结构。由于我们打算从 Android 系统中提取完整的数据对象，因此我们将使用流行的易失性内存取证框架：**Volatility**。

在本节中，我们将使用一个支持 ARM 架构的 Volatility 版本（至少需要版本 2.3）。给定一个内存镜像，Volatility 可以提取正在运行的进程、打开的网络套接字、每个进程的内存映射以及内核模块。

### 注意

在分析内存镜像之前，必须创建一个 Volatility 配置文件，并将其作为命令行参数传递给 Volatility 框架。这样的 Volatility 配置文件是一组**vtype**定义和可选的符号地址，Volatility 用它们来定位敏感信息并解析。

基本上，配置文件是一个压缩档案，其中包含以下两个文件：

+   `System.map`文件包含 Linux 内核中静态数据结构的符号名称和地址。对于 Android 设备，该文件可以在内核编译后，在内核源码树中找到。

+   `module.dwarf`文件是在编译模块并针对目标内核提取 DWARF 调试信息时生成的。

为了创建`module.dwarf`文件，需要使用名为`dwarfdump`的工具。Volatility 源代码树中包含`tools/linux`目录。如果在该目录下运行`make`命令，该命令会编译模块并生成所需的 DWARF 文件。创建实际的配置文件只需运行以下命令：

```
user@lab $ zip Nexus4.zip module.dwarf System.map

```

生成的 ZIP 文件需要复制到`volatility/plugins/overlays/linux`目录下。成功复制文件后，配置文件将在 Volatility 帮助输出的配置文件部分显示。

尽管 Volatility 对 Android 的支持相对较新，但已有大量的 Linux 插件在 Android 上也能完美运行。例如：

+   `linux_pslist`：它枚举系统中所有正在运行的进程，类似于 Linux 的 ps 命令

+   `linux_ifconfig`：该插件模拟 Linux 的`ifconfig`命令

+   `linux_route_cache`：它读取并打印路由缓存，存储最近使用的路由条目在哈希表中的信息

+   `linux_proc_maps`：该插件获取每个独立进程的内存映射

如果你对如何编写自定义 Volatility 插件并解析**达尔文虚拟机**（**DVM**）中的未知结构感兴趣，请查看我和我的同事所写的以下论文：*冷启动 Android 设备的事后内存分析*（参考[`www1.informatik.uni-erlangen.de/filepool/publications/android.ram.analysis.pdf`](https://www1.informatik.uni-erlangen.de/filepool/publications/android.ram.analysis.pdf)）。

在下一部分，我们将示范如何借助 LiME 和 Volatility 重建特定的应用数据。

## 为 Android 重建数据

现在，我们将展示如何在 Volatility 的帮助下以及通过自定义插件重建应用程序数据。因此，我们选择了通话历史和键盘缓存。如果你正在调查一个普通的 Linux 或 Windows 系统，已经有大量的插件可以使用，正如你将在本章的最后部分看到的那样。不幸的是，在 Android 上，你必须编写自己的插件。

### 通话历史

我们的目标之一是从 Android 内存转储中恢复最近的来电和去电电话列表。此列表在打开电话应用时加载。负责电话应用和通话历史记录的进程是`com.android.contacts`。该进程加载`PhoneClassDetails.java`类文件，该文件建模了所有电话通话的数据，保存在历史结构中。每个历史记录条目对应一个类实例。每个实例的数据字段是电话的典型元信息，如下所示：

+   类型（来电、去电或未接）

+   时长

+   日期和时间

+   电话号码

+   联系人姓名

+   联系人指定的照片

为了自动提取并显示这些元数据，我们提供了一个 Volatility 插件，名为`dalvik_app_calllog`，如下所示：

```
class dalvik_app_calllog(linux_common.AbstractLinuxCommand):

     def __init__(self, config, *args, **kwargs):
          linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
          dalvik.register_option_PID(self._config)
          dalvik.register_option_GDVM_OFFSET(self._config)
          self._config.add_option('CLASS_OFFSET', short_option = 'c', default = None,
          help = 'This is the offset (in hex) of system class PhoneCallDetails.java', action = 'store', type = 'str')

     def calculate(self):
          # if no gDvm object offset was specified, use this one
          if not self._config.GDVM_OFFSET:
               self._config.GDVM_OFFSET = str(hex(0x41b0))

          # use linux_pslist plugin to find process address space and ID if not specified
          proc_as = None
          tasks = linux_pslist.linux_pslist(self._config).calculate()
          for task in tasks:
               if str(task.comm) == "ndroid.contacts":
                    proc_as = task.get_process_address_space()
                    if not self._config.PID:
                         self._config.PID = str(task.pid)
                    break

          # use dalvik_loaded_classes plugin to find class offset if not specified
          if not self._config.CLASS_OFFSET:
              classes = dalvik_loaded_classes.dalvik_loaded_classes(self._config).calculate()
              for task, clazz in classes:
                   if (dalvik.getString(clazz.sourceFile)+"" == "PhoneCallDetails.java"):
                        self._config.CLASS_OFFSET = str(hex(clazz.obj_offset))
                        break

          # use dalvik_find_class_instance plugin to find a list of possible class instances
          instances = dalvik_find_class_instance.dalvik_find_class_instance(self._config).calculate()
          for sysClass, inst in instances:
               callDetailsObj = obj.Object('PhoneCallDetails', offset = inst, vm = proc_as)
               # access type ID field for sanity check
               typeID = int(callDetailsObj.callTypes.contents0)
               # valid type ID must be 1,2 or 3
               if (typeID == 1 or typeID == 2 or typeID == 3):
                    yield callDetailsObj

     def render_text(self, outfd, data):
          self.table_header(outfd, [    ("InstanceClass", "13"),
                                        ("Date", "19"),
                                        ("Contact", "20"),
                                        ("Number", "15"),
                                        ("Duration", "13"),
                                        ("Iso", "3"),
                                        ("Geocode", "15"),
                                        ("Type", "8")                                      
                                        ])
          for callDetailsObj in data:
               # convert epoch time to human readable date and time
               rawDate = callDetailsObj.date / 1000
               date =    str(time.gmtime(rawDate).tm_mday) + "." + \
                         str(time.gmtime(rawDate).tm_mon) + "." + \
                         str(time.gmtime(rawDate).tm_year) + " " + \
                         str(time.gmtime(rawDate).tm_hour) + ":" + \
                         str(time.gmtime(rawDate).tm_min) + ":" + \
                         str(time.gmtime(rawDate).tm_sec)

               # convert duration from seconds to hh:mm:ss format
               duration =     str(callDetailsObj.duration / 3600) + "h " + \
                              str((callDetailsObj.duration % 3600) / 60) + "min " + \
                              str(callDetailsObj.duration % 60) + "s"

               # replace call type ID by string
               callType = int(callDetailsObj.callTypes.contents0)
               if callType == 1:
                    callType = "incoming"
               elif callType == 2:
                    callType = "outgoing"
               elif callType == 3:
                    callType = "missed"
               else:
                    callType = "unknown"

               self.table_row(     outfd,
                                   hex(callDetailsObj.obj_offset),
                                   date,
                                   dalvik.parseJavaLangString(callDetailsObj.name.dereference_as('StringObject')),
                                   dalvik.parseJavaLangString(callDetailsObj.formattedNumber.dereference_as('StringObject')),
                                   duration,               
                                   dalvik.parseJavaLangString(callDetailsObj.countryIso.dereference_as('StringObject')),
                                   dalvik.parseJavaLangString(callDetailsObj.geoCode.dereference_as('StringObject')),
                                   callType)
```

该插件接受以下命令行参数：

+   `-o`：用于指向 gDvm 对象的偏移量

+   `-p`：用于进程 ID（PID）

+   `-c`：用于指向 PhoneClassDetails 类的偏移量

如果知道并传递这些参数给插件，插件的运行时间将显著减少。否则，插件必须在 RAM 中自行查找这些值。

### 键盘缓存

现在，我们想查看默认键盘应用程序的缓存。假设在解锁屏幕后没有其他输入，并且智能手机受 PIN 保护，则该 PIN 等于最后的用户输入，可以在 Android 内存转储中找到该输入作为 UTF-16 Unicode 字符串。最后的用户输入的 Unicode 字符串是由`com.android.inputmethod.latin`进程中的`RichInputConnection`类创建的，并存储在名为`mCommittedTextBeforeComposingText`的变量中。这个变量就像一个键盘缓冲区，存储了屏幕键盘最后输入并确认的按键。为了恢复最后的用户输入，我们提供了一个 Volatility 插件，名为`dalvik_app_lastInput`，如下所示：

```
class dalvik_app_lastInput(linux_common.AbstractLinuxCommand):

     def __init__(self, config, *args, **kwargs):
          linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
          dalvik.register_option_PID(self._config)
          dalvik.register_option_GDVM_OFFSET(self._config)
          self._config.add_option('CLASS_OFFSET', short_option = 'c', default = None,
          help = 'This is the offset (in hex) of system class RichInputConnection.java', action = 'store', type = 'str')

     def calculate(self):

          # if no gDvm object offset was specified, use this one
          if not self._config.GDVM_OFFSET:
               self._config.GDVM_OFFSET = str(0x41b0)

          # use linux_pslist plugin to find process address space and ID if not specified
          proc_as = None     
          tasks = linux_pslist.linux_pslist(self._config).calculate()
          for task in tasks:
               if str(task.comm) == "putmethod.latin":                    
                    proc_as = task.get_process_address_space()
                    self._config.PID = str(task.pid)
                    break

          # use dalvik_loaded_classes plugin to find class offset if not specified
          if not self._config.CLASS_OFFSET:
              classes = dalvik_loaded_classes.dalvik_loaded_classes(self._config).calculate()
              for task, clazz in classes:
                   if (dalvik.getString(clazz.sourceFile)+"" == "RichInputConnection.java"):
                        self._config.CLASS_OFFSET = str(hex(clazz.obj_offset))
                        break

          # use dalvik_find_class_instance plugin to find a list of possible class instances
          instance = dalvik_find_class_instance.dalvik_find_class_instance(self._config).calculate()
          for sysClass, inst in instance:
               # get stringBuilder object
               stringBuilder = inst.clazz.getJValuebyName(inst, "mCommittedTextBeforeComposingText").Object.dereference_as('Object')
               # get superclass object
               abstractStringBuilder = stringBuilder.clazz.super.dereference_as('ClassObject')

               # array object of super class
               charArray = abstractStringBuilder.getJValuebyName(stringBuilder, "value").Object.dereference_as('ArrayObject')
               # get length of array object
               count = charArray.length
               # create string object with content of the array object
               text = obj.Object('String', offset = charArray.contents0.obj_offset,
               vm = abstractStringBuilder.obj_vm, length = count*2, encoding = "utf16")
               yield inst, text

     def render_text(self, outfd, data):
          self.table_header(outfd, [    ("InstanceClass", "13"),
                                        ("lastInput", "20")                                 
                                        ])
          for inst, text in data:

               self.table_row(     outfd,
                                   hex(inst.obj_offset),
                                   text)
```

实际上，这个插件不仅恢复 PIN 码，还恢复最后一次给出的任意用户输入；在许多情况下，这可能是数字证据中的一个有趣的证据。与前面的插件类似，它接受相同的三个命令行参数：`gDvm offset`、`PID`和`class file offset`。如果这些参数中的任何一个或全部没有提供，插件也可以自动确定缺失的值。

# 在 Linux 上使用 Volatility

在接下来的部分，我们将介绍内存获取技术和使用 Volatility 进行 Linux 内存取证的示例用例。

## 内存获取

如果系统未虚拟化，因此无法从虚拟化层直接获取内存；即使在 Linux 系统中，我们首选的工具仍然是 LiME。

然而，与 Android 不同的是，工具的安装和操作要简单得多，因为我们直接在 Linux 系统上生成并运行 LiME；但正如你将在接下来的段落中注意到的，许多步骤是非常相似的。

首先，确定正在分析的系统上运行的确切内核版本。如果没有足够的文档支持，可以运行以下命令来获取内核版本：

```
user@forensic-target $ uname –a
Linux forensic-target 3.2.0-88-generic #126-Ubuntu SMP Mon Jul 6 21:33:03 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

```

### 提示

**在企业环境中使用配置管理**

企业环境中通常运行配置管理系统，能够显示目标系统的内核版本和 Linux 发行版。要求客户提供这些数据，甚至是提供一台具有相同内核版本和软件环境的系统，能够帮助你减少 LiME 模块与取证目标之间的兼容性风险。

在实验环境中，准备 LiME 内核模块进行内存采集。要编译该模块，请确保你拥有正确版本的目标内核源代码，然后在 LiME 的`src`目录中执行以下构建命令：

```
user@lab src $ make -C /usr/src/linux-headers-3.2.0-88-generic M=$PWD

```

这应在当前目录中创建`lime.ko`模块。

在目标系统上，可以使用这个内核模块将内存转储到磁盘，如下所示：

```
user@forensic-target $ sudo insmod lime.ko path=/path/to/dump.lime format=lime

```

### 注意

我们建议选择网络路径来写入镜像。这样，做出的本地系统更改会很少。也可以通过网络传输镜像。只需按照*在 Android 上使用 Volatility*部分中的描述操作。

## Linux 上的 Volatility

Volatility 提供了各种*配置文件*。这些配置文件由 Volatility 用于解释内存转储。不幸的是，由于 Linux 内核、系统架构和内核配置的种类繁多，无法为所有版本的 Linux 内核提供配置文件。

### 提示

**列出所有 Volatility 配置文件**

可以通过`vol.py --info`命令获取所有可用配置文件的列表。

因此，可能需要创建你自己的配置文件，以便与取证目标完美匹配。Volatility 框架通过提供一个虚拟模块来支持这一步骤，该模块必须针对目标系统的内核头文件进行编译。这个模块可以在 Volatility 分发版中的`tools/linux`子目录找到。将其编译——类似于 LiME——但启用调试设置：

```
user@lab src $ make -C /usr/src/linux-headers-3.2.0-88-generic CONFIG_DEBUG_INFO=y M=$PWD

```

这将创建`module.ko`。无需加载此模块；我们所需要的是其调试信息。我们使用`dwarfdump`工具，该工具在大多数 Linux 发行版中作为安装包提供，用于提取这些调试信息：

```
user@lab $ dwarfdump -di module.ko > module.dwarf

```

创建我们配置文件的下一步是获取目标系统或具有相同架构、内核版本和内核配置的系统的`System.map`文件。`System.map`文件通常位于`/boot`目录中。通常，内核版本会包含在文件名中，因此务必选择适用于取证目标系统运行内核的`System.map`文件。

将`module.dwarf`和`System.map`放入一个压缩档案中，这将成为我们的 Volatility 配置文件，如下所示：

```
user@lab $ zip Ubuntu3.2.0-88.zip module.dwarf System.map

```

如示例所示，ZIP 文件的名称应反映发行版和内核版本。

### 注意

确保不要向压缩档案中添加额外的路径信息。否则，Volatility 可能无法加载配置文件数据。

将新配置文件复制到 Volatility 的 Linux 配置文件目录，如下所示：

```
user@lab $ sudo cp Ubuntu3.2.0-88.zip /usr/local/lib/python2.7/dist-packages/volatility-2.4-py2.7.egg/volatility/plugins/overlays/linux/

```

除了使用系统范围的配置文件目录外，你还可以选择一个新的目录，并将`--plugins=/path/to/profiles`选项添加到 Volatility 命令行。

最后，你需要获取新配置文件的名称以供进一步使用。因此，使用以下命令：

```
user@lab $ vol.py --info

```

输出应包含一行额外的内容，显示新的配置文件，如下所示：

```
Profiles
--------
LinuxUbuntu3_2_0-88x64 - A Profile for Linux Ubuntu3.2.0-88 x64

```

要使用此配置文件，请在所有后续调用`vol.py`时，作为命令行参数添加`--profile=LinuxUbuntu3_2_0-88x64`。

## 重建 Linux 的数据

所有分析 Linux 内存转储的插件都有`linux_`前缀。因此，你应使用 Linux 版本的插件。否则，可能会出现错误消息，提示所选配置文件不支持该模块。

### 分析进程和模块

分析内存转储的一个典型第一步是列出所有正在运行的进程和加载的内核模块。

以下是如何通过 Volatility 从内存转储中提取所有正在运行的进程：

```
user@lab $ vol.py --profile=LinuxUbuntu3_2_0-88x64 --file=memDump.lime linux_pslist
Volatility Foundation Volatility Framework 2.4

Offset             Name                 Pid             Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- ------ ------------------ ----------
0xffff8802320e8000 init                 1               0               0      0x000000022f6c0000 2015-08-16 09:51:21 UTC+0000
0xffff8802320e9700 kthreadd             2               0               0      ------------------ 2015-08-16 09:51:21 UTC+0000

0xffff88022fbc0000 cron                 2500            0               0      0x000000022cd38000 2015-08-16 09:51:25 UTC+0000
0xffff88022fbc1700 atd                  2501            0               0      0x000000022fe28000 2015-08-16 09:51:25 UTC+0000
0xffff88022f012e00 irqbalance           2520            0               0      0x000000022df39000 2015-08-16 09:51:25 UTC+0000
0xffff8802314b5c00 whoopsie             2524            105             114    0x000000022f1b0000 2015-08-16 09:51:25 UTC+0000
0xffff88022c5c0000 freshclam            2598            119             131    0x0000000231fa7000 2015-08-16 09:51:25 UTC+0000

```

如输出所示，`linux_pslist`插件通过描述活动进程来迭代内核结构，即它从`init_task`符号开始，迭代`task_struct->tasks`链表。该插件获取所有正在运行的进程的列表，包括它们在内存中的偏移地址、进程名称、进程 ID（PID）、进程的用户和组的数值 ID（UID 和 GID），以及启动时间。**目录表基址**（**DTB**）可用于进一步分析，将物理地址转换为虚拟地址。空的 DTB 条目最有可能与内核线程相关。例如，在我们的示例输出中是`kthreadd`。

### 分析网络信息

内存转储包含有关法医目标系统网络活动的各种信息。以下示例展示了如何利用 Volatility 推导出最近的网络活动信息。

**地址解析协议**（**ARP**）**缓存**用于将 MAC 地址映射到 IP 地址。在建立*本地网络*上的网络通信之前，Linux 内核会发送 ARP 请求以获取给定目标 IP 地址对应的 MAC 地址信息。响应会被缓存到内存中，以便重新使用并与该 IP 地址在本地网络上进一步通信。因此，ARP 缓存条目指示了法医目标系统与本地网络上的哪些系统进行了通信。

要从 Linux 内存转储中读取 ARP 缓存，请使用以下命令：

```
user@lab $ vol.py --profile=LinuxUbuntu3_2_0-88x64 --file=memDump.lime linux_arp
[192.168.167.22                            ] at 00:00:00:00:00:00    on eth0
[192.168.167.20                            ] at b8:27:eb:01:c2:8f    on eth0

```

该输出提取显示系统为目标地址`192.168.167.20`保留了一个缓存条目，对应的 MAC 地址是`b8:27:eb:01:c2:8f`。第一个条目很可能是由于一次不成功的通信尝试而产生的缓存条目，也就是说，`192.168.167.22`的通信伙伴没有对系统发出的 ARP 请求做出响应，因此，相应的 ARP 缓存条目保持其初始值`00:00:00:00:00:00`。可能是通信伙伴无法访问，或者它根本不存在。

### 注意

如果你在 ARP 缓存中看到本地子网的大部分系统显示出多个 MAC 地址为 00:00:00:00:00:00 的条目，那么这表明存在扫描活动，也就是说，系统尝试在本地网络上探测其他系统。

为了进一步的网络分析，可能值得将从 ARP 缓存中获取的 MAC 地址列表与本地子网中应该存在的系统进行对比。虽然这种方法并非万无一失（因为 MAC 地址可以伪造），但它可能有助于发现不明的网络设备。

### 注意

**查找 MAC 地址的硬件供应商**

MAC 地址的前缀揭示了相应网络硬件的硬件供应商。像[`www.macvendorlookup.com`](http://www.macvendorlookup.com)这样的网站提供了网络卡硬件供应商的相关信息。

如果我们查找示例中`b8:27:eb:01:c2:8f` MAC 地址的硬件供应商，它显示该设备是由树莓派基金会制造的。在标准的办公室或数据中心环境中，这些嵌入式设备很少使用，因此检查该设备是否为良性设备是非常值得的。

为了概览创建内存转储时的网络活动，Volatility 提供了模拟 `linux_netstat` 命令的方法，如下所示：

```
user@lab $ vol.py --profile=LinuxUbuntu3_2_0-88x64 --file=memDump.lime linux_netstat
TCP      192.168.167.21  :55622 109.234.207.112  :  143 ESTABLISHED           thunderbird/3746
UNIX 25129          thunderbird/3746
TCP      0.0.0.0         : 7802 0.0.0.0         :    0 LISTEN                      skype/3833

```

这三行只是该命令典型输出的一个小片段。第一行显示 `thunderbird` 进程（PID 为 `3746`）与 IMAP 服务器（TCP 端口 `143`）通过 `109.234.207.112` IP 地址建立了一个活动的 `ESTABLISHED` 网络连接。第二行仅显示一个 UNIX 类型的套接字，用于**进程间通信**（**IPC**）。最后一行显示 `skype`（PID 为 `3833`）正在等待 `LISTEN` 状态，准备接收来自 TCP 端口 `7802` 的传入连接。

Volatility 还可以用来将进程列表缩小到那些具有原始网络访问权限的进程。通常，这种访问仅对**动态主机配置协议**（**DHCP**）客户端、网络诊断工具以及当然的恶意软件有用，目的是在网络接口上构造任意数据包，例如进行所谓的 ARP 缓存中毒攻击。以下展示了如何列出具有原始网络套接字的进程：

```
user@lab $ vol.py --profile=LinuxUbuntu3_2_0-88x64 --file=memDump.lime linux_list_raw
Process          PID    File Descriptor Inode 
---------------- ------ --------------- ------------------
dhclient           2817               5              15831

```

这里，仅检测到 DHCP 客户端拥有原始网络访问权限。

### 提示

**Rootkit 检测模块**

Volatility 提供了多种机制来检测典型的 rootkit 行为，例如中断钩取、网络栈的操作和隐藏的内核模块。我们建议熟悉这些模块，因为它们可以加速你的分析。此外，定期检查模块更新，以利用 Volatility 内置的新恶意软件检测机制。

一些通用的方法和启发式技术用于恶意软件检测，并已结合在`linux_malfind`模块中。该模块会查找可疑的进程内存映射，并生成可能恶意进程的列表。

### 使用 YARA 进行恶意软件狩猎

**YARA** 本身是一个工具，能够在任意文件和数据集中的匹配给定的模式。相应的规则，也称为签名，是在硬盘或内存转储中搜索已知恶意文件的好方法。

在本节中，我们将展示如何在获取的 Linux 机器内存转储中搜索给定的恶意软件。因此，您可以使用我们将在接下来的内容中讨论的两种不同程序：

+   直接使用 YARA 帮助搜索内存转储

+   使用`linux_yarascan`和 Volatility

第一个选项有一个很大的缺点；正如我们所知，内存转储包含的是通常连续的碎片化数据。这一事实使得如果您在搜索已知签名时遇到失败的风险，因为它们不一定按您搜索的顺序排列。

第二个选项—使用`linux_yarascan`—更具容错性，因为它使用 Volatility 并了解获取的内存转储的结构。借助这些知识，它能够解决碎片化问题并可靠地搜索已知签名。虽然我们在 Linux 上使用`linux_yarascan`，但该模块也可用于 Windows（`yarascan`）和 Mac OS X（`mac_yarascan`）。

该模块的主要功能如下：

+   在内存转储中扫描给定进程以查找给定的 YARA 签名

+   扫描完整的内核内存范围

+   将包含符合给定 YARA 规则的正面结果的内存区域提取到磁盘

输入`vol.py linux_yarascan –h`即可查看完整的命令行选项列表

基本上，您可以通过多种方式进行搜索。使用此模块的最简单方法是通过在内存转储中搜索给定的 URL。可以通过输入以下命令来完成此操作：

```
user@lab $ vol.py --profile=LinuxUbuntu3_2_0-88x64 --file=memDump.lime linux_yarascan –-yara-rules="microsoft.com" --wide

Task: skype pid 3833 rule r1 addr 0xe2be751f
0xe2be751f  6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00   m.i.c.r.o.s.o.f.
0xe2be752f  74 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 79 00   t...c.o.m./.t.y.
0xe2be753f  70 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00   p.o.g.r.a.p.h.y.
0xe2be754f  2f 00 66 00 6f 00 6e 00 74 00 73 00 2f 00 59 00   /.f.o.n.t.s./.Y.
0xe2be755f  6f 00 75 00 20 00 6d 00 61 00 79 00 20 00 75 00   o.u...m.a.y...u.
0xe2be756f  73 00 65 00 20 00 74 00 68 00 69 00 73 00 20 00   s.e...t.h.i.s...
0xe2be757f  66 00 6f 00 6e 00 74 00 20 00 61 00 73 00 20 00   f.o.n.t...a.s...
0xe2be758f  70 00 65 00 72 00 6d 00 69 00 74 00 74 00 65 00   p.e.r.m.i.t.t.e.
0xe2be759f  64 00 20 00 62 00 79 00 20 00 74 00 68 00 65 00   d...b.y...t.h.e.
0xe2be75af  20 00 45 00 55 00 4c 00 41 00 20 00 66 00 6f 00   ..E.U.L.A...f.o.
0xe2be75bf  72 00 20 00 74 00 68 00 65 00 20 00 70 00 72 00   r...t.h.e...p.r.
0xe2be75cf  6f 00 64 00 75 00 63 00 74 00 20 00 69 00 6e 00   o.d.u.c.t...i.n.
0xe2be75df  20 00 77 00 68 00 69 00 63 00 68 00 20 00 74 00   ..w.h.i.c.h...t.
0xe2be75ef  68 00 69 00 73 00 20 00 66 00 6f 00 6e 00 74 00   h.i.s...f.o.n.t.
0xe2be75ff  20 00 69 00 73 00 20 00 69 00 6e 00 63 00 6c 00   ..i.s...i.n.c.l.
0xe2be760f  75 00 64 00 65 00 64 00 20 00 74 00 6f 00 20 00   u.d.e.d...t.o...
Task: skype pid 3833 rule r1 addr 0xedfe1267
0xedfe1267  6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00   m.i.c.r.o.s.o.f.
0xedfe1277  74 00 2e 00 63 00 6f 00 6d 00 2f 00 74 00 79 00   t...c.o.m./.t.y.
0xedfe1287  70 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00   p.o.g.r.a.p.h.y.
0xedfe1297  2f 00 66 00 6f 00 6e 00 74 00 73 00 2f 00 59 00   /.f.o.n.t.s./.Y.
0xedfe12a7  6f 00 75 00 20 00 6d 00 61 00 79 00 20 00 75 00   o.u...m.a.y...u.
0xedfe12b7  73 00 65 00 20 00 74 00 68 00 69 00 73 00 20 00   s.e...t.h.i.s...
0xedfe12c7  66 00 6f 00 6e 00 74 00 20 00 61 00 73 00 20 00   f.o.n.t...a.s...
0xedfe12d7  70 00 65 00 72 00 6d 00 69 00 74 00 74 00 65 00   p.e.r.m.i.t.t.e.
0xedfe12e7  64 00 20 00 62 00 79 00 20 00 74 00 68 00 65 00   d...b.y...t.h.e.
0xedfe12f7  20 00 45 00 55 00 4c 00 41 00 20 00 66 00 6f 00   ..E.U.L.A...f.o.
0xedfe1307  72 00 20 00 74 00 68 00 65 00 20 00 70 00 72 00   r...t.h.e...p.r.
0xedfe1317  6f 00 64 00 75 00 63 00 74 00 20 00 69 00 6e 00   o.d.u.c.t...i.n.
0xedfe1327  20 00 77 00 68 00 69 00 63 00 68 00 20 00 74 00   ..w.h.i.c.h...t.
0xedfe1337  68 00 69 00 73 00 20 00 66 00 6f 00 6e 00 74 00   h.i.s...f.o.n.t.
0xedfe1347  20 00 69 00 73 00 20 00 69 00 6e 00 63 00 6c 00   ..i.s...i.n.c.l.
0xedfe1357  75 00 64 00 65 00 64 00 20 00 74 00 6f 00 20 00   u.d.e.d...t.o...

```

一种更复杂但更实际的方式是搜索给定的 YARA 规则。以下 YARA 规则是用来确定系统是否感染了`Derusbi`恶意软件家族：

```
rule APT_Derusbi_Gen
{
meta:
  author = "ThreatConnect Intelligence Research Team"
strings:
  $2 = "273ce6-b29f-90d618c0" wide ascii
  $A = "Ace123dx" fullword wide ascii
  $A1 = "Ace123dxl!" fullword wide ascii
  $A2 = "Ace123dx!@#x" fullword wide ascii
  $C = "/Catelog/login1.asp" wide ascii
  $DF = "~DFTMP$$$$$.1" wide ascii
  $G = "GET /Query.asp?loginid=" wide ascii
  $L = "LoadConfigFromReg failded" wide ascii
  $L1 = "LoadConfigFromBuildin success" wide ascii
  $ph = "/photoe/photo.asp HTTP" wide ascii
  $PO = "POST /photos/photo.asp" wide ascii
  $PC = "PCC_IDENT" wide ascii
condition:
  any of them
}
```

如果我们将此规则保存为`apt_derusbi_gen.rule`，我们可以通过输入以下命令在获取的内存转储中进行搜索：

```
user@lab $ vol.py --profile=LinuxUbuntu3_2_0-88x64 --file=memDump.lime linux_yarascan --yara-file=apt_derusbi_gen.rule --wide

```

结果只会显示一个简短的预览，您可以通过使用`--size`选项来放大它。

如果您正在调查预定义的场景（例如，如果您已经知道系统已被已知的攻击组攻击），您可以将所有规则复制到一个规则文件中，并一次性在内存转储中搜索该文件中的所有规则。Volatility 和`linux_yarascan`将显示每个匹配的结果及其对应的规则编号。这使得扫描已知恶意行为在内存转储中变得更快。

有大量可用于 YARA 签名的来源，这些来源在野外可用，我们这里只提及一些最重要的来源，以帮助你开始恶意软件猎杀，具体如下：

+   Google Groups 上的 YARA 签名交换组：[`www.deependresearch.org/`](http://www.deependresearch.org/)

+   来自 AlienVault Labs 的签名：[`github.com/AlienVault-Labs/AlienVaultLabs/tree/master/malware_analysis`](https://github.com/AlienVault-Labs/AlienVaultLabs/tree/master/malware_analysis)

+   可以借助 ClamAV 和《恶意软件分析师手册》中的配方 3-3 构建的杀毒软件签名：[`code.google.com/p/malwarecookbook/source/browse/trunk/3/3/clamav_to_yara.py`](https://code.google.com/p/malwarecookbook/source/browse/trunk/3/3/clamav_to_yara.py)

# 摘要

在本章中，我们概述了如何使用 Volatility 框架进行内存取证。在示例中，我们展示了 Android 和 Linux 系统的内存获取技术，并展示了如何在这两个系统上使用 LiME。我们使用 Volatility 获取了有关正在运行的进程、加载的模块、可能的恶意活动和最近的网络活动的信息。后者对于通过网络追踪攻击者的活动非常有用。

在本章的最后一个示例中，我们演示了如何在这样的内存转储中搜索给定的恶意软件签名或其他高度灵活的基于模式的规则。这些 YARA 签名或规则有助于快速识别可疑活动或文件。

此外，我们演示了如何获取 Android 设备的键盘缓存和通话历史。

# 接下来该做什么

如果你想测试从本书中获得的工具和知识，我们给你以下两条建议：

+   创建一个包含两台虚拟机的实验室——**Metasploit**和**Metasploitable**。尝试入侵你的**Metasploitable**系统，并随后进行取证分析。你能重建这次攻击并收集所有的妥协指标吗？

+   获取一些旧的硬盘，这些硬盘已经不再使用，但过去曾经经常使用。对这些硬盘进行取证分析，并尽量重建尽可能多的数据。你能重建这些硬盘上的历史操作吗？

如果你想增强对本书中一些主题的了解，以下几本书是非常好的选择：

+   *实用移动取证* 由 *Satish Bommisetty*、*Rohit Tamma*、*Heather Mahalik*、*Packt Publishing*出版

+   *记忆取证的艺术：在 Windows、Linux 和 Mac 内存中检测恶意软件和威胁* 由 *Michael Hale Ligh*、*Andrew Case*、*Jamie Levy* 和 *AAron Walters* 编写，*Wiley India*出版

+   *数字取证与调查手册* 由 *Eoghan Casey* 编写，*Academic Press*出版

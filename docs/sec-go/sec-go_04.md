# 第四章：法医学

法医学是收集证据以侦测犯罪的过程。数字法医学指的就是寻找数字证据，包括定位可能包含相关信息的异常文件、寻找隐藏数据、确定文件最后修改时间、确定谁发送了邮件、对文件进行哈希处理、收集有关攻击 IP 的信息，或捕获网络通信。

除了法医学，本章还将介绍一个简单的隐写术示例——将档案隐藏在图像中。隐写术是一种将信息隐藏在其他信息中的技巧，使其不易被发现。

哈希处理与法医学相关，详细内容见第六章，*密码学*，而数据包捕获则在第五章，*数据包捕获与注入*中进行讲解。你将在本书的各章中找到可能对法医调查员有用的示例。

在这一章中，你将学习以下内容：

+   文件法医学

+   获取基本文件信息

+   查找大文件

+   查找最近修改的文件

+   读取磁盘的启动扇区

+   网络法医学

+   查找主机名和 IP 地址

+   查找 MX 邮件记录

+   查找主机的名称服务器

+   隐写术

+   将档案隐藏在图像中

+   检测隐藏在图像中的档案

+   生成随机图像

+   创建一个 ZIP 压缩档案

# 文件

文件法医学很重要，因为攻击者可能会留下痕迹，需要在做出更多更改或丢失信息之前收集证据。这包括确定文件的所有者、文件最后修改时间、谁有权限访问文件，并检查文件中是否有隐藏的数据。

# 获取文件信息

让我们从一些简单的内容开始。本程序将打印出关于文件的信息，即文件最后修改时间、文件所有者、文件大小以及文件权限。这也将作为一个良好的测试，确保你的 Go 开发环境已正确设置。

如果调查员发现了异常文件，首先需要检查所有基本的元数据。这将提供关于文件所有者、哪些群组可以访问该文件、文件最后修改时间、是否是可执行文件以及文件的大小等信息。这些信息可能都非常有用。

我们将使用的主要函数是`os.Stat()`。它返回一个`FileInfo`结构体，我们将打印出来。为了调用`os.Stat()`，我们需要在开始时导入`os`包。`os.Stat()`会返回两个变量，这与许多只允许返回一个变量的语言不同。如果你想忽略某个返回变量（如错误），可以使用下划线（`_`）符号代替变量名。

我们导入的`fmt`（格式化输出的缩写）包包含了典型的打印函数，如`fmt.Println()`和`fmt.Printf()`。`log`包包含了`log.Printf()`和`log.Println()`。`fmt`和`log`的区别在于，`log`在消息前会打印一个`时间戳`，并且是线程安全的。

`log`包有一个`fmt`包没有的函数，即`log.Fatal()`，它在打印信息后会立即调用`os.Exit(1)`退出程序。`log.Fatal()`函数对于处理某些错误条件很有用，它会打印错误信息并退出。如果你想要干净的输出并完全控制格式，请使用`fmt`的打印函数。如果你需要在每条消息中附带时间戳，可以使用`log`包的打印函数。在收集法医线索时，记录下每个操作的时间是非常重要的。

在这个例子中，变量在`main`函数之前的独立部分中定义。在这个作用域内的变量对于整个包都是可用的。这意味着每个函数都在同一个文件中，其他文件也在相同目录下，并使用相同的包声明。这个定义变量的方法只是为了展示 Go 语言是如何实现的，它是 Pascal 语言对 Go 的影响之一，此外还有`:=`操作符。将所有变量在顶部明确列出并标明数据类型是很方便的。为了在后面的例子中节省空间，我们将使用*声明并赋值*操作符或`:=`符号。这在编写代码时非常方便，因为你不需要先声明变量类型，编译时会自动推断数据类型。然而，在阅读源代码时，明确声明变量类型有助于读者理解代码。我们也可以将整个`var`声明放入`main`函数内，以进一步限制作用域：

```
package main

import (
   "fmt"
   "log"
   "os"
)

var (
   fileInfo os.FileInfo
   err error
)

func main() {
   // Stat returns file info. It will return
   // an error if there is no file.
   fileInfo, err = os.Stat("test.txt")
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println("File name:", fileInfo.Name())
   fmt.Println("Size in bytes:", fileInfo.Size())
   fmt.Println("Permissions:", fileInfo.Mode())
   fmt.Println("Last modified:", fileInfo.ModTime())
   fmt.Println("Is Directory: ", fileInfo.IsDir())
   fmt.Printf("System interface type: %T\n", fileInfo.Sys())
   fmt.Printf("System info: %+v\n\n", fileInfo.Sys())
}
```

# 查找最大文件

在调查过程中，大文件通常是嫌疑的首选对象。大型数据库转储、密码转储、彩虹表、信用卡缓存、被盗的知识产权以及其他数据常常被存储在一个大型档案中，如果你有合适的工具，这类文件很容易被发现。此外，寻找异常大的图像或视频文件也很有帮助，因为它们可能隐藏有通过隐写术加密的信息。隐写术将在本章进一步讨论。

这个程序将在一个目录及其所有子目录中搜索所有文件，并按文件大小排序。我们将使用`ioutil.ReadDir()`来探索初始目录，以获取作为`os.FileInfo`结构体切片的内容。为了检查文件是否是目录，我们将使用`os.IsDir()`。然后我们将创建一个名为`FileNode`的自定义数据结构来存储所需的信息。我们使用链表来存储文件信息。在将元素插入链表之前，我们会遍历它，找到合适的位置，以保持链表的正确排序。请注意，在像`/`这样的目录上运行程序可能会花费很长时间。尝试使用更具体的目录，比如你的`home`文件夹：

```
package main

import (
   "container/list"
   "fmt"
   "io/ioutil"
   "log"
   "os"
   "path/filepath"
)

type FileNode struct {
   FullPath string
   Info os.FileInfo
}

func insertSorted(fileList *list.List, fileNode FileNode) {
   if fileList.Len() == 0 { 
      // If list is empty, just insert and return
      fileList.PushFront(fileNode)
      return
   }

   for element := fileList.Front(); element != nil; element =    
      element.Next() {
      if fileNode.Info.Size() < element.Value.(FileNode).Info.Size()       
      {
         fileList.InsertBefore(fileNode, element)
         return
      }
   }
   fileList.PushBack(fileNode)
}

func getFilesInDirRecursivelyBySize(fileList *list.List, path string) {
   dirFiles, err := ioutil.ReadDir(path)
   if err != nil {
      log.Println("Error reading directory: " + err.Error())
   }

   for _, dirFile := range dirFiles {
      fullpath := filepath.Join(path, dirFile.Name())
      if dirFile.IsDir() {
         getFilesInDirRecursivelyBySize(
            fileList,
            filepath.Join(path, dirFile.Name()),
         )
      } else if dirFile.Mode().IsRegular() {
         insertSorted(
            fileList,
            FileNode{FullPath: fullpath, Info: dirFile},
         )
      }
   }
}

func main() {
   fileList := list.New()
   getFilesInDirRecursivelyBySize(fileList, "/home")

   for element := fileList.Front(); element != nil; element =   
      element.Next() {
      fmt.Printf("%d ", element.Value.(FileNode).Info.Size())
      fmt.Printf("%s\n", element.Value.(FileNode).FullPath)
   }
}
```

# 查找最近修改的文件

在法医检查受害者机器时，首先可以做的一件事是查找最近被修改的文件。这可能会为你提供关于攻击者查看了哪些地方、修改了哪些设置，或他们的动机是什么的线索。

然而，如果调查员正在检查攻击者的机器，那么目标会有所不同。最近访问的文件可能会提供线索，告诉你攻击者使用了哪些工具，在哪些地方可能隐藏了数据，或者他们使用了什么软件。

以下示例将搜索一个目录及其子目录，找到所有文件，并按最后修改时间排序。这个示例与前一个非常相似，不同之处在于排序是通过使用`time.Time.Before()`函数比较时间戳来完成的：

```
package main

import (
   "container/list"
   "fmt"
   "io/ioutil"
   "log"
   "os"
   "path/filepath"
)

type FileNode struct {
   FullPath string
   Info os.FileInfo
}

func insertSorted(fileList *list.List, fileNode FileNode) {
   if fileList.Len() == 0 { 
      // If list is empty, just insert and return
      fileList.PushFront(fileNode)
      return
   }

   for element := fileList.Front(); element != nil; element = 
      element.Next() {
      if fileNode.Info.ModTime().Before(element.Value.
        (FileNode).Info.ModTime()) {
            fileList.InsertBefore(fileNode, element)
            return
        }
    }

    fileList.PushBack(fileNode)
}

func GetFilesInDirRecursivelyBySize(fileList *list.List, path string) {
    dirFiles, err := ioutil.ReadDir(path)
    if err != nil {
        log.Println("Error reading directory: " + err.Error())
    }

    for _, dirFile := range dirFiles {
        fullpath := filepath.Join(path, dirFile.Name())
        if dirFile.IsDir() {
            GetFilesInDirRecursivelyBySize(
            fileList,
            filepath.Join(path, dirFile.Name()),
            )
        } else if dirFile.Mode().IsRegular() {
           insertSorted(
              fileList,
              FileNode{FullPath: fullpath, Info: dirFile},
           )
        }
    }
}

func main() {
    fileList := list.New()
    GetFilesInDirRecursivelyBySize(fileList, "/")

    for element := fileList.Front(); element != nil; element =    
       element.Next() {
        fmt.Print(element.Value.(FileNode).Info.ModTime())
        fmt.Printf("%s\n", element.Value.(FileNode).FullPath)
    }
}
```

# 读取引导扇区

这个程序将读取磁盘的前 512 字节，并将结果以十进制值、十六进制和字符串的形式打印出来。`io.ReadFull()`函数类似于普通的读取操作，但它确保你提供的数据字节切片被完全填充。如果文件中的字节不足以填充字节切片，它会返回一个错误。

这种方法的实际应用是检查机器的引导扇区，看看它是否被修改。Rootkit 和恶意软件可能通过修改引导扇区劫持引导过程。你可以手动检查其中是否有任何异常，或者将其与已知的良好版本进行比较。也许可以将机器的备份镜像或全新安装的版本与其进行比较，看看是否有所变化。

请注意，技术上你可以传递任何文件名，而不仅仅是磁盘，因为在 Linux 中一切都被视为文件。如果你直接传递设备的名称，例如`/dev/sda`，它将读取磁盘的前`512`字节，即引导扇区。主要的磁盘设备通常是`/dev/sda`，但也可能是`/dev/sdb`或`/dev/sdc`。使用`mount`或`df`工具可以获取更多关于磁盘名称的信息。你需要以`sudo`身份运行该应用程序，以便有权限直接读取磁盘设备。

有关文件、输入和输出的更多信息，请参考`os`、`bufio`和`io`包，如以下代码块所示：

```
package main

// Device is typically /dev/sda but may also be /dev/sdb, /dev/sdc
// Use mount, or df -h to get info on which drives are being used
// You will need sudo to access some disks at this level

import (
   "io"
   "log"
   "os"
)

func main() {
   path := "/dev/sda"
   log.Println("[+] Reading boot sector of " + path)

   file, err := os.Open(path)
   if err != nil {
      log.Fatal("Error: " + err.Error())
   }

   // The file.Read() function will read a tiny file in to a large
   // byte slice, but io.ReadFull() will return an
   // error if the file is smaller than the byte slice.
   byteSlice := make([]byte, 512)
   // ReadFull Will error if 512 bytes not available to read
   numBytesRead, err := io.ReadFull(file, byteSlice)
   if err != nil {
      log.Fatal("Error reading 512 bytes from file. " + err.Error())
   }

   log.Printf("Bytes read: %d\n\n", numBytesRead)
   log.Printf("Data as decimal:\n%d\n\n", byteSlice)
   log.Printf("Data as hex:\n%x\n\n", byteSlice)
   log.Printf("Data as string:\n%s\n\n", byteSlice)
}
```

# 隐写术

隐写术是将信息隐藏在非秘密信息中的技术。不要与速记术混淆，速记术是记录口述内容的技术，比如法庭记录员在庭审过程中将口头发言转录下来。隐写术有着悠久的历史，一个古老的例子是将摩尔斯电码信息缝在衣物的缝线上。

在数字世界中，人们可以将任何类型的二进制数据隐藏在图像、音频或视频文件中。这个过程可能会影响原始文件的质量，也可能不会。一些图像可以完全保持其原始完整性，但它们在表面下隐藏了额外的数据，形式是一个`.zip`或`.rar`压缩包。有些隐写算法比较复杂，将原始二进制数据隐藏在每个字节的最低位，只会略微降低原始质量。其他隐写算法比较简单，仅仅是将图像文件和压缩包合并成一个文件。我们将看看如何将压缩包隐藏在图像中，以及如何检测隐藏的压缩包。

# 生成带有随机噪声的图像

这个程序将创建一张每个像素都设置为随机颜色的 JPEG 图片。这是一个简单的程序，所以我们只有一个 JPEG 图片可以处理。Go 标准库提供了`jpeg`、`gif`和`png`包。所有不同图像类型的接口是相同的，因此从`jpeg`切换到`gif`或`png`包非常简单：

```
package main

import (
   "image"
   "image/jpeg"
   "log"
   "math/rand"
   "os"
)

func main() {
   // 100x200 pixels
   myImage := image.NewRGBA(image.Rect(0, 0, 100, 200))

   for p := 0; p < 100*200; p++ {
      pixelOffset := 4 * p
      myImage.Pix[0+pixelOffset] = uint8(rand.Intn(256)) // Red
      myImage.Pix[1+pixelOffset] = uint8(rand.Intn(256)) // Green
      myImage.Pix[2+pixelOffset] = uint8(rand.Intn(256)) // Blue
      myImage.Pix[3+pixelOffset] = 255 // Alpha
   }

   outputFile, err := os.Create("test.jpg")
   if err != nil {
      log.Fatal(err)
   }

   jpeg.Encode(outputFile, myImage, nil)

   err = outputFile.Close()
   if err != nil {
      log.Fatal(err)
   }
}
```

# 创建 ZIP 压缩包

这个程序将创建一个 ZIP 压缩包，以便我们进行隐写术实验。Go 标准库提供了一个`zip`包，但它也支持通过`tar`包处理 TAR 压缩包。这个示例生成一个包含两个文件的 ZIP 文件：`test.txt`和`test2.txt`。为了简化起见，每个文件的内容在源代码中都作为硬编码字符串给出：

```
package main

import (
   "crypto/md5"
   "crypto/sha1"
   "crypto/sha256"
   "crypto/sha512"
   "fmt"
   "io/ioutil"
   "log"
   "os"
)

func printUsage() {
   fmt.Println("Usage: " + os.Args[0] + " <filepath>")
   fmt.Println("Example: " + os.Args[0] + " document.txt")
}

func checkArgs() string {
   if len(os.Args) < 2 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1]
}

func main() {
   filename := checkArgs()

   // Get bytes from file
   data, err := ioutil.ReadFile(filename)
   if err != nil {
      log.Fatal(err)
   }

   // Hash the file and output results
   fmt.Printf("Md5: %x\n\n", md5.Sum(data))
   fmt.Printf("Sha1: %x\n\n", sha1.Sum(data))
   fmt.Printf("Sha256: %x\n\n", sha256.Sum256(data))
   fmt.Printf("Sha512: %x\n\n", sha512.Sum512(data))
}
```

# 创建隐写图像压缩包

现在我们有了一个图像和一个 ZIP 压缩包，我们可以将它们结合起来，将压缩包“隐藏”在图像内。这可能是最原始的隐写术形式。更高级的方法是将文件逐字节拆分，将信息存储在图像的低位中，使用特定程序从图像中提取数据，然后重建原始数据。这个示例非常好，因为我们可以轻松地测试和验证它是否仍然作为图片加载并且仍然像 ZIP 压缩包一样工作。

以下示例将使用一张 JPEG 图片和一个 ZIP 压缩包，并将它们结合起来创建一个隐藏的压缩包。文件将保留`.jpg`扩展名，仍然会像普通图片一样显示和运作。但是，该文件仍然可以作为 ZIP 压缩包使用。你可以解压`.jpg`文件，压缩包内的文件将被提取出来：

```
package main

import (
   "io"
   "log"
   "os"
)

func main() {
   // Open original file
   firstFile, err := os.Open("test.jpg")
   if err != nil {
      log.Fatal(err)
   }
   defer firstFile.Close()

   // Second file
   secondFile, err := os.Open("test.zip")
   if err != nil {
      log.Fatal(err)
   }
   defer secondFile.Close()

   // New file for output
   newFile, err := os.Create("stego_image.jpg")
   if err != nil {
      log.Fatal(err)
   }
   defer newFile.Close()

   // Copy the bytes to destination from source
   _, err = io.Copy(newFile, firstFile)
   if err != nil {
      log.Fatal(err)
   }
   _, err = io.Copy(newFile, secondFile)
   if err != nil {
      log.Fatal(err)
   }
}

```

# 在 JPEG 图像中检测 ZIP 压缩包

如果使用前面示例中的技术隐藏了数据，可以通过在图像中搜索 ZIP 文件签名来检测。一个文件可能有`.jpg`扩展名，仍然能够在照片查看器中正确加载，但它仍可能包含一个 ZIP 存档。以下程序会遍历文件并查找 ZIP 文件签名。我们可以使用它检查前一个示例中创建的文件：

```
package main

import (
   "bufio"
   "bytes"
   "log"
   "os"
)

func main() {
   // Zip signature is "\x50\x4b\x03\x04"
   filename := "stego_image.jpg"
   file, err := os.Open(filename)
   if err != nil {
      log.Fatal(err)
   }
   bufferedReader := bufio.NewReader(file)

   fileStat, _ := file.Stat()
   // 0 is being cast to an int64 to force i to be initialized as
   // int64 because filestat.Size() returns an int64 and must be
   // compared against the same type
   for i := int64(0); i < fileStat.Size(); i++ {
      myByte, err := bufferedReader.ReadByte()
      if err != nil {
         log.Fatal(err)
      }

      if myByte == '\x50' { 
         // First byte match. Check the next 3 bytes
         byteSlice := make([]byte, 3)
         // Get bytes without advancing pointer with Peek
         byteSlice, err = bufferedReader.Peek(3)
         if err != nil {
            log.Fatal(err)
         }

         if bytes.Equal(byteSlice, []byte{'\x4b', '\x03', '\x04'}) {
            log.Printf("Found zip signature at byte %d.", i)
         }
      }
   }
}
```

# 网络

有时，日志中会出现一个奇怪的 IP 地址，您需要找出更多信息，或者可能有一个域名，您需要根据 IP 地址来进行地理定位。这些示例展示了如何收集主机信息。数据包捕获也是网络取证调查的一个重要部分，但关于数据包捕获有很多可以讨论的内容，因此，第五章，*数据包捕获与注入*专门讲解数据包捕获和注入。

# 从 IP 地址查找主机名

这个程序将接受一个 IP 地址，并找出对应的主机名。`net.parseIP()`函数用于验证提供的 IP 地址，而`net.LookupAddr()`执行实际的工作，找出主机名是什么。

默认情况下，使用的是纯 Go 解析器。可以通过设置`GODEBUG`环境变量中的`netdns`值来覆盖解析器。将`GODEBUG`的值设置为`go`或`cgo`。在 Linux 中，您可以使用以下 Shell 命令进行设置：

```
export GODEBUG=netdns=go # force pure Go resolver (Default)
export GODEBUG=netdns=cgo # force cgo resolver
```

这是程序的代码：

```
package main

import (
   "fmt"
   "log"
   "net"
   "os"
)

func main() {
   if len(os.Args) != 2 {
      log.Fatal("No IP address argument provided.")
   }
   arg := os.Args[1]

   // Parse the IP for validation
   ip := net.ParseIP(arg)
   if ip == nil {
      log.Fatal("Valid IP not detected. Value provided: " + arg)
   }

   fmt.Println("Looking up hostnames for IP address: " + arg)
   hostnames, err := net.LookupAddr(ip.String())
   if err != nil {
      log.Fatal(err)
   }
   for _, hostnames := range hostnames {
      fmt.Println(hostnames)
   }
}
```

# 从主机名查找 IP 地址

以下示例接受一个主机名并返回 IP 地址。它与之前的示例非常相似，但顺序相反。`net.LookupHost()`函数承担了主要工作：

```
package main

import (
   "fmt"
   "log"
   "net"
   "os"
)

func main() {
   if len(os.Args) != 2 {
      log.Fatal("No hostname argument provided.")
   }
   arg := os.Args[1]

   fmt.Println("Looking up IP addresses for hostname: " + arg)

   ips, err := net.LookupHost(arg)
   if err != nil {
      log.Fatal(err)
   }
   for _, ip := range ips {
      fmt.Println(ip)
   }
}
```

# 查找 MX 记录

该程序将接受一个域名并返回 MX 记录。MX 记录（邮件交换记录）是指向邮件服务器的 DNS 记录。例如，[`www.devdungeon.com/`](https://www.devdungeon.com/)的 MX 服务器是`mail.devdungeon.com`。`net.LookupMX()`函数执行此查找并返回一个`net.MX`结构体切片：

```
package main

import (
   "fmt"
   "log"
   "net"
   "os"
)

func main() {
   if len(os.Args) != 2 {
      log.Fatal("No domain name argument provided")
   }
   arg := os.Args[1]

   fmt.Println("Looking up MX records for " + arg)

   mxRecords, err := net.LookupMX(arg)
   if err != nil {
      log.Fatal(err)
   }
   for _, mxRecord := range mxRecords {
      fmt.Printf("Host: %s\tPreference: %d\n", mxRecord.Host,   
         mxRecord.Pref)
   }
}
```

# 查找主机名的 DNS 服务器

该程序将查找与给定主机名相关联的 DNS 服务器。这里的主要功能是`net.LookupNS()`：

```
package main

import (
   "fmt"
   "log"
   "net"
   "os"
)

func main() {
   if len(os.Args) != 2 {
      log.Fatal("No domain name argument provided")
   }
   arg := os.Args[1]

   fmt.Println("Looking up nameservers for " + arg)

   nameservers, err := net.LookupNS(arg)
   if err != nil {
      log.Fatal(err)
   }
   for _, nameserver := range nameservers {
      fmt.Println(nameserver.Host)
   }
}
```

# 总结

阅读完本章后，您应该对数字取证调查的目标有了基本了解。每个主题都可以深入讨论，取证是一个专业领域，值得拥有自己的书籍，更不用说是一个章节了。

使用您阅读过的示例作为起点，思考一下如果您面对一台被攻破的机器，并且您的目标是找出攻击者如何入侵、发生的时间、他们访问了什么、修改了什么、动机是什么、泄露了多少数据以及您能够找到的其他信息，以便识别攻击者身份或其在系统上采取的行动。

一个熟练的对手会尽力掩盖自己的踪迹并避免被取证检测。因此，保持对最新工具和趋势的了解非常重要，这样在调查时你才能知道应该寻找哪些技巧和线索。

这些示例可以扩展、自动化，并集成到其他执行大规模取证搜索的应用程序中。借助 Go 语言的可扩展性，可以轻松创建一个工具，以高效的方式搜索整个文件系统或网络。

在下一章，我们将讨论如何使用 Go 进行数据包捕获。我们将从基本的内容开始，比如获取网络设备列表并将网络流量转储到文件中。接着，我们将讨论如何使用过滤器来查找特定的网络流量。此外，我们还将探讨使用 Go 接口解码和检查数据包的更高级技巧。我们还将介绍如何创建自定义数据包层以及从网络卡伪造和发送数据包，从而允许你发送任意数据包。

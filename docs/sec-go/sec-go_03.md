# 第三章：文件操作

Unix 和 Linux 系统的一个显著特点是将所有内容都视为文件。进程、文件、目录、套接字、设备和管道都被视为文件。鉴于操作系统的这一基本特性，学习如何操作文件是一项关键技能。本章提供了几个不同的文件操作示例。

首先，我们将查看基础知识，即创建、截断、删除、打开、关闭、重命名和移动文件。我们还将查看如何获取有关文件的详细属性，例如权限和所有权、大小和符号链接信息。

本章的一个重要部分专门讨论了从文件中读取和写入数据的不同方式。有多个包含有用函数的包；此外，阅读器和写入器接口支持许多不同的选项，如缓冲读取器和写入器、直接读写、扫描器以及快速操作的辅助函数。

此外，还提供了有关归档和解档、压缩和解压缩、创建临时文件和目录以及通过 HTTP 下载文件的示例。

具体来说，本章将涵盖以下主题：

+   创建空文件和截断文件

+   获取详细的文件信息

+   重命名、移动和删除文件

+   修改权限、所有权和时间戳

+   符号链接

+   多种文件的读写方式

+   存档

+   压缩

+   临时文件和目录

+   通过 HTTP 下载文件

# 文件基础知识

因为文件是计算生态系统中不可或缺的一部分，了解在 Go 中处理文件的选项非常重要。本节涵盖了一些基本操作，如打开、关闭、创建和删除文件。此外，还涉及重命名、移动、检查文件是否存在、修改权限、所有权、时间戳以及处理符号链接。这些示例大多使用了一个硬编码的文件名`test.txt`。如果要操作其他文件，请更改此文件名。

# 创建空文件

在 Linux 中常用的一个工具是**touch**程序。当您需要快速创建具有特定名称的空文件时，经常会使用它。以下示例复制了**touch**的常见用例之一，即创建空文件。

创建空文件的用途有限，但我们可以考虑一个例子。如果有一个服务将日志写入一组旋转的文件。每天会创建一个带有当前日期的新文件，并将当天的日志写入该文件。开发者可能已经非常聪明地为日志文件设置了非常严格的权限，只允许管理员读取。但如果他们在目录上留下了松散的权限呢？如果你创建一个带有第二天日期的空文件会发生什么？服务可能只有在文件不存在时才会创建新文件，但如果文件已经存在，它会使用该文件，而不检查权限。你可以利用这一点，创建一个你有读取权限的空文件。这个文件应该以与服务命名日志文件相同的方式命名。例如，如果服务使用类似 `logs-2018-01-30.txt` 这样的格式来命名日志文件，你可以创建一个名为 `logs-2018-01-31.txt` 的空文件，第二天，服务将写入该文件，因为它已经存在，而你有读取权限，相比之下，如果没有文件存在，服务将创建一个只有 root 用户权限的新文件。

以下是这个示例的代码实现：

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   newFile, err := os.Create("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Println(newFile) 
   newFile.Close() 
} 
```

# 截断文件

截断文件是指将文件修剪到最大长度。截断通常用于完全移除文件的所有内容，但也可以用于限制文件到特定的最大大小。`os.Truncate()` 的一个显著特点是，如果文件小于指定的截断限制，它实际上会增加文件的长度。它会用空字节填充任何空白空间。

截断文件比创建空文件有更多实际用途。当日志文件过大时，可以通过截断来节省磁盘空间。如果你在进行攻击，你可能希望截断 `.bash_history` 和其他日志文件，以掩盖你的痕迹。实际上，恶意行为者可能仅仅是为了销毁数据而截断文件。

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Truncate a file to 100 bytes. If file 
   // is less than 100 bytes the original contents will remain 
   // at the beginning, and the rest of the space is 
   // filled will null bytes. If it is over 100 bytes, 
   // Everything past 100 bytes will be lost. Either way 
   // we will end up with exactly 100 bytes. 
   // Pass in 0 to truncate to a completely empty file 

   err := os.Truncate("test.txt", 100) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 获取文件信息

以下示例将打印出文件的所有元数据。它包括明显的属性，如文件名、大小、权限、最后修改时间以及是否是目录。它包含的最后一项数据是 `FileInfo.Sys()` 接口。该接口包含关于文件底层来源的信息，通常来源于硬盘上的文件系统：

```
package main 

import ( 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   // Stat returns file info. It will return 
   // an error if there is no file. 
   fileInfo, err := os.Stat("test.txt") 
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

# 重命名文件

标准库提供了一个方便的函数来移动文件。重命名和移动是同义词；如果你想将文件从一个目录移动到另一个目录，可以使用 `os.Rename()` 函数，如以下代码块所示：

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   originalPath := "test.txt" 
   newPath := "test2.txt" 
   err := os.Rename(originalPath, newPath) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 删除文件

以下示例很简单，演示了如何删除一个文件。标准库提供了 `os.Remove()`，该函数接受一个文件路径：

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   err := os.Remove("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 打开和关闭文件

打开文件时，有几种选项。当调用`os.Open()`时，只需要文件名，并提供只读文件。另一个选项是使用`os.OpenFile()`，它需要更多的选项。你可以指定是只读文件、只写文件，还是可读写文件。你还可以选择在打开时进行追加、创建（如果文件不存在）或截断。通过逻辑“或”操作符结合所需选项。关闭文件是通过对文件对象调用`Close()`来完成的。你可以显式地关闭文件，或者你也可以延迟调用。有关`defer`关键字的更多细节，请参考第二章，*Go 语言程序设计*。下面的示例没有使用`defer`关键字选项，但后面的示例将会使用：

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Simple read only open. We will cover actually reading 
   // and writing to files in examples further down the page 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   }  
   file.Close() 

   // OpenFile with more options. Last param is the permission mode 
   // Second param is the attributes when opening 
   file, err = os.OpenFile("test.txt", os.O_APPEND, 0666) 
   if err != nil { 
      log.Fatal(err) 
   } 
   file.Close() 

   // Use these attributes individually or combined 
   // with an OR for second arg of OpenFile() 
   // e.g. os.O_CREATE|os.O_APPEND 
   // or os.O_CREATE|os.O_TRUNC|os.O_WRONLY 

   // os.O_RDONLY // Read only 
   // os.O_WRONLY // Write only 
   // os.O_RDWR // Read and write 
   // os.O_APPEND // Append to end of file 
   // os.O_CREATE // Create is none exist 
   // os.O_TRUNC // Truncate file when opening 
} 
```

# 检查文件是否存在

检查文件是否存在是一个两步过程。首先，必须对文件调用`os.Stat()`以获取`FileInfo`。如果文件不存在，则不会返回`FileInfo`结构体，而是返回一个错误。`os.Stat()`可能会返回多种错误，因此必须检查错误类型。标准库提供了一个名为`os.IsNotExist()`的函数，它将检查错误是否因为文件不存在而导致。

如果文件不存在，下面的示例将调用`log.Fatal()`，但你可以优雅地处理错误并继续操作，而无需退出：

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Stat returns file info. It will return 
   // an error if there is no file. 
   fileInfo, err := os.Stat("test.txt") 
   if err != nil { 
      if os.IsNotExist(err) { 
         log.Fatal("File does not exist.") 
      } 
   } 
   log.Println("File does exist. File information:") 
   log.Println(fileInfo) 
} 
```

# 检查读写权限

类似于前面的示例，检查读写权限是通过使用名为`os.IsPermission()`的函数来检查错误完成的。如果传递的错误是由于权限问题引起的，该函数将返回 true，以下例子展示了这一点：

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Test write permissions. It is possible the file 
   // does not exist and that will return a different 
   // error that can be checked with os.IsNotExist(err) 
   file, err := os.OpenFile("test.txt", os.O_WRONLY, 0666) 
   if err != nil { 
      if os.IsPermission(err) { 
         log.Println("Error: Write permission denied.") 
      } 
   } 
   file.Close() 

   // Test read permissions 
   file, err = os.OpenFile("test.txt", os.O_RDONLY, 0666) 
   if err != nil { 
      if os.IsPermission(err) { 
         log.Println("Error: Read permission denied.") 
      } 
   } 
   file.Close()
} 
```

# 更改权限、所有权和时间戳

如果你拥有文件或具有适当的权限，你可以更改所有权、时间戳和权限。标准库提供了一组函数，以下是这些函数：

+   `os.Chmod()`

+   `os.Chown()`

+   `os.Chtimes()`

以下示例演示了如何使用这些函数来更改文件的元数据：

```
package main 

import ( 
   "log" 
   "os" 
   "time" 
) 

func main() { 
   // Change permissions using Linux style 
   err := os.Chmod("test.txt", 0777) 
   if err != nil { 
      log.Println(err) 
   } 

   // Change ownership 
   err = os.Chown("test.txt", os.Getuid(), os.Getgid()) 
   if err != nil { 
      log.Println(err) 
   } 

   // Change timestamps 
   twoDaysFromNow := time.Now().Add(48 * time.Hour) 
   lastAccessTime := twoDaysFromNow 
   lastModifyTime := twoDaysFromNow 
   err = os.Chtimes("test.txt", lastAccessTime, lastModifyTime) 
   if err != nil { 
      log.Println(err) 
   } 
} 
```

# 硬链接和符号链接

一个典型的文件只是硬盘上的一个指针，称为 inode。硬链接会创建指向相同位置的新指针。文件只有在所有指向它的链接被移除后，才会从磁盘中删除。硬链接仅在同一文件系统上有效。硬链接就是你可能认为的“正常”链接。

符号链接，或软链接，稍有不同，它不直接指向磁盘上的位置。符号链接仅通过名称引用其他文件。它们可以指向不同文件系统上的文件。然而，并非所有系统都支持符号链接。

Windows 历史上对符号链接的支持较差，但这些示例已在 Windows 10 Pro 上测试过，若拥有管理员权限，硬链接和符号链接均能正常工作。要以管理员身份从命令行执行 Go 程序，首先通过右键点击命令提示符并选择“以管理员身份运行”打开命令提示符。然后你就可以执行程序，符号链接和硬链接将按预期工作。

以下示例展示了如何创建硬链接和符号链接文件，以及如何判断一个文件是否是符号链接，并在不修改原始文件的情况下修改符号链接文件的元数据：

```
package main 

import ( 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   // Create a hard link 
   // You will have two file names that point to the same contents 
   // Changing the contents of one will change the other 
   // Deleting/renaming one will not affect the other 
   err := os.Link("original.txt", "original_also.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   fmt.Println("Creating symlink") 
   // Create a symlink 
   err = os.Symlink("original.txt", "original_sym.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // Lstat will return file info, but if it is actually 
   // a symlink, it will return info about the symlink. 
   // It will not follow the link and give information 
   // about the real file 
   // Symlinks do not work in Windows 
   fileInfo, err := os.Lstat("original_sym.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Link info: %+v", fileInfo) 

   // Change ownership of a symlink only 
   // and not the file it points to 
   err = os.Lchown("original_sym.txt", os.Getuid(), os.Getgid()) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 读取和写入

读取和写入文件有很多种方法。Go 提供了接口，使得你可以轻松编写与文件或其他读取/写入接口一起工作的函数。

在`os`、`io`和`ioutil`包之间，你可以找到满足你需求的正确函数。这些示例涵盖了许多可用选项。

# 复制文件

以下示例使用`io.Copy()`函数将内容从一个读取器复制到另一个写入器：

```
package main 

import ( 
   "io" 
   "log" 
   "os" 
) 

func main() { 
   // Open original file 
   originalFile, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer originalFile.Close() 

   // Create new file 
   newFile, err := os.Create("test_copy.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer newFile.Close() 

   // Copy the bytes to destination from source 
   bytesWritten, err := io.Copy(newFile, originalFile) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Copied %d bytes.", bytesWritten) 

   // Commit the file contents 
   // Flushes memory to disk 
   err = newFile.Sync() 
   if err != nil { 
      log.Fatal(err) 
   }  
} 
```

# 在文件中寻址

`Seek()`函数用于将文件指针设置到特定位置。默认情况下，它从偏移量 0 开始，并随着读取字节向前移动。你可能想将指针重置回文件开头，或直接跳转到特定位置。`Seek()`函数可以实现这一功能。

`Seek()`函数接受两个参数。第一个参数是距离，表示你想将指针移动多少字节。如果传入正整数，指针会向前移动；如果传入负数，则指针会向后移动。第一个参数是相对值，而不是文件中的绝对位置。第二个参数指定相对位置的起始点，称为`whence`。`whence`参数是相对偏移的参考点。它可以是`0`、`1`或`2`，分别表示文件的开头、当前位置和文件的末尾。

举个例子，如果指定`Seek(-1, 2)`，它会将文件指针从文件末尾向后移动一个字节。`Seek(2, 0)`会将文件指针移动到文件开头后的第二个字节，`file.Seek(5, 1)`会将指针从当前位移向前 5 个字节：

```
package main 

import ( 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   file, _ := os.Open("test.txt") 
   defer file.Close() 

   // Offset is how many bytes to move 
   // Offset can be positive or negative 
   var offset int64 = 5 

   // Whence is the point of reference for offset 
   // 0 = Beginning of file 
   // 1 = Current position 
   // 2 = End of file 
   var whence int = 0 
   newPosition, err := file.Seek(offset, whence) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Just moved to 5:", newPosition) 

   // Go back 2 bytes from current position 
   newPosition, err = file.Seek(-2, 1) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Just moved back two:", newPosition) 

   // Find the current position by getting the 
   // return value from Seek after moving 0 bytes 
   currentPosition, err := file.Seek(0, 1) 
   fmt.Println("Current position:", currentPosition) 

   // Go to beginning of file 
   newPosition, err = file.Seek(0, 0) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Position after seeking 0,0:", newPosition) 
} 
```

# 写入字节到文件

你可以只使用`os`包来进行写操作，它本身就用于打开文件。由于 Go 程序是静态链接的二进制文件，导入的每个包都会增加可执行文件的大小。其他包如`io`、`ioutil`和`bufio`提供了一些额外的帮助，但它们不是必须的：

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Open a new file for writing only 
   file, err := os.OpenFile( 
      "test.txt", 
      os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 
      0666, 
   ) 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer file.Close() 

   // Write bytes to file 
   byteSlice := []byte("Bytes!\n") 
   bytesWritten, err := file.Write(byteSlice) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Wrote %d bytes.\n", bytesWritten) 
} 
```

# 快速写入文件

`ioutil`包有一个非常有用的函数`WriteFile()`，可以处理创建/打开文件、写入字节切片并关闭文件。如果你只是需要快速将字节切片写入文件，这个函数非常方便：

```
package main 

import ( 
   "io/ioutil" 
   "log" 
) 

func main() { 
   err := ioutil.WriteFile("test.txt", []byte("Hi\n"), 0666) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 缓冲写入器

`bufio` 包允许你创建一个缓冲写入器，以便在将数据写入磁盘之前在内存中处理缓冲区。这在你需要在写入磁盘之前对数据进行大量操作时非常有用，可以节省磁盘 I/O 时间。如果你每次只写一个字节，并且希望在一次写入文件之前将大量数据存储在内存缓冲区中，那么它也很有用，否则你将为每个字节都进行磁盘 I/O 操作，这会导致磁盘磨损，并且会减慢过程。

可以检查缓冲写入器，查看它当前存储了多少未缓冲的数据，以及剩余多少缓冲区空间。缓冲区还可以重置，以撤销自上次刷新以来的所有更改。缓冲区的大小也可以调整。

以下示例打开名为 `test.txt` 的文件，并创建一个缓冲写入器来包装该文件对象。一些字节被写入缓冲区，然后写入一个字符串。在将缓冲区的内容刷新到磁盘上的文件之前，检查内存中的缓冲区。它还演示了如何重置缓冲区，撤销所有尚未刷新到磁盘的更改，以及如何检查缓冲区中剩余的空间。最后，它展示了如何将缓冲区调整为特定大小：

```
package main 

import ( 
   "bufio" 
   "log" 
   "os" 
) 

func main() { 
   // Open file for writing 
   file, err := os.OpenFile("test.txt", os.O_WRONLY, 0666) 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer file.Close() 

   // Create a buffered writer from the file 
   bufferedWriter := bufio.NewWriter(file) 

   // Write bytes to buffer 
   bytesWritten, err := bufferedWriter.Write( 
      []byte{65, 66, 67}, 
   ) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Bytes written: %d\n", bytesWritten) 

   // Write string to buffer 
   // Also available are WriteRune() and WriteByte() 
   bytesWritten, err = bufferedWriter.WriteString( 
      "Buffered string\n", 
   ) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Bytes written: %d\n", bytesWritten) 

   // Check how much is stored in buffer waiting 
   unflushedBufferSize := bufferedWriter.Buffered() 
   log.Printf("Bytes buffered: %d\n", unflushedBufferSize) 

   // See how much buffer is available 
   bytesAvailable := bufferedWriter.Available() 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Available buffer: %d\n", bytesAvailable) 

   // Write memory buffer to disk 
   bufferedWriter.Flush() 

   // Revert any changes done to buffer that have 
   // not yet been written to file with Flush() 
   // We just flushed, so there are no changes to revert 
   // The writer that you pass as an argument 
   // is where the buffer will output to, if you want 
   // to change to a new writer 
   bufferedWriter.Reset(bufferedWriter) 

   // See how much buffer is available 
   bytesAvailable = bufferedWriter.Available() 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Available buffer: %d\n", bytesAvailable) 

   // Resize buffer. The first argument is a writer 
   // where the buffer should output to. In this case 
   // we are using the same buffer. If we chose a number 
   // that was smaller than the existing buffer, like 10 
   // we would not get back a buffer of size 10, we will 
   // get back a buffer the size of the original since 
   // it was already large enough (default 4096) 
   bufferedWriter = bufio.NewWriterSize( 
      bufferedWriter, 
      8000, 
   ) 

   // Check available buffer size after resizing 
   bytesAvailable = bufferedWriter.Available() 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Available buffer: %d\n", bytesAvailable) 
} 
```

# 从文件中读取最多 n 字节

`os.File` 类型包含一些基本函数，其中之一是 `File.Read()`。`Read()` 函数期望传入一个字节切片作为参数。字节会从文件中读取并放入字节切片中。`Read()` 会尽可能多地读取字节，直到缓冲区填满为止，然后停止读取。

根据提供的缓冲区大小和文件的大小，可能需要多次调用 `Read()` 才能读取完整个文件。如果在调用 `Read()` 时到达文件末尾，将返回 `io.EOF` 错误：

```
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Open file for reading 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer file.Close() 

   // Read up to len(b) bytes from the File 
   // Zero bytes written means end of file 
   // End of file returns error type io.EOF 
   byteSlice := make([]byte, 16) 
   bytesRead, err := file.Read(byteSlice) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Number of bytes read: %d\n", bytesRead) 
   log.Printf("Data read: %s\n", byteSlice) 
} 
```

# 精确读取 n 字节

在前面的示例中，如果文件仅包含 10 个字节，而你提供了一个大小为 500 字节的字节切片缓冲区，`File.Read()` 不会返回错误。某些情况下，你可能希望确保整个缓冲区都被填满。`io.ReadFull()` 函数将返回错误，如果缓冲区没有被填满。如果 `io.ReadFull()` 没有任何数据可以读取，将返回 EOF 错误；如果读取了一些数据，但随后遇到 EOF，它将返回 `ErrUnexpectedEOF` 错误：

```
package main 

import ( 
   "io" 
   "log" 
   "os" 
) 

func main() { 
   // Open file for reading 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // The file.Read() function will happily read a tiny file in to a    
   // large byte slice, but io.ReadFull() will return an 
   // error if the file is smaller than the byte slice. 
   byteSlice := make([]byte, 2) 
   numBytesRead, err := io.ReadFull(file, byteSlice) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Number of bytes read: %d\n", numBytesRead) 
   log.Printf("Data read: %s\n", byteSlice) 
} 
```

# 至少读取 n 字节

`io` 包提供的另一个有用函数是 `io.ReadAtLeast()`。如果没有读取到指定数量的字节，它将返回一个错误。与 `io.ReadFull()` 类似，如果没有读取到数据，将返回 `EOF` 错误；如果读取到一些数据，但遇到文件末尾，则会返回 `ErrUnexpectedEOF` 错误：

```
package main 

import ( 
   "io" 
   "log" 
   "os" 
) 

func main() { 
   // Open file for reading 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   byteSlice := make([]byte, 512) 
   minBytes := 8 
   // io.ReadAtLeast() will return an error if it cannot 
   // find at least minBytes to read. It will read as 
   // many bytes as byteSlice can hold. 
   numBytesRead, err := io.ReadAtLeast(file, byteSlice, minBytes) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Number of bytes read: %d\n", numBytesRead) 
   log.Printf("Data read: %s\n", byteSlice) 
} 
```

# 读取文件的所有字节

`ioutil`包提供了一个函数来读取文件中的每个字节，并将其返回为字节切片。这个函数很方便，因为在读取之前你不需要定义字节切片。缺点是，如果文件非常大，它会返回一个可能比预期还大的字节切片。

`io.ReadAll()`函数期望一个已经通过`os.Open()`或`Create()`打开的文件：

```
package main 

import ( 
   "fmt" 
   "io/ioutil" 
   "log" 
   "os" 
) 

func main() { 
   // Open file for reading 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // os.File.Read(), io.ReadFull(), and 
   // io.ReadAtLeast() all work with a fixed 
   // byte slice that you make before you read 

   // ioutil.ReadAll() will read every byte 
   // from the reader (in this case a file), 
   // and return a slice of unknown slice 
   data, err := ioutil.ReadAll(file) 
   if err != nil { 
      log.Fatal(err) 
   } 

   fmt.Printf("Data as hex: %x\n", data) 
   fmt.Printf("Data as string: %s\n", data) 
   fmt.Println("Number of bytes read:", len(data)) 
} 
```

# 快速将整个文件读取到内存

类似于前面示例中的`io.ReadAll()`函数，`io.ReadFile()`将读取文件中的所有字节并返回一个字节切片。这两者之间的主要区别是，`io.ReadFile()`期望的是文件路径，而不是已经打开的文件对象。`io.ReadFile()`函数将负责打开、读取和关闭文件。你只需提供文件名，它就会提供字节数据。这通常是加载文件数据最快且最简便的方法。

尽管这种方法非常方便，但它有一定的局限性；因为它将整个文件直接读取到内存中，过大的文件可能会超出系统的内存限制：

```
package main 

import ( 
   "io/ioutil" 
   "log" 
) 

func main() { 
   // Read file to byte slice 
   data, err := ioutil.ReadFile("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   log.Printf("Data read: %s\n", data) 
} 
```

# 缓冲区读取器

创建一个缓冲区读取器将会存储一个内存缓冲区，其中包含一些内容。缓冲区读取器还提供一些在`os.File`或`io.Reader`类型中不可用的功能。默认缓冲区大小为 4096，最小大小为 16。缓冲区读取器提供了一组有用的函数，包括但不限于以下功能：

+   `Read()`：用于将数据读取到字节切片中

+   `Peek()`：用于查看下一个字节，而不移动文件指针

+   `ReadByte()`：用于读取单个字节

+   `UnreadByte()`：取消读取上一个读取的字节

+   `ReadBytes()`：读取字节直到达到指定的分隔符

+   `ReadString()`：读取字符串直到遇到指定的分隔符

以下示例演示了如何使用缓冲区读取器从文件中获取数据。首先，它打开一个文件，然后创建一个包装该文件对象的缓冲区读取器。一旦缓冲区读取器准备好后，接下来展示如何使用前述函数：

```
package main 

import ( 
   "bufio" 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   // Open file and create a buffered reader on top 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   bufferedReader := bufio.NewReader(file) 

   // Get bytes without advancing pointer 
   byteSlice := make([]byte, 5) 
   byteSlice, err = bufferedReader.Peek(5) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Peeked at 5 bytes: %s\n", byteSlice) 

   // Read and advance pointer 
   numBytesRead, err := bufferedReader.Read(byteSlice) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Read %d bytes: %s\n", numBytesRead, byteSlice) 

   // Ready 1 byte. Error if no byte to read 
   myByte, err := bufferedReader.ReadByte() 
   if err != nil { 
      log.Fatal(err) 
   }  
   fmt.Printf("Read 1 byte: %c\n", myByte) 

   // Read up to and including delimiter 
   // Returns byte slice 
   dataBytes, err := bufferedReader.ReadBytes('\n') 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Read bytes: %s\n", dataBytes) 

   // Read up to and including delimiter 
   // Returns string 
   dataString, err := bufferedReader.ReadString('\n') 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Read string: %s\n", dataString) 

   // This example reads a few lines so test.txt 
   // should have a few lines of text to work correct 
} 
```

# 使用扫描器进行读取

扫描器是`bufio`包的一部分。它对于按特定分隔符逐步读取文件非常有用。通常，换行符被用作分隔符来按行分割文件。在 CSV 文件中，逗号会作为分隔符。`os.File`对象可以像缓冲区读取器一样被包装在`bufio.Scanner`对象中。我们将调用`Scan()`方法读取到下一个分隔符，然后使用`Text()`或`Bytes()`获取读取的数据。

分隔符不仅仅是一个简单的字节或字符。实际上，存在一个特殊的函数，你需要实现它，该函数将决定下一个分隔符的位置，指针应该向前推进多少，并返回哪些数据。如果未提供自定义的`SplitFunc`类型，它默认为`ScanLines`，将在每个换行符处分割。`bufio`中还包含其他分割函数，如`ScanRunes`和`ScanWords`。

要定义自己的分割函数，定义一个与此指纹匹配的函数：

```
type SplitFuncfunc(data []byte, atEOF bool) (advance int, token []byte, 
   err error)
```

返回（`0`，`nil`，`nil`）将告诉扫描器重新扫描，但需要更大的缓冲区，因为当前数据不足以达到分隔符。

在以下示例中，从文件创建了`bufio.Scanner`，然后按单词扫描文件：

```
package main 

import ( 
   "bufio" 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   // Open file and create scanner on top of it 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   scanner := bufio.NewScanner(file) 

   // Default scanner is bufio.ScanLines. Lets use ScanWords. 
   // Could also use a custom function of SplitFunc type 
   scanner.Split(bufio.ScanWords) 

   // Scan for next token. 
   success := scanner.Scan() 
   if success == false { 
      // False on error or EOF. Check error 
      err = scanner.Err() 
      if err == nil { 
         log.Println("Scan completed and reached EOF") 
      } else { 
         log.Fatal(err) 
      } 
   } 

   // Get data from scan with Bytes() or Text() 
   fmt.Println("First word found:", scanner.Text()) 

   // Call scanner.Scan() manually, or loop with for 
   for scanner.Scan() { 
      fmt.Println(scanner.Text()) 
   } 
} 
```

# 归档

归档是一种存储多个文件的文件格式。最常见的两种归档格式是 tar 包和 ZIP 归档。Go 标准库同时支持`tar`和`zip`包。这些示例使用 ZIP 格式，但 tar 格式可以轻松互换。

# 归档（ZIP）文件

以下示例演示了如何创建一个包含多个文件的归档文件。示例中的文件是硬编码的，仅包含几个字节，但应该可以轻松适应其他需求：

```
// This example uses zip but standard library 
// also supports tar archives 
package main 

import ( 
   "archive/zip" 
   "log" 
   "os" 
) 

func main() { 
   // Create a file to write the archive buffer to 
   // Could also use an in memory buffer. 
   outFile, err := os.Create("test.zip") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer outFile.Close() 

   // Create a zip writer on top of the file writer 
   zipWriter := zip.NewWriter(outFile) 

   // Add files to archive 
   // We use some hard coded data to demonstrate, 
   // but you could iterate through all the files 
   // in a directory and pass the name and contents 
   // of each file, or you can take data from your 
   // program and write it write in to the archive without 
   var filesToArchive = []struct { 
      Name, Body string 
   }{ 
      {"test.txt", "String contents of file"}, 
      {"test2.txt", "\x61\x62\x63\n"}, 
   } 

   // Create and write files to the archive, which in turn 
   // are getting written to the underlying writer to the 
   // .zip file we created at the beginning 
   for _, file := range filesToArchive { 
      fileWriter, err := zipWriter.Create(file.Name) 
      if err != nil { 
         log.Fatal(err) 
      } 
      _, err = fileWriter.Write([]byte(file.Body)) 
      if err != nil { 
         log.Fatal(err) 
      } 
   } 

   // Clean up 
   err = zipWriter.Close() 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 提取（解压）归档文件

以下示例演示了如何解压 ZIP 格式的文件。它会通过创建必要的目录来复制归档文件中的目录结构：

```
// This example uses zip but standard library 
// also supports tar archives 
package main 

import ( 
   "archive/zip" 
   "io" 
   "log" 
   "os" 
   "path/filepath" 
) 

func main() { 
   // Create a reader out of the zip archive 
   zipReader, err := zip.OpenReader("test.zip") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer zipReader.Close() 

   // Iterate through each file/dir found in 
   for _, file := range zipReader.Reader.File { 
      // Open the file inside the zip archive 
      // like a normal file 
      zippedFile, err := file.Open() 
      if err != nil { 
         log.Fatal(err) 
      } 
      defer zippedFile.Close() 

      // Specify what the extracted file name should be. 
      // You can specify a full path or a prefix 
      // to move it to a different directory. 
      // In this case, we will extract the file from 
      // the zip to a file of the same name. 
      targetDir := "./" 
      extractedFilePath := filepath.Join( 
         targetDir, 
         file.Name, 
      ) 

      // Extract the item (or create directory) 
      if file.FileInfo().IsDir() { 
         // Create directories to recreate directory 
         // structure inside the zip archive. Also 
         // preserves permissions 
         log.Println("Creating directory:", extractedFilePath) 
         os.MkdirAll(extractedFilePath, file.Mode()) 
      } else { 
         // Extract regular file since not a directory 
         log.Println("Extracting file:", file.Name) 

         // Open an output file for writing 
         outputFile, err := os.OpenFile( 
            extractedFilePath, 
            os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 
            file.Mode(), 
         ) 
         if err != nil { 
            log.Fatal(err) 
         } 
         defer outputFile.Close() 

         // "Extract" the file by copying zipped file 
         // contents to the output file 
         _, err = io.Copy(outputFile, zippedFile) 
         if err != nil { 
            log.Fatal(err) 
         } 
      }  
   } 
} 
```

# 压缩

Go 标准库还支持压缩功能，这与归档不同。通常，归档和压缩是结合使用的，用来将大量文件打包成一个单一的紧凑文件。最常见的格式可能是`.tar.gz`文件，它是一个 gzip 压缩的 tar 包。不要将 zip 和 gzip 混淆，它们是两种不同的东西。

Go 标准库支持多种压缩算法：

+   **bzip2**：bzip2 格式

+   **flate**：DEFLATE（RFC 1951）

+   **gzip**：gzip 格式（RFC 1952）

+   **lzw**：Lempel-Ziv-Welch 格式，出自 *A Technique for High-Performance Data Compression, Computer, 17(6) (1984 年 6 月)，第 8-19 页*

+   **zlib**：zlib 格式（RFC 1950）

了解更多关于每个包的内容，请访问 [`golang.org/pkg/compress/`](https://golang.org/pkg/compress/)。这些示例使用 gzip 压缩，但应该很容易将上述任何包互换使用。

# 压缩文件

以下示例演示了如何使用`gzip`包压缩文件：

```
// This example uses gzip but standard library also 
// supports zlib, bz2, flate, and lzw 
package main 

import ( 
   "compress/gzip" 
   "log" 
   "os" 
) 

func main() { 
   // Create .gz file to write to 
   outputFile, err := os.Create("test.txt.gz") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // Create a gzip writer on top of file writer 
   gzipWriter := gzip.NewWriter(outputFile) 
   defer gzipWriter.Close() 

   // When we write to the gzip writer 
   // it will in turn compress the contents 
   // and then write it to the underlying 
   // file writer as well 
   // We don't have to worry about how all 
   // the compression works since we just 
   // use it as a simple writer interface 
   // that we send bytes to 
   _, err = gzipWriter.Write([]byte("Gophers rule!\n")) 
   if err != nil { 
      log.Fatal(err) 
   } 

   log.Println("Compressed data written to file.") 
} 
```

# 解压文件

以下示例演示了如何使用`gzip`算法解压文件：

```
// This example uses gzip but standard library also 
// supports zlib, bz2, flate, and lzw 
package main 

import ( 
   "compress/gzip" 
   "io" 
   "log" 
   "os" 
) 

func main() { 
   // Open gzip file that we want to uncompress 
   // The file is a reader, but we could use any 
   // data source. It is common for web servers 
   // to return gzipped contents to save bandwidth 
   // and in that case the data is not in a file 
   // on the file system but is in a memory buffer 
   gzipFile, err := os.Open("test.txt.gz") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // Create a gzip reader on top of the file reader 
   // Again, it could be any type reader though 
   gzipReader, err := gzip.NewReader(gzipFile) 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer gzipReader.Close() 

   // Uncompress to a writer. We'll use a file writer 
   outfileWriter, err := os.Create("unzipped.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer outfileWriter.Close() 

   // Copy contents of gzipped file to output file 
   _, err = io.Copy(outfileWriter, gzipReader) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

在结束本章关于文件操作的内容之前，让我们看两个可能有用的实际示例。临时文件和目录在你不想创建永久文件，但又需要一个文件进行操作时非常有用。此外，获取文件的常见方式是通过互联网下载。以下示例展示了这些操作。

# 创建临时文件和目录

`ioutil` 包提供了两个函数：`TempDir()` 和 `TempFile()`。调用者有责任在使用完毕后删除临时文件。这些函数提供的唯一好处是你可以传递一个空字符串作为目录，它会自动在系统的默认临时文件夹中创建该文件（在 Linux 上是 `/tmp`），因为 `os.TempDir()` 函数将返回默认的系统临时目录：

```
package main 

import ( 
   "fmt" 
   "io/ioutil" 
   "log" 
   "os" 
) 

func main() { 
   // Create a temp dir in the system default temp folder 
   tempDirPath, err := ioutil.TempDir("", "myTempDir") 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Temp dir created:", tempDirPath) 

   // Create a file in new temp directory 
   tempFile, err := ioutil.TempFile(tempDirPath, "myTempFile.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Temp file created:", tempFile.Name()) 

   // ... do something with temp file/dir ... 

   // Close file 
   err = tempFile.Close() 
   if err != nil { 
      log.Fatal(err) 
   } 

   // Delete the resources we created 
   err = os.Remove(tempFile.Name()) 
   if err != nil { 
      log.Fatal(err) 
   } 
   err = os.Remove(tempDirPath) 
   if err != nil { 
      log.Fatal(err) 
   } 
}
```

# 通过 HTTP 下载文件

现代计算中的一个常见任务是通过 HTTP 协议下载文件。以下示例展示了如何快速下载一个特定 URL 到文件。

其他常见的完成此任务的工具包括`curl`和`wget`：

```
package main 

import ( 
   "io" 
   "log" 
   "net/http" 
   "os" 
) 

func main() { 
   // Create output file 
   newFile, err := os.Create("devdungeon.html") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer newFile.Close() 

   // HTTP GET request devdungeon.com 
   url := "http://www.devdungeon.com/archive" 
   response, err := http.Get(url) 
   defer response.Body.Close() 

   // Write bytes from HTTP response to file. 
   // response.Body satisfies the reader interface. 
   // newFile satisfies the writer interface. 
   // That allows us to use io.Copy which accepts 
   // any type that implements reader and writer interface 
   numBytesWritten, err := io.Copy(newFile, response.Body) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Downloaded %d byte file.\n", numBytesWritten) 
} 
```

# 总结

阅读完本章后，你应该已经熟悉了一些与文件交互的不同方式，并且能够自如地执行基本操作。目标不是记住所有这些函数名，而是意识到有哪些工具可用。如果你需要示例代码，本章可以作为参考，但我鼓励你创建一个食谱库，收集像这样的代码片段。

有用的文件函数分布在多个包中。`os` 包仅包含用于处理文件的基本操作，如打开、关闭和简单的读取操作。`io` 包提供了比 `os` 包更高层次的可以在读取和写入接口上使用的函数。`ioutil` 包提供了更高级的便捷函数，用于处理文件。

在下一章中，我们将讨论取证的主题。内容将包括如何查找异常的文件，如异常大的或最近修改的文件。除了文件取证外，我们还将讨论一些网络取证调查话题，即查找主机的主机名、IP 地址和 MX 记录。取证章节还包括一些基本的隐写术示例，展示如何在图像中隐藏数据以及如何在图像中查找隐藏的数据。

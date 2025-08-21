# 第三章：英特尔指令集架构（ISA）

几乎可以说，任何数字设备都有一套特定的指令。甚至一个晶体管，作为现代数字电子学的基石，也有两个指令，开和关，每个指令用 1 或 0 表示（哪一个表示开和关取决于晶体管是*n-p-n*还是*p-n-p*）。处理器由数百万个晶体管构成，同样也由 1 和 0 的序列控制（这些序列被分组成 8 位字节，进而组成指令）。幸运的是，我们不必担心指令编码（毕竟现在是 21 世纪），因为汇编器会为我们做这些事。

每条 CPU 指令（这对于任何 CPU 都适用，不仅仅是基于英特尔的）都有一个助记符（以下简称助记符），你需要学习这个助记符以及一些关于操作数大小（和内存寻址，具体内容将在第四章，*内存寻址模式*中深入探讨）的简单规则，这正是我们在本章要做的事情。

我们将从创建一个简单的汇编模板开始，这个模板将贯穿全书，作为我们代码的起始点。接着，我们将进入实际的 CPU 指令集，熟悉以下类型的指令：

+   数据传输指令

+   算术指令

+   浮点指令

+   执行流控制指令

+   扩展

# 汇编源模板

我们将从两个 32 位模板开始，一个用于 Windows，一个用于 Linux。64 位模板将很快添加进来，我们会看到它们与 32 位模板没有太大区别。这些模板包含一些宏指令和指令，这些将在书中稍后解释。至于现在，这些模板仅提供了让你能够编写简单（或不那么简单）代码片段、编译它们并在调试器中测试它们的能力。

# Windows 汇编模板（32 位）

一个 Windows 可执行文件由多个部分组成（PE 可执行文件/对象文件的结构将在第九章，*操作系统接口*中更详细地讨论）；通常包含一个代码部分，一个数据部分和一个导入数据部分（其中包含有关从动态链接库导入的外部过程的信息）。**动态链接库**（**DLL**）也有一个导出部分，包含该 DLL 中公开的过程/对象信息。在我们的模板中，我们只是定义这些部分，并让汇编器完成剩余的工作（编写头文件等）。

现在，让我们来看看模板本身。有关 PE 特定细节的进一步说明请参见注释：

```
*; File: srctemplate_win.asm*

*; First of all, we tell the compiler which type of executable we want it*
*; to be. In our case it is a 32-bit PE executable.* 
format PE GUI

*; Tell the compiler where we want our program to start - define the entry*
*; point. We want it to be at the place labeled with '_start'.*
entry _start

*; The following line includes a set of macros, shipped with FASM, which* 
*; are essential for the Windows program. We can, of course, implement all* 
*; we need ourselves, and we will do that in chapter 9.*
include 'win32a.inc'

*; PE file consists of at least one section.* 
*; In this template we only need 3:*
*;    1\. '.text' - section that contains executable code*
*;    2\. '.data' - section that contains data*
*;    3\. '.idata' - section that contains import information*
*;*
*; '.text' section: contains code, is readable, is executable*
section '.text' code readable executable
_start:
   *;*
 *; Put your code here*
 *;*

 *; We have to terminate the process properly*
 *; Put return code on stack*
   push  0
   *; Call ExitProcess Windows API procedure*
   call [exitProcess]

*; '.data' section: contains data, is readable, may be writeable*
section '.data' data readable writeable
   *;*
 *; Put your data here*
 *;*

*; '.idata' section: contains import information, is readable, is* *writeable*
section '.idata' import data readable writeable

*; 'library' macro from 'win32a.inc' creates proper entry for importing* 
*; procedures from a dynamic link library. For now it is only 'kernel32.dll',*
*; library kernel, 'kernel32.dll'*

*; 'import' macro creates the actual entries for procedures we want to import* 
*; from a dynamic link library*
import kernel, 
   exitProcess, 'ExitProcess'
```

# Linux 汇编模板（32 位）

在 Linux 上，虽然磁盘上的文件被划分为多个部分，但内存中的可执行文件则划分为代码段和数据段。以下是我们的 Linux 32 位 ELF 可执行文件模板：

```
*; File: src/template_lin.asm*

*; Just as in the Windows template - we tell the assembler which type* 
*; of output we expect.* 
*; In this case it is 32-bit executable ELF*
format ELF executable

*; Tell the assembler where the entry point is*
entry _start

*; On *nix based systems, when in memory, the space is arranged into* 
*; segments, rather than in sections, therefore, we define* 
*; two segments:*
*; Code segment (executable segment)*
segment readable executable

*; Here is our entry point*
_start:

   *; Set return value to 0*
   xor ebx, ebx
   mov eax, ebx

   *; Set eax to 1 - 32-bit Linux SYS_exit system call number*
   inc eax

   *; Call kernel*
   int 0x80

*; Data segment*
segment readable writeable
   db 0

*; As you see, there is no import/export segment here. The structure* 
*; of an ELF executable/object file will be covered in more detail* 
*; in chapters 8 and 9*
```

如前面代码所提到的，这两个模板将作为我们在本书中编写的任何代码的起点。

# 数据类型及其定义

在我们开始编写汇编指令之前，我们必须知道如何定义数据，或者更准确地说，如何告诉汇编器我们正在使用的数据类型。

Flat Assembler 支持六种内置数据类型，并允许我们定义或声明变量。这里定义和声明的区别在于，当我们定义一个变量时，我们同时为它赋予一个特定的值，而声明时，我们只是为某种数据类型保留空间：

**变量定义格式**：`[label] definition_directive value(s)`

+   `label`：这是可选的，但引用未命名的变量会更困难。

变量声明格式：`[label] declaration_directive count`

+   `label`：这是可选的，但引用未命名的变量会更困难。

+   `count`：这告诉汇编器它需要为`declaration_directive`中指定的类型预留多少个数据条目

下表展示了按大小排序的内置数据类型的定义和声明指令：

| **数据类型的字节大小** | **定义指令** | **声明（预留空间）指令** |
| --- | --- | --- |
| 1 | `db` 文件（包括二进制文件） | `rb` |
| 2 | `dw` `du`（定义 unicode 字符） | `rw` |
| 4 | `dd` | `rd` |
| 6 | `dp` `df` | `rp` `rf` |
| 8 | `dq` | `rq` |
| 10 | `dt` | `rt` |

上表列出了按字节大小排序的可接受数据类型，最左侧列出的是这些类型的字节大小。中间的列包含我们在汇编代码中用来定义某种类型数据的指令。例如，如果我们想定义一个名为`my_var`的字节变量，那么我们会写如下代码：

```
my_var   db  0x5a
```

在这里，`0x5a`是我们为该变量赋予的值。在不需要初始化变量为特定值的情况下，我们可以写成如下方式：

```
my_var db ?
```

在这里，问号（`?`）意味着汇编器可以将此变量占用的内存区域初始化为任何值（通常为`0`）。

有两个指令需要更多注意：

+   `file`：该指令告诉汇编器在编译过程中包含一个二进制文件。

+   `du`：此指令的使用方法与`db`类似，用于定义字符或其字符串，但它生成的是类似 unicode 的字符/字符串，而不是 ASCII。其效果是将 8 位值扩展为 16 位值。这是一个便利指令，当需要进行适当的 unicode 转换时，必须进行重写。

最右侧的指令用于当我们需要为某种类型的数据条目保留空间时，而不需要指定其具体值。例如，如果我们想为 12 个 32 位整数（标记为`my_array`）预留空间，那么我们会写如下代码：

```
my_array rd 12
```

汇编器将为这个数组保留 48 个字节，从代码中标记为`my_array`的位置开始。

尽管大部分时间你会在数据段中使用这些指令，但它们可以放置在任何地方。例如，你可以（出于任何目的）在一个过程内部、两个过程之间保留一些空间，或者包含一个包含预编译代码的二进制文件。

# 一个调试器

我们几乎准备好开始指令集探索的过程了；然而，还有一件事情我们还没有涉及，因为没有必要--调试器。市面上有相对较多的调试器可供选择，作为开发者，你很可能至少使用过其中一个。然而，由于我们对调试用汇编语言编写的程序感兴趣，我建议选择以下之一：

+   **IDA Pro** ([`www.hex-rays.com/products/ida/index.shtml`](https://www.hex-rays.com/products/ida/index.shtml))：非常方便，但也非常昂贵。如果你有它，那很好！如果没有，没关系，我们还有其他选择。仅适用于 Windows。

+   **OllyDbg** ([`www.ollydbg.de/version2.html`](http://www.ollydbg.de/version2.html))：免费调试器/反汇编器。对我们所需的内容已经足够了。仅适用于 Windows。不幸的是，该工具的 64 位版本从未完成，这意味着你无法将其用于 64 位示例。

+   **HopperApp** ([`www.hopperapp.com`](https://www.hopperapp.com))：商业化，但价格非常实惠的反汇编器，带有 GDB 前端。macOS X 和 Linux。

+   **GDB**（**GNU 调试器**）：免费提供，在 Windows、Linux、mac OS X 等系统上运行。虽然 GDB 是一个命令行工具，但使用起来相当容易。唯一的限制是反汇编器的输出是 AT&T 语法。

你可以自由选择这些中的任何一个，或者选择列表中未提及的调试器（有相对较多的选择）。在选择调试器时只有一个重要因素需要考虑--你应该感到舒适，因为在调试器中运行代码，查看处理器寄存器或内存中发生的一切，将极大地增强你在汇编语言编写代码时的体验。

# 指令集摘要

我们终于到了有趣的部分--指令集本身。不幸的是，描述现代基于英特尔的处理器的每一条指令都需要一本单独的书，但由于已经有这样一本书（[`www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf`](http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)），我们不会无谓地增加东西，而是集中在指令组而不是单个指令上。在本章末尾，我们将实现 AES128 加密以进行演示。

# 通用指令

通用指令执行基本操作，如数据移动、算术运算、流程控制等。它们按功能分组：

+   数据传输指令

+   二进制算术指令

+   十进制算术指令

+   逻辑指令

+   移位与旋转指令

+   位/字节操作指令

+   流程控制指令

+   字符串操作指令

+   ENTER/LEAVE 指令

+   标志控制指令

+   杂项指令

指令的分组与《Intel 软件开发者手册》中所述相同。

# 数据传输指令

数据传输指令，顾名思义，用于在寄存器之间或寄存器与内存之间传输数据。它们中的一些可能将立即数作为源操作数。以下示例说明了它们的使用。

```
 push ebx                 *; save EBX register on stack*
 mov  ax, 0xc001          *; move immediate value to AX register*
 movzx ebx, ax             *; move zero-extended content of AX to EBX* 
 *; register*
 *; EBX = 0x0000c001*
 bswap ebx                 *; reverse byte order of EBX register* 
 *; EBX = 0x01c00000*
 mov  [some_address], ebx *; move content of EBX register to* 
 *; memory at 'some_address'*
 *; content of 'some_address' =* 
 *; 0x01c00000*
                            *; The above two lines of code could have* 
 *; been replaced with:*
 *; movbe [some_address], ebx*
 pop  ebx                  *; restore EBX register from stack*
```

让我们更仔细地看一下与示例一起使用的指令：

+   **PUSH**：该指令要求处理器将操作数的值存储到堆栈中，并递减堆栈指针（32 位系统中是 ESP 寄存器，64 位系统中是 RSP 寄存器）。

+   **MOV**：这是最常用的数据传输指令：

    +   它在相同大小的寄存器之间移动数据

    +   它将立即数或从内存读取的值加载到寄存器中

    +   它将寄存器的内容存储到内存中

    +   它将立即数存储到内存中

+   **MOVZX**：这条指令在寻址模式上不如 MOV 强大，因为它只能在寄存器与寄存器之间或内存与寄存器之间传输数据，但它有一个特殊的功能——被传输的值会转换为更宽（使用更多位）的值，并且会进行零扩展。至于该指令支持的寻址模式，它只能执行以下操作：

    +   它将字节值从寄存器或内存移动到字大小的寄存器，并用零扩展结果值（将添加一个字节）

    +   它将字节值从寄存器或内存移动到一个双字节大小的寄存器，在这种情况下，原始值将添加三个字节，并用零扩展该值

    +   它将字节大小的值从寄存器或内存移动到双字节大小的寄存器中，添加两个字节并用 0 的扩展值填充

+   **MOVSX** 类似于 MOVZX；然而，扩展位被源操作数的符号位填充。

+   **BSWAP/MOVBE**：BSWAP 指令是切换值的字节序最简单的方法；然而，它实际上并不是一条传输指令，因为它仅在寄存器内重新排列数据。BSWAP 指令仅适用于 32 位/64 位操作数。MOVBE 是一条更方便的字节顺序交换指令，因为它不仅可以交换字节顺序，还可以在操作数之间移动数据。该指令适用于 16 位、32 位和 64 位操作数，但无法在寄存器之间移动数据。

+   **POP**：此指令从栈中检索先前存储的值。此指令的唯一操作数是值应存储的目标，可以是寄存器或内存位置。此指令还会增加栈指针寄存器。

# 二进制算术指令

这些指令执行基本的算术操作。操作数可以是字节、字、双字或四字寄存器、内存位置或立即数。它们都会根据操作结果修改 CPU 标志，这反过来允许我们根据某些标志的值改变执行流程。

让我们来看几个基本的算术指令：

+   **INC**：这是增量的缩写。此指令将 1 加到其操作数的值上。显然，`inc` 指令或其对应的 `dec` 指令不能与立即数一起使用。`inc` 指令会影响某些 CPU 标志。例如，考虑我们取一个寄存器（为了简化起见，假设是 EAX 寄存器），将其设置为 0，并执行如下操作：

```
      inc eax
```

在这种情况下，EAX 的值将为 1，ZF（零标志，记得吗？）将被设置为 0，这意味着操作结果是一个非零值。另一方面，如果我们将 EAX 寄存器加载为 `0xffffffff`，并使用 `inc` 指令将其增量 1，则寄存器将变为零，并且由于零是最新操作的结果，ZF 将被设置（值为 `1`）。

+   **ADD**：该指令执行简单的加法操作，将源操作数加到目标操作数，并将结果存储在目标操作数中。此指令还会影响几个 CPU 标志。在以下示例中，我们将 `0xffffffff` 加到已设置为 `1` 的 EBX 寄存器。此操作的结果将是一个 33 位的值，但由于我们只能用 32 位存储结果，多余的一位将进入进位标志。此机制不仅对控制执行流程有用，还可以在加法操作两个大数时使用（可能是几百位数），因为我们可以通过较小的部分（例如 32 位）来处理这些数字。

+   **ADC**：谈到大数加法，`adc` 指令允许我们将由先前操作设置的进位标志的值，添加到额外两个值的和中。例如，如果我们想要加 `0x802597631` 和 `0x4fe013872`，我们首先将 `0x02597631` 和 `0xfe013872` 相加，结果是 `0x005aaea3`，并且进位标志被设置。接下来，我们将加上 8、4 和进位标志的值：

```
 *;Assuming EAX equals to 8 and EBX equals to 4*
      adc eax, ebx
```

这将得到 `8 + 4 + 1`（其中 1 是隐式操作数——CF 的值）`= 0xd`，因此，最终结果将是 `0xd005aaea3`。

以下示例更详细地说明了这些指令：

```
mov   eax, 0          *; Set EAX to 0*
mov   ebx, eax        *; Set EBX to 0*
inc   ebx             *; Increment EBX*
 *; EBX = 1*
add   ebx, 0xffffffff *; add 4294967295 to EBX*
 *; EBX = 0 and Carry Flag is set*
adc   eax, 0          *; Add 0 and Carry Flag to EAX* 
 *; EAX = 1*
```

# 十进制算术指令

在大约 15 年的汇编语言开发和反向工程软件过程中，我只遇到过这些指令一次，那是在大学时。然而，提到它们是正确的，原因有几个：

+   像 AAM 和 AAD 这样的指令有时会作为乘法和除法的较小变体使用，因为它们允许立即操作数。它们较小，因为它们的编码方式可以生成更小的代码。

+   像 AAD 0（即除以零）这样的指令可以用作某些保护方案中的异常触发器。

+   不提及这些指令将是历史性的错误。

十进制算术指令在 64 位平台上是非法的。

首先，什么是 BCD？它是**二进制编码十进制** (**BCD**)，实际上是为了简化将数字的二进制表示转换为其 ASCII 等效值，反之亦然，同时增加了对以十六进制形式表示的十进制数执行基本算术操作的能力（不是它们的十六进制等价物！）。

BCD 有两种类型：压缩 BCD 和非压缩 BCD。压缩 BCD 使用单字节的 nibbles 来表示十进制数。例如，数字 12 将表示为 0x12。另一方面，非压缩 BCD 使用字节表示单独的数字（例如，12 转换为 0x0102）。

然而，考虑到这些指令自首次出现以来并未发生变化，它们仅作用于存储在单个字节中的值（对于压缩 BCD）或存储在单个字中的值（对于非压缩 BCD）。更重要的是，这些值应仅存储在 AL 寄存器中（对于压缩 BCD），或存储在 AX 寄存器中（更精确地说，是存储在 AH:AL 对寄存器中，针对非压缩 BCD）。

只有六个 BCD 指令：

+   **加法后的十进制调整** (**DAA**)：该指令专用于压缩 BCD。由于两个压缩 BCD 数字的加法结果不一定是有效的压缩 BCD 数字，因此调用 DAA 可以通过进行必要的调整，将结果转换为正确的压缩 BCD 值。例如，让我们加上 12 和 18。通常结果是 30，但如果我们加上`0x12`和`0x18`，结果将是`0x2a`。以下示例说明了此类计算的过程：

```
mov al, 0x12   *; AL = 0x12, which is packed BCD* 
 *; representation of 12*
add al, 0x18   *; Add BCD representation of 18, 
               ; which would result in 0x2a*
daa            *; Adjust. AL would contain 0x30 after this instruction,* 
 *; which is the BCD representation of 30*
```

+   **减法后的十进制调整** (**DAS**)：此指令在减去两个压缩 BCD 数字后执行类似的调整。让我们在前面的代码中再添加一些行（AL 仍然包含`0x30`）：

```
sub al, 0x03  *; We are subtracting 3 from 30, however,* 
 *; the result of 0x30 - 0x03* 
 *; would be 0x2d*
das           *; This instruction sets AL to 0x27, 
              ; which is the packed BCD* 
              *; representation of 27.*
```

+   **加法后的 ASCII 调整** (**AAA**)：此指令类似于 DAA，但它作用于非压缩 BCD 数字（即，AX 寄存器）。让我们来看以下示例，在其中我们仍然加上 18 到 12，但我们使用非压缩 BCD 来执行此操作：

```
mov ax, 0x0102  *; 0x0102 is the unpacked BCD representation of 12*
add ax, 0x0108  *; same for 18*
 *; The result of the addition would be 
                ; 0x020a - far from being 0x0300*
aaa             *; Converts the value of AX register to 0x0300*
```

结果值可以通过加上`0x3030`轻松转换为 ASCII 表示。

+   **减法后的 ASCII 调整** (**AAS**): 该指令类似于 DAS，但作用于解包的 BCD 数字。我们可以继续在前面的示例中添加代码（AX 寄存器仍然有 `0x0300` 的值）。让我们减去 3，最终得到的结果应该是 `0x0207`：

```
sub ax, 0x0003  *; AX now contains 0x02fd*
aas             *; So we convert it to unpacked BCD* 
                *; representation, but...*
 *; AX becomes 0x0107, but as we know, 
                ; 30 - 3 != 17...*
```

那么，问题出在哪里呢？事实上，并没有出什么问题；只是 AAS 指令的内部实现导致了进位（如我们在调试器中所见，CF 标志确实被设置了），或者更确切地说，发生了借位。这就是为什么我们为了方便，最好做如下处理：

```
adc ah, 0  *; Adds the value of CF to AH*
```

最终结果为 `0x0207`，它是 27 的解包 BCD 表示——正是我们所期待的结果。

+   **乘法后的 ASCII 调整** (**AAM**): 两个解包 BCD 数字相乘的结果，也需要进行某些调整，以使其成为解包 BCD 格式。但我们首先要记住的是这些操作所涉及的大小限制。由于我们仅限于 AX 寄存器，所以乘数的最大值是 9（或 `0x09`），意味着在 AX 中存储结果时，我们只能处理一个字节的乘数。假设我们想将 8 乘以 4（即 `0x08 * 0x04`）；自然，结果将是 `0x20`（32 的十六进制表示），这远远不是一个解包 BCD 表示的数字。`aam` 指令通过将 AL 寄存器的值转换为解包 BCD 格式并存储在 AX 中来解决这个问题：

```
mov al, 4 
mov bl, 8
mul bl     *; AX becomes 0x0020*
aam        *; Converts the value of AX to the* 
 *; corresponding unpacked BCD form. Now the AX*
 *; register equals to 0x0302*
```

如我们所见，两字节解包 BCD 的相乘结果是一个解包 BCD 字。

+   **除法前的 ASCII 调整** (**AAD**): 如同指令的名称所示，它应该在除法之前调整 AX 寄存器的值。其大小限制与 AAM 中相同。前一个示例后，AX 寄存器仍包含 `0x0302`，所以我们来将其除以 4：

```
mov bl, 4
aad        *; Adjust AX. The value changes from 0x0302 to 0x0020*
div bl     *; Perform the division itself*
 *; AL register contains the result - 0x08*
```

如我们所见，尽管这些指令看似有点方便，但在数字之间转换 ASCII 表示法和二进制等价物时，有更好的方法，更不用说常规算术指令使用起来要方便得多了。

# 逻辑指令

这一组指令包含了位操作逻辑运算，这些你作为开发者肯定已经知道。这些包括 NOT、OR、XOR 和 AND 运算。然而，虽然高级语言区分位运算符和逻辑运算符（例如，在 C 中，位与 (&) 和逻辑与 (&&)），但它们在汇编层面上是相同的，并且通常与 EFlags 寄存器（或 64 位系统上的 RFlags）一起使用。

例如，考虑以下 C 语言的简单代码片段，它检查某个特定位是否已设置，并根据条件执行某些代码：

```
if(my_var & 0x20)
{
   *// do something if true*
}
else
{
  *// do something else otherwise*
}
```

它可以这样在汇编中实现：

```
and dword [my_var], 0x20  *; Check for sixth bit of 'my_var'.* 
 *; This operation sets ZF if the result* 
 *; is zero (if the bit is not set).*
jnz do_this_if_true       *; Go to this label if the bit is set*
jmp do_this_if_false      *; Go to this label otherwise*
```

这些指令的众多其他应用之一是有限域算术，在其中 XOR 代表加法，AND 代表乘法。

# 移位和旋转指令

这一组指令允许我们在目标操作数内移动位，这是高级语言中仅部分支持的功能。我们可以移位，但不能旋转，也不能隐式指定算术移位（算术移位或逻辑移位的选择通常由高级语言实现，依据操作的数据类型决定）。

使用移位指令，除了它们主要的作用是将位向左或向右移动一定位置外，它也是一种执行目标操作数乘除以 2 的幂的整数乘除法的简便方法。此外，还有两条特殊的移位指令，允许我们将一定数量的位从一个位置移动到另一个位置——更精确地说，是从一个寄存器移动到另一个寄存器或内存位置。

旋转指令允许我们，如其名称所示，将位从目标操作数的一端旋转到另一端。值得一提的是，位可以通过 CF（进位标志位）进行旋转，这意味着被移出的位会存储到 CF 中，同时 CF 的值会被旋转到操作数的另一侧。我们来看下面的例子，这是最简单的完整性控制算法之一：CRC8：

```
   poly = 0x31       *; The polynomial used for CRC8 calculation*
   xor  dl, dl       *; Initialise CRC state register with 0*
   mov  al, 0x16     ; *Prepare the sequence of 8 bits (may definitely* 
 *; be more than 8 bits)*
   mov  ecx, 8       *; Set amount of iterations*
crc_loop:
   shl  al, 1
   rcl  bl, 1
   shl  dl, 1
   rcl  bh, 1
   xor  bl, bh
   test bl, 1
   jz  .noxor
   xor  dl, poly
.noxor:
   loop crc_loop
```

前面的代码段中的循环体故意没有添加注释，因为我们希望更详细地观察那里发生了什么。

循环的第一条指令`shl al, 1`将我们正在计算 CRC8 值的最重要位移出，并将其存储到 CF 标志位中。接下来的指令`rcl bl, 1`将 CF（我们从比特流中移出的位）的值存入 BL 寄存器。接下来的两条指令做同样的事情，将最重要的位存入 DL 寄存器并保存到 BH 寄存器。`rcl`指令的副作用是，BL 和 BH 寄存器中的最重要位被移到 CF 标志位中。虽然在这个特定的例子中这并不重要，但在旋转 CF 标志位时我们应该记住这一点。最终，这意味着在 8 次迭代后，前面的代码为我们提供了`0x16`（即`0xE5`）的 CRC8 值，并将其存储在 DL 寄存器中。

示例中提到的两个移位和旋转指令有它们右侧的对应指令：

+   **SHR**：这会将位向右移，同时将最后移出的位保存在 CF 中。

+   **RCR**：这通过进位标志位将位旋转到右边。

还有一些我们不能跳过的额外指令：

+   **SAR**：这会将位移向右，同时“拖动”符号位，而不是简单地用零填充“空缺”的位。

+   **SAL**：这是一个算术左移。它不是真正的指令，而是为了方便程序员使用的助记符。汇编程序会生成与 SHL 相同的编码。

+   **ROR**：这会将位向右旋转。每个被右移的位都被移入左侧，并且也存储在 CF 中。

最后，正如前面提到的，两个特殊的移位指令如下：

+   **SHLD**：将一定数量的左侧（最高有效）位从一个寄存器移入另一个寄存器或内存位置。

+   **SHRD**：将一定数量的右侧（最低有效）位从一个寄存器移入另一个寄存器或内存位置。

之前示例中的另一个新指令是 TEST，但它将在下一节中解释。

# 位与字节指令

这一组指令是让我们能够在操作数内操作单个位和/或根据 EFlags/RFlags 寄存器中的标志状态设置字节的指令。

在实现位字段的高级语言中，即使我们想执行比仅仅扫描、测试、设置或重置更复杂的操作，也很容易访问单个位，正如 Intel 汇编语言提供的那样。然而，对于没有位字段的高级语言，我们必须实现某些构造，以便能够访问单个位，这也是汇编语言更为方便的地方。

虽然位和字节指令可能有多种应用，但让我们在 CRC8 示例的上下文中考虑它们（仅仅是其中几个）。说这些指令在该示例中会显著优化它并不完全正确；毕竟，它只会让我们去掉一条指令，使得算法的实现看起来更清晰。我们来看看`crc_loop`会如何变化：

```
crc_loop:
   shl  al, 1     *; Shift left-most bit out to CF*
   setc bl        *; Set bl to 1 if CF==1, or to zero otherwise*
   shl  dl, 1     *; shift left-most bit out to CF*
   setc bh        *; Set bh to 1 if CF==1, or to zero otherwise*
   xor  bl, bh    *; Here we, in fact, are XOR'ing the previously left-most bits of al and dl*
   jz  .noxor     *; Do not add POLY if XOR result is zero*
   xor  dl, poly
.noxor:
   loop crc_loop
```

上述代码非常直观，但让我们更详细地了解一下这一组位指令：

+   **BT**：将目标操作数（位基）中的一位存储到 CF。该位通过源操作数中指定的索引来标识。

+   **BTS**：这与 BT 相同，但它还会设置目标操作数中的位。

+   **BTR**：这与 BT 相同，但它还会重置目标操作数中的位。

+   **BTC**：这与 BT 相同，但它还会反转（补码）目标操作数中的位。

+   **BSF**：这代表**位扫描前移**。它会在源操作数中查找设置的最低有效位。如果找到，该位的索引将返回到目标操作数中。如果源操作数全为零，则目标操作数的值未定义，并且 ZF 被置为 1。

+   **BSR**：这代表**位扫描反向**。它会在源操作数中查找设置的最高有效位。如果找到，该位的索引将返回到目标操作数中。如果源操作数全为零，则目标操作数的值未定义，并且 ZF 被置为 1。

+   **TEST**：此指令使得可以同时检查多个位是否被设置。简而言之，TEST 指令执行逻辑与运算，设置相应的标志，并丢弃结果。

字节指令的格式通常为 SETcc，其中**cc**表示**条件码**。以下是 Intel 平台上的条件码，参照《Intel 64 和 IA-32 架构软件开发者手册 第 1 卷 附录 B EFlags 条件码》的 B.1 条件码部分：

| **助记符 (cc)** | **测试条件** | **状态标志设置** |
| --- | --- | --- |
| O | 溢出 | OF = 1 |
| NO | 无溢出 | OF = 0 |
| B NAE | 小于 既不大于也不等于 | CF = 1 |
| NB AE | 不小于或等于 | CF = 1 |
| E Z | 等于 零 | ZF = 1 |
| NE NZ | 不等于 不为零 | ZF = 0 |
| BE NA | 小于或等于 不大于 | (CF 或 ZF) = 1 |
| NBE A | 既不小于也不等于 大于 | (CF 或 ZF) = 0 |
| S | 符号 | SF = 1 |
| NS | 无符号 | SF = 0 |
| P PE | 奇偶校验 偶校验 | PF = 1 |
| NP PO | 无奇偶校验 奇校验 | PF = 0 |
| L NGE | 小于 既不大于也不等于 | (SF xor OF) = 1 |
| NL GE | 不小于 大于或等于 | (SF xor OF) = 0 |
| LE NG | 小于或等于 不大于 | ((SF xor OF) 或 ZF) = 1 |
| NLE G | 不小于或等于 大于 | ((SF xor OF) 或 ZF) = 0 |

所以，通过前面的表格和 CRC8 示例中的`setc`指令，我们可以得出结论：它指示处理器在 C 条件为真时将`bl`（和`bh`）设置为 1，即 CF == 1。

# 执行流程转移指令

这一组指令使得无论是依据 EFlags/RFlags 寄存器中指定的特定条件，还是完全无条件的，执行流程都可以轻松地进行分支，因此可以将其分为两组：

+   无条件执行流程转移指令：

    +   **JMP**：执行无条件跳转到明确指定的位置。这会将指令指针寄存器加载为指定位置的地址。

    +   **CALL**：此指令用于调用一个过程。它将下一条指令的地址推送到栈中，并将指令指针加载为被调用过程中的第一条指令地址。

    +   **RET**：此指令用于从过程返回。它将栈中存储的值弹出到指令指针寄存器。当在过程末尾使用时，它将执行返回到 CALL 指令后的指令。

        RET 指令可能会有一个 2 字节的操作数，在这种情况下，该值定义了在栈上传递给过程的操作数占用的字节数。然后，栈指针会通过加上字节数自动调整。

    +   **INT**：此指令触发软件中断。

        在 Windows 上编程时，在环 3 中使用此指令相当罕见。甚至可以安全地假设唯一的使用场景是 INT3——软件断点。然而，在 32 位 Linux 上，它用于调用系统调用。

+   条件执行流转移指令：

    +   **Jcc**：这是 JMP 指令的条件变种，其中**cc**代表**条件码**，可以是前面表格中列出的条件码之一。例如，查看 CRC8 示例中的`jz .noxor`行。

    +   **JCXZ**：这是条件跳转指令的特殊版本，使用 CX 寄存器作为条件。只有当 CX 寄存器的值为 0 时，跳转才会执行。

    +   **JECXZ**：这与上面相同，但它作用于 ECX 寄存器。

    +   **JRCXZ**：这与上面相同，但它作用于 RCX 寄存器（仅限长模式）。

    +   **LOOP**：一个以 ECX 作为计数器的循环，这将递减 ECX，并且如果结果不为 0，则将指令指针寄存器加载为循环标签的地址。我们已经在 CRC8 示例中使用了这个指令。

    +   **LOOPZ**/**LOOPE**：这是一个以 ECX 作为计数器的循环，前提是 ZF = 1。

    +   **LOOPNZ**/**LOOPNE**：这是一个以 ECX 作为计数器的循环，前提是 ZF = 0。

为了举例说明，我们实现 CRC8 算法作为一个过程（将以下代码插入到相关 32 位模板的代码部分）：

```
*;*
*; Put your code here*
*; * 
   mov al, 0x16         *; In this specific case we pass the 
                        ; only argument via AL register*
   call crc_proc        *; Call the 'crc_proc' procedure*

 *; For Windows*
   push 0               *; Terminate the process if you are on Windows*
   call [exitProcess]

   *; For Linux          ; Terminate the process if you are on Linux*
   xor  ebx, ebx
   mov  eax, ebx
   inc  eax
   int  0x80

crc_proc:               *; Our CRC8 procedure*
   push ebx ecx edx     *; Save the register we are going to use on stack*
   xor dl, dl           *; Initialise the CRC state register*
   mov ecx, 8           *; Setup counter*
.crc_loop:
   shl al, 1
   setc bl
   shl dl, 1
   setc bh
   xor bl, bh
   jz .noxor
   xor dl, 0x31
.noxor:
   loop .crc_loop
   mov al, dl          *; Setup return value*
   pop edx ecx ebx     *; Restore registers*
   ret                 *; Return from this procedure*
```

# 字符串指令

这是一个有趣的指令组，操作的是字节、字、双字或四字的字符串（仅限长模式）。这些指令只有隐式操作数：

+   源地址应加载到 ESI 寄存器中（长模式下为 RSI 寄存器）

+   目标地址应加载到 EDI 寄存器中（长模式下为 RDI 寄存器）

+   所有指令中，除了 MOVS*和 CMPS*指令之外，都使用了 EAX（例如，AL 和 AX）寄存器的某个变体。

+   迭代次数（如果有的话）应位于 ECX 中（仅与 REP*前缀一起使用）

对于字节数据，ESI 和/或 EDI 寄存器自动增加 1；对于字数据，增加 2；对于双字数据，增加 4。这些操作的方向（增或减 ESI/EDI）由 EFlags 寄存器中的方向标志（DF）控制：DF = 1：递减 ESI/EDI，DF = 0：递增 ESI/EDI。

这些指令可以分为五组。实际上，更准确地说，有五个指令，每个指令支持四种数据大小：

+   **MOVSB**/**MOVSW**/**MOVSD**/**MOVSQ**：这些指令将内存中的字节、字、双字或四字从由 ESI/RSI 指向的位置移动到由 EDI/RDI 指向的位置。指令的后缀指定要移动的数据大小。将 ECX/RCX 设置为要移动的数据项数量，并在其前加上 REP*前缀，指示处理器执行该指令 ECX 次，或者在使用 REP*前缀的条件（如果有的话）为真时执行。

+   **CMPSB**/**CMPSW**/**CMPSD**/**CMPSQ**：这些指令将 ESI/RSI 寄存器指向的数据与 EDI/RDI 寄存器指向的数据进行比较。迭代规则与 MOVS* 指令相同。

+   **SCASB**/**SCASW**/**SCASD**/**SCASQ**：这些指令扫描由 EDI/RDI 寄存器指向的数据项序列（其大小由指令的后缀指定），查找存储在 AL、AX、EAX 或 RAX 中的值，具体取决于操作模式（保护模式或长模式）和指令的后缀。迭代规则与 MOVS* 指令相同。

+   **LODSB**/**LODSW**/**LODSD**/**LODSQ**：这些指令将 AL、AX、EAX 或 RAX（取决于操作模式和指令的后缀）从内存中加载值，该值由 ESI/RSI 寄存器指向。迭代规则与 MOVS* 指令相同。

+   **STOSB**/**STOSW**/**STOSD**/**STOSQ**：这些指令将 AL、AX、EAX 或 RAX 寄存器的值存储到由 EDI/RDI 寄存器指向的内存位置。这些迭代规则与 MOVS* 指令相同。

所有前面的指令都有没有后缀的显式操作数形式，但在这种情况下，我们需要指定操作数的大小。虽然操作数本身不会改变，因此始终是 ESI/RSI 和 EDI/RDI，但我们可以改变的只是操作数的大小。以下是这种情况的示例：

```
scas byte[edi]
```

以下示例展示了 SCAS* 指令的典型用法——扫描一个字节序列（在此特定情况下）以查找存储在 AL 寄存器中的特定值。其他指令的使用方法类似。

```
*; Calculate the length of a string*
   mov   edi, hello
   mov   ecx, 0x100    *; Maximum allowed string length*
   xor   al, al        *; We will look for 0*
   rep scasb           *; Scan for terminating 0*
   or    ecx, 0        *; Check whether the string is too long*
   jz    too_long
   neg   ecx           *; Negate ECX*
   add   ecx, 0x100    *; Get the length of the string*
                       *; ECX = 14 (includes terminating 0)*
too_long:
   *; Handle this*

hello db "Hello, World!", 0
```

`rep` 前缀，在前面的示例中使用，表示处理器应使用 ECX 寄存器作为计数器来执行带前缀的命令（就像它在 LOOP* 指令中使用一样）。但是，还有一个由 ZF（零标志）指定的可选条件。这样的条件由附加在 REP 后面的条件后缀指定。例如，使用 E 或 Z 后缀会指示处理器在每次迭代之前检查 ZF 是否已设置。后缀 NE 或 NZ 会指示处理器在每次迭代之前检查 ZF 是否已重置。考虑以下示例：

```
repz cmpsb
```

这将指示处理器在两个字节序列相等且 ECX 不为零时，持续比较由 EDI/RDI 和 ESI/RSI 寄存器指向的字节序列。

# ENTER/LEAVE

根据英特尔开发者手册，*这些指令为块结构语言中的过程调用提供机器语言支持；*然而，它们对汇编开发者同样非常有用。

在实现一个过程时，我们必须处理栈帧的创建，存储过程变量，存储 ESP 的值，然后在离开过程之前恢复这些内容。这两条指令可以为我们完成所有这些工作：

```
*; Do something here*
call   my_proc
*; Do something else here*

my_proc:
   enter 0x10, 0   *; Save EBP register on stack,*
                   *; save ESP to EBP and*
 *; allocate 16 bytes on stack for procedure variables*
 *;*
 *; procedure body*
 *;*
   leave           *; Restore ESP and EBP registers (this automatically*
                   *; releases the space allocated on stack with ENTER)*
   ret             *; Return from procedure*
```

上述代码等价于以下代码：

```
*; Do something here*
call   my_proc
*; Do something else here*

my_proc:
   push   ebp       *; Save EBP register on stack,*
   mov    ebp, esp  *; save ESP to EBP and*
   sub    esp, 0x10 *; allocate 16 bytes on stack for procedure variables*
 *;*
 *; procedure body*
 *;*
   mov    esp, ebp *; Restore ESP and EBP registers (this automatically*
   pop    ebp       *; releases the space allocated on stack with ENTER)*
   ret              *; Return from procedure*
```

# 标志控制指令

EFlags 寄存器包含有关最后一次 ALU 操作的某些信息以及 CPU 的某些设置（例如，字符串指令的方向）；然而，我们有机制通过以下指令控制该寄存器的内容，甚至是单个标志：

+   **设置**/**清除进位标志** (**STC**/**CLC**)：在某些操作之前，我们可能需要设置或重置 CF。

+   **补充进位标志** (**CMC**)：该指令反转 CF 的值。

+   **设置**/**清除方向标志** (**STD**/**CLD**)：我们可以使用这些指令来设置或重置 DF，以确定在字符串指令中 ESI/EDI（RSI/RDI）是递增还是递减。

+   **将标志加载到 AH 寄存器** (**LAHF**)：某些标志（例如 ZF）没有直接修改的相关指令，因此我们可以将 Flags 寄存器加载到 AH 中，修改相应的位，并用修改后的值重新加载 Flags 寄存器。

+   **将 AH 寄存器存储到标志寄存器** (**SAHF**)：该指令将 AH 寄存器的值存储到标志寄存器中。

+   **设置**/**清除中断标志** (**STI**/**CLI**)（非用户空间）：这些指令用于操作系统级别的中断使能/禁用。

+   **将标志**/**EFlags**/**RFlags 寄存器推送到堆栈** (**PUSHF**/**PUSHFD**/**PUSHFQ**)：LAHF/SAHF 指令可能不足以检查/修改 Flags/EFlags/RFlags 寄存器中的某些标志。通过使用 PUSHF* 指令，我们可以访问其他位（标志）。

+   **从堆栈恢复标志**/**EFlags**/**RFlags 寄存器** (**POPF**/**POPFD**/**POPFQ**)：这些指令将从堆栈中重新加载 Flags/EFlags/RFlags 寄存器的新值。

# 杂项指令

有一些指令没有特别指定的类别，具体如下：

+   **加载有效地址** (**LEA**)：该指令根据处理器的寻址模式，在源操作数中计算有效地址，并将其存储到目标操作数中。当寻址模式中指定的项需要计算时，它也常常作为 ADD 指令的替代使用。以下示例代码展示了这两种情况：

```
lea eax, [some_label] *; EAX will contain the address of some_label*
 lea eax, [ebx + edi] *; EAX will contain the sum of EBX and EDI*
```

+   **无操作** (**NOP**)：顾名思义，该指令不执行任何操作，通常用于填充对齐过程之间的空白。

+   **处理器识别** (**CPUID**)：根据操作数（在 EAX 中）的值，该指令返回 CPU 的识别信息。只有当 EFlags 寄存器中的 ID 标志（第 21 位）被设置时，才可以使用该指令。

# FPU 指令

FPU 指令由 x87 **浮点单元** (**FPU**) 执行，处理浮点、整数或二进制编码十进制值。这些指令根据它们的用途进行分组：

+   FPU 数据传输指令

+   FPU 基本算术指令

+   FPU 比较指令

+   FPU 加载常量指令

+   FPU 控制指令

FPU 操作的另一个重要方面是，与处理器的寄存器不同，浮点寄存器是以堆栈的形式组织的。像`fld`这样的指令用于将操作数压入堆栈顶部，像`fst`这样的指令用于从堆栈顶部读取值，而像`fstp`这样的指令则用于将值从堆栈顶部弹出，并将其他值向顶部移动。

以下示例展示了计算半径为`0.2345`的圆的周长：

```
*; This goes in '.text' section*
fld     [radius]    *; Load radius to ST0*
 *; ST0 <== 0.2345*
fldpi               *; Load PI to ST0*
 *; ST1 <== ST0*
 *; ST0 <== 3.1415926*
fmulp               *; Multiply (ST0 * ST1) and pop*
 *; ST0 = 0.7367034*
fadd    st0, st0    *; * 2*
 *; ST0 = 1.4734069*
fstp    [result]    *; Store result*
 *; result <== ST0*

*; This goes in '.data' section*
radius  dt  0.2345
result  dt  0.0
```

# 扩展

自从第一个 Intel 微处理器问世以来，技术发展显著，处理器架构的复杂性也大大增加。最初的一套指令，虽然现在仍然非常强大，但已无法满足某些任务的需求（在这里我们不得不承认，随着时间的推移，这类任务的数量正在增加）。Intel 采用的解决方案非常好，而且相当用户友好：**指令集架构扩展**（**ISA 扩展**）。从**MMX**（非官方地称为**多媒体扩展**）到 SSE4.2、AVX 和 AVX2 扩展，Intel 走了很长一段路，这些扩展引入了对 256 位数据处理的支持，以及 AVX-512，后者允许处理 512 位数据，并将可用的 SIMD 寄存器数量扩展到 32 个。所有这些都是 SIMD 扩展，SIMD 代表单指令多数据。在本节中，我们将特别关注 AES-NI 扩展，并部分关注 SSE（将在第五章中详细讲解，*并行数据处理*）。

# AES-NI

**AES-NI**代表**高级加密标准新指令**，这是 Intel 在 2008 年首次提出的扩展，旨在加速 AES 算法的实现。

以下代码检查 CPU 是否支持 AES-NI：

```
mov   eax, 1        *; CPUID request code #1*
cpuid
test ecx, 1 shl 25  *; Check bit 25*
jz not_supported    *; If bit 25 is not set - CPU does not support AES-NI*
```

该扩展中的指令相对简单且数量较少：

+   **AESENC**：此指令对 128 位数据执行 AES 加密的一轮，使用 128 位轮密钥，适用于除最后一轮以外的所有加密轮次

+   **AESENCLAST**：此指令对 128 位数据执行 AES 加密的最后一轮

+   **AESDEC**：此指令对 128 位数据执行 AES 解密的一轮，使用 128 位轮密钥，适用于除最后一轮以外的所有解密轮次

+   **AESDECLAST**：此指令对 128 位数据执行 AES 解密的最后一轮

+   **AESKEYGENASSIST**：此指令帮助使用 8 位轮常量（RCON）生成 AES 轮密钥

+   **AESIMC**：此指令对 128 位轮密钥执行逆混合列转换

# SSE

SSE 代表流式 SIMD 扩展，顾名思义，它允许通过单一指令处理多个数据，最典型的例子如下代码所示：

```
lea   esi, [fnum1]
movq  xmm0, [esi]    *; Load fnum1 and fnum2 into xmm0 register*
add   esi, 8
movq  xmm1, [esi]    *; Load fnum3 and fnum4 into xmm1 register*
addps xmm0, xmm1     *; Add two floats in xmm1 to another two floats in xmm0*
 *; xmm0 will then contain:*
 *; 0.0  0.0  1.663  12.44*

fnum1  dd 0.12
fnum2  dd 1.24
fnum3  dd 12.32
fnum4  dd 0.423
```

# 示例程序

如你所注意到，前两节（AES-NI 和 SSE）没有适当的示例。原因在于，展示这两种扩展功能的最佳方式是将它们混合在一个程序中。在这一节中，我们将借助这两个扩展实现一个简单的 AES-128 加密算法。AES 加密是一个经典的例子，显然会从 SSE 提供的数据并行处理中受益。

我们将使用在本章开头准备的模板，因此，我们只需要在这条评论的位置写下以下代码：

```
*;*
*; Put your code here*
*;*
```

代码在 Windows 和 Linux 上运行都一样，因此无需其他准备：

```
 *; First of all we have to expand the key*
 *; into AES key schedule.*
 lea esi, [k]
 movups xmm1, [esi]
 lea edi, [s]

 *; Copy initial key to schedule*
 mov ecx, 4
 rep movsd
 *; Expand the key*
 call aes_set_encrypt_key

 *; Actually encrypt data*
 lea esi, [s] *; ESI points to key schedule*
 lea edi, [r] *; EDI points to result buffer*
 lea eax, [d] *; EAX points to data we want*
 *; to encrypt*
 movups xmm0, [eax] *; Load this data to XMM0*

 *; Call the AES128 encryption procedure*
 call aes_encrypt

 *; Nicely terminate the process*
 push 0
 call [exitProcess]

*; AES128 encryption procedure*
aes_encrypt: *; esi points to key schedule*
 *; edi points to output buffer*
 *; xmm0 contains data to be encrypted*
   mov ecx, 9
   movups xmm1, [esi]
   add esi, 0x10
   pxor xmm0, xmm1          *; Add the first round key*

.encryption_loop:
   movups xmm1, [esi]       *; Load next round key*
   add esi, 0x10
   aesenc xmm0, xmm1        *; Perform encryption round*
   loop .encryption_loop

   movups xmm1, [esi]       *; Load last round key* 
   aesenclast xmm0, xmm1    *; Perform the last encryption round*

   lea edi, [r]
   movups [edi], xmm0       *; Store encrypted data*
   ret

*; AES128 key setup procedures*
*; This procedure creates full*
*; AES128 encryption key schedule*
aes_set_encrypt_key: *; xmm1 contains the key*
 *; edi points to key schedule*
   aeskeygenassist xmm2, xmm1, 1
   call key_expand
   aeskeygenassist xmm2, xmm1, 2
   call key_expand
   aeskeygenassist xmm2, xmm1, 4
   call key_expand
   aeskeygenassist xmm2, xmm1, 8
   call key_expand
   aeskeygenassist xmm2, xmm1, 0x10
   call key_expand
   aeskeygenassist xmm2, xmm1, 0x20
   call key_expand
   aeskeygenassist xmm2, xmm1, 0x40
   call key_expand
   aeskeygenassist xmm2, xmm1, 0x80
   call key_expand
   aeskeygenassist xmm2, xmm1, 0x1b
   call key_expand
   aeskeygenassist xmm2, xmm1, 0x36
   call key_expand
   ret

key_expand: *; xmm2 contains key portion*
 *; edi points to place in schedule*
 *; where this portion should*
 *; be stored at*
 pshufd xmm2, xmm2, 0xff    *; Set all elements to 4th element*
 vpslldq xmm3, xmm1, 0x04   *; Shift XMM1 4 bytes left*
 *; store result to XMM3*
 pxor xmm1, xmm3            
 vpslldq xmm3, xmm1, 0x04
 pxor xmm1, xmm3
 vpslldq xmm3, xmm1, 0x04
 pxor xmm1, xmm3
 pxor xmm1, xmm2
 movups [edi], xmm1
 add edi, 0x10
 ret
```

以下内容应放置在数据段/段落中：

```
 *; Data to be encrypted*
 d db 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa,0xb, 0xc, 0xd, 0xe, 0xf

 *; Encryption key*
 k db 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1

 *; AES key schedule (11 round keys, 16 bytes each)*
 s rb 16 * 11

 *; Result will be placed here*
 r rb 16
```

# 总结

我们以创建两个模板开始本章——一个用于 32 位 Windows 可执行文件，另一个用于 32 位 Linux 可执行文件。虽然这两个模板中有些部分可能仍不清楚，但请不要为此烦恼，因为我们会在适当的时候逐一讲解它们。你可以将这些模板作为自己代码的骨架。

本章最重要的部分，然而，是专门介绍了 Intel 指令集架构本身。当然，这只是一个非常简短的概述，因为没有必要描述每一条指令——Intel 通过发布其程序员手册完成了这项工作，该手册包含超过三千页内容。因此，决定只提供基本信息，帮助我们对 Intel 指令集有一个基本的了解。

本章的最后，我们借助 AES-NI 扩展实现了 AES128 加密算法，这使得 AES128 加密/解密过程变得显著更简单和更容易。

现在，当我们理解了这些指令后，我们准备继续深入学习内存组织以及数据和代码寻址模式。

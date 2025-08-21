# 第五章：并行数据处理

我记得坐在我的 ZX Spectrum 前，64KB 的内存（16KB ROM + 48KB RAM），老式磁带录音机插入其中，新的磁带也放了进去。在磁带上相对较多的程序中，有一个特别引起了我的注意。并不是因为它能做什么特别的事情；毕竟，它只是根据出生日期（事实上，我还必须输入当前日期）计算个人的生物节律图，并在屏幕上绘制出来。算法甚至没有任何复杂性（无论算法如何复杂，本质上只是对某些值进行正弦计算）。让我觉得有趣的是，屏幕上出现了一个“等待结果处理”的提示信息，信息框中出现了一种进度条，持续了将近半分钟（是的，我曾天真地认为在这个信息框“背后”可能真的有计算在进行），同时三个图表似乎同时在绘制。嗯，看起来好像它们是在同时绘制。

该程序是用 BASIC 编写的，因此逆向它是一项相对简单的任务。简单，但令人失望。当然，绘制图表时并没有并行处理，仅仅是同一个函数按顺序在每个点上为每个图表依次调用。

显然，ZX Spectrum 并不是一个适合寻找并行处理能力的平台。而英特尔架构则提供了这样一种机制。在本章中，我们将探讨**Streaming SIMD Extension**（**SSE**）提供的几个功能，它允许对所谓的打包整数、打包的单精度或双精度浮点数进行同时计算，这些数据被包含在 128 位寄存器中。

本章将简要介绍 SSE 技术，回顾其可用的寄存器及访问模式。随后，我们将继续讨论算法本身的实现，该算法涉及与所有三种生物节律相关的单精度浮点值的并行操作。

一些对生物节律图计算至关重要的步骤，在高级语言中实现时非常简单，比如正弦计算、指数运算和阶乘，在这里将详细介绍，因为我们暂时没有访问任何数学库的权限；因此，我们没有现成的实现这些计算所涉及的过程。我们将为每个步骤实现自己的解决方案。

# SSE

英特尔 Pentium II 处理器引入了**MMX**技术（非官方称为**多媒体扩展**，然而这种别名从未在英特尔文档中使用），它使我们能够使用 64 位寄存器处理打包的整数数据。尽管这种技术带来了显著的好处，但至少存在两个缺点：

+   我们只能处理整数数据

+   MMX 寄存器被映射到**浮点单元**（**FPU**）的寄存器上

尽管比没有更好，MMX 技术仍然没有提供足够的计算能力。

随着 Pentium III 处理器的推出，情况发生了很大变化，它引入了自己的 128 位寄存器和指令集，允许在标量或打包字节、32 位整数、32 位单精度浮点值或 64 位双精度浮点值上执行广泛的操作，且支持流式 SIMD 扩展。

# 寄存器

基于 Intel 的处理器有 8 个 XMM 寄存器可供 SSE 使用，在 32 位平台上，这些寄存器命名为 XMM0 到 XMM7，而在 64 位平台上，命名为 XMM0 到 XMM15。需要注意的是，在 64 位平台上，只有 8 个 XMM 寄存器可用，且只有在非长模式下。

每个 XMM 寄存器的内容可以被视为以下类型之一：

+   16 字节（我们在 AES-NI 实现中看到的）

+   八个 16 位字

+   四个 32 位双字

+   四个 32 位单精度浮点数（我们将在本章中以这种方式使用寄存器）

+   两个 64 位四字

+   两个 64 位双精度浮点数

SSE 指令能够对寄存器的相同部分作为操作数进行操作，也可以对操作数的不同部分进行操作（例如，它们可以将源寄存器的低位部分移动到目标寄存器的高位部分）。

# 版本更新

目前，SSE 指令集（以及该技术）有五个版本，分别如下：

+   **SSE**：这一技术于 1999 年推出，包含了该技术及其指令的初步设计

+   **SSE2**：此版本随 Pentium 4 发布，带来了 144 条新指令

+   **SSE3**：虽然 SSE3 仅增加了 13 条新指令，但它引入了执行所谓“水平”操作的能力（在单个寄存器上执行的操作）

+   **SSSE3**：这一版本引入了 16 条新指令，其中包括用于水平整数操作的指令

+   **SSE4**：这一版本带来了另外 54 条指令，从而极大地方便了开发人员

# 生物节律计算器

我之前提到过，我想重申的是，在我看来，理解和学习事物的最好方式是通过示例。我们通过提到一个旧的生物节律水平计算程序开始了这一章，似乎当这个程序使用 SSE 架构实现时，它可能是一个简单而又很好的例子，展示了如何执行并行计算。下一节中的代码展示了 2017 年 5 月 9 日到 2017 年 5 月 29 日之间，针对我个人的生物节律计算，将结果存储到一个表格中。所有的计算（包括指数运算和正弦运算）都是使用 SSE 指令实现的，显然也使用了 XMM 寄存器。

# 这个想法

“生物节律”一词源于两个希腊词；“bios”意为生命，“rhythmos”意为节奏。这个概念最早由德国耳鼻喉科医生威廉·弗里斯提出，他生活在十九世纪末至二十世纪初。他认为我们的生活受到生物周期的影响，这些周期影响着我们的心理、身体和情感方面。

弗里斯推导出了三个主要的生物节律周期：

+   **身体周期**

    持续时间：23 天

    表示：

    +   协调性

    +   力量

    +   健康状况

+   **情感周期**

    持续时间：28 天

    表示：

    +   创造力

    +   敏感性

    +   心情

    +   觉察力

+   **智力周期**

    持续时间：33 天

    表示：

    +   警觉性

    +   分析和逻辑能力

    +   通信

这个理论本身可能相当有争议，特别是因为大多数科学界认为它是伪科学；然而，它足够科学，至少可以作为并行数据处理机制的一个示例。

# 算法

生物节律计算的算法相当简单，可以说是微不足道的。

用于指定特定日期下每个生物节律的变化率的变量值在(-1.0, 1.0)范围内，并使用以下公式计算：

*x = sin((2 * PI * t) / T)*

在这里，*t*表示从某人出生日期到我们希望了解其生物节律值的日期（很可能是当前日期）所经过的天数，*T*是给定生物节律的周期。

借助 SSE 技术，我们能优化的东西并不多。我们可以做的确实是一次性计算所有三种生物节律的数据，这足以展示 Streaming SIMD Extension 的能力和威力。

# 数据部分

由于源文件中各部分没有特定的顺序，我们将从数据部分开始简要查看，以更好地理解代码。数据部分，或者更准确地说，数据在数据部分的排列，是相当自明的。重点放在数据对齐上，允许通过对齐的 SSE 指令更快地访问：

```
section '.data' data readable writeable
   *; Current date and birth date*
 *; The dates are arranged in a way most suitable*
 *; for use with XMM registers*
   cday   dd 9               *; Current day of the month*
   cyear  dd 2017            *; Current year*
   bday   dd 16              *; Birth date day of the month*
   byear  dd 1979            *; Birth year*

   cmonth dd 5               *; 1-based number of current month*
          dd 0              
   bmonth dd 1               *; 1-based number of birth month*
          dd 0

   *; These values are used for calculation of days*
 *; in both current and birth dates*
   dpy    dd 1.0
          dd 365.25

   *; This table specifies number of days since the new year*
 *; till the first day of specified month.*
 *; Table's indices are zero based*
monthtab:
         dd 0   *; January*
         dd 31  *; February*
         dd 59  *; March*
         dd 90  *; April*
         dd 120 *; May*
         dd 151 *; June*
         dd 181 *; July*
         dd 212 *; August*
         dd 243 *; September*
         dd 273 *; October*
         dd 304 *; November*
         dd 334 *; December*

 align 16
 *; Biorhythmic periods*
 T       dd 23.0 *; Physical*
         dd 28.0 *; Emotional*
         dd 33.0 *; Intellectual*

 pi_2    dd 6.28318 *; 2xPI - used in formula*

 align 16
 *; Result storage*
 *; Arranged as table:*
 *; Physical : Emotional : Intellectual : padding*
 output  rd 20 * 4

*; '.idata' section: contains import information,* 
*; is readable, is writeable*
section '.idata' import data readable writeable

*; 'library' macro from 'win32a.inc' creates* 
*; proper entry for importing*
*; functions from a dynamic link library.* 
*; For now it is only 'kernel32.dll'.*
library kernel, 'kernel32.dll'

*; 'import' macro creates the actual entries* 
*; for functions we want to import from a dynamic link library*
import kernel,\
 exitProcess, 'ExitProcess'
```

# 代码

我们将从 32 位 Windows 的标准模板开始（如果你使用的是 Linux，可以安全地使用 Linux 模板）。

# 标准头文件

首先，我们告诉汇编器我们期望的输出类型，即 GUI 可执行文件（尽管它没有任何 GUI），我们的入口点是什么，当然，我们还包括`win32a.inc`文件，以便能够调用`ExitProcess()`Windows API。然后，我们创建代码部分：

```
format PE GUI                             *; Specify output file format*
entry _start                              *; Specify entry point*
include 'win32a.inc'                      *; Include some macros*
section '.text' code readable executable  *; Start code section*
```

# `main()`函数

以下是 C/C++中`main()`函数的类比，它控制着整个算法，并负责执行所有必要的准备工作以及预报计算循环的执行。

# 数据准备步骤

首先，我们需要对日期进行一些小的修正（月份以其数字表示）。我们关注的是从 1 月 1 日到某个月第一天的天数。进行此修正的最简单和最快方法是使用一个包含 12 个条目的小表格，表格中包含了 1 月 1 日到每个月第一天的天数。这个表格叫做 `monthtab`，并且位于数据段中。

```
*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;*
*;*
*; Entry point*
*;*
*;-----------------------------------------------------*
_start:
   mov ecx, 20                     *; Length of biorhythm data to* 
 *; produce*

   mov eax, [bmonth]               *; Load birth month*
   dec eax                         *; Decrement it in order to address* 
 *; 0-based array*

   mov eax, [monthtab + eax * 4]   *; Replace month with number of days*
 *; since New Year*
   mov [bmonth], eax               *; Store it back*

   mov eax, [cmonth]               *; Do the same for current month*
   dec eax
   mov eax, [monthtab + eax * 4]
   mov [cmonth], eax

   xor eax, eax                *; Reset EAX as we will use it as counter*
```

上述代码展示了此修复的应用：

+   我们从出生日期中读取月份数字

+   由于我们使用的表格实际上是一个 0 基数组，因此需要将其递减

+   用从表格中读取的值替换原始的月份数字

顺便提一下，读取表格值时使用的寻址模式是比例/索引/基址/位移的变体。正如我们所看到的，`monthtab` 是位移，`eax` 寄存器存储索引，4 是比例因子。

这两个日期的日/月/年特别安排以便正确地适应 XMM 寄存器并简化计算。看起来，以下代码的第一行是将 `cday` 的值加载到 XMM0 中，但实际上，所用的指令是从 `cday` 的地址开始加载 `xmmword`（128 位数据类型），意味着它将四个值加载到 XMM0 中：

| **位 96 - 127** | **位 64 - 95** | **位 32 - 63** | **位 0 - 31** |
| --- | --- | --- | --- |
| `byear` | `bday` | `cyear` | `cday` |
| 1979 | 16 | 2017 | 9 |

XMM0 寄存器中的数据表示

类似地，第二条 `movaps` 指令加载了 XMM1 寄存器，从 `cmonth` 的地址开始加载四个双字：

| **位 96 - 127** | **位 64 - 95** | **位 32 - 63** | **位 0 - 31** |
| --- | --- | --- | --- |
| 0 | `bmonth` | 0 | `cmonth` |
| 0 | 0 | 0 | 120 |

XMM1 寄存器中的数据表示

如我们所见，当将两个表格直接放置在彼此之上并将其视为 XMM 寄存器 0 和 1 时，我们在 XMM0 和 XMM1 中加载了 `cmonth`/`cday` 和 `bmonth`/`bday`，它们共享相同的双字。我们将在稍后看到这种数据安排为何如此重要。

`movaps` 指令只能在两个 XMM 寄存器之间，或者一个 XMM 寄存器和一个 16 字节对齐的内存位置之间移动数据。若要访问未对齐的内存位置，应使用 `movups`。

在以下代码片段的最后两行中，我们将刚刚加载的双字值转换为单精度浮点数：

```
   movaps xmm0, xword[cday]    *; Load the day/year parts of both dates*
   movapd xmm1, xword[cmonth]  *; Load number of days since Jan 1st for both dates*
   cvtdq2ps xmm0, xmm0         *; Convert loaded values to single precision floats*
   cvtdq2ps xmm1, xmm1
```

我们仍然没有完成将日期转换为天数的操作，因为年份依然是年份，并且每个月的天数和两个日期从 1 月 1 日开始的天数仍然分别存储。我们在对每个日期的天数进行求和之前，只需要将每一年乘以 365.25（其中 0.25 是对闰年的补偿）。然而，XMM 寄存器的部分内容无法像通用寄存器的部分内容那样被单独访问（例如，在 EAX 中没有类似 AX、AH、AL 的部分）。不过，我们可以通过使用特殊指令来操作 XMM 寄存器的部分内容。在以下代码片段的第一行，我们将 XMM2 寄存器的低 64 位部分加载到存储在 `dpy`（每年天数）位置的两个浮动值中。这些值是 `1.0` 和 `365.25`。你可能会问，`1.0` 与此有何关系，答案可以在下表中看到：

| **位 96 - 127** | **位 64 - 95** | **位 32 - 63** | **位 0 - 31** | **寄存器名称** |
| --- | --- | --- | --- | --- |
| 1979.0 | 16.0 | 2017.0 | 9.0 | XMM0 |
| 0.0 | 0.0 | 0.0 | 120.0 | XMM1 |
| 0.0 | 0.0 | 365.25 | 1.0 | XMM2 |

XMM0 - XMM2 寄存器的内容

对 XMM 寄存器的打包操作（打包意味着对多个值进行操作）大多数时候是按列进行的。因此，为了将 `2017.0` 乘以 `365.25`，我们需要将 XMM2 与 XMM0 相乘。然而，我们也不能忘记 `1979.0`，最简单的方式是使用 `movlhps` 指令将 XMM2 寄存器的低部分内容复制到其高部分。

```
   movq xmm2, qword[dpy]  *; Load days per year into lower half of XMM2*
   movlhps xmm2, xmm2     *; Duplicate it to the upper half*
```

在这些指令执行后，XMM0 - XMM2 寄存器的内容应该如下所示：

| **位 96 - 127** | **位 64 - 95** | **位 32 - 63** | **位 0 - 31** | **寄存器名称** |
| --- | --- | --- | --- | --- |
| 1979.0 | 16.0 | 2017.0 | 9.0 | XMM0 |
| 0.0 | 0.0 | 0.0 | 120.0 | XMM1 |
| 365.25 | 1.0 | 365.25 | 1.0 | XMM2 |

执行 movlhps 后，XMM0 - XMM2 寄存器的内容

使用 `pinsrb`/`pinsrd`/`pinsrq` 指令在需要时将单个字节/双字/四字插入 XMM 寄存器中。为了演示水平操作，这些指令在我们的代码中并未使用。

现在我们可以安全地进行乘法和加法运算：

```
addps xmm1, xmm0      *; Summation of day of the month with days since January 1st*
mulps xmm2, xmm1      *; Multiplication of years by days per year*
haddps xmm2, xmm2     *; Final summation of days for both dates*
hsubps xmm2, xmm2     *; Subtraction of birth date from current date*
```

上述代码首先计算从 1 月 1 日到两日期月日的总天数。在第二行，最后，它将两个日期的年份乘以每年的天数。这一行也解释了为什么每年天数的值后面伴随着 `1.0`——因为我们在将 XMM1 与 XMM2 相乘时，不希望丢失之前计算的天数，我们只需将从 1 月 1 日以来的天数乘以 `1.0`。

此时，三个 XMM 寄存器的内容应该如下所示：

| **位 96 - 127** | **位 64 - 95** | **位 32 - 63** | **位 0 - 31** | **寄存器名称** |
| --- | --- | --- | --- | --- |
| 1979.0 | 16.0 | 2017.0 | 9.0 | XMM0 |
| 1979.0 | 16.0 | 2017.0 | 129.0 | XMM1 |
| 722829.75 | 16.0 | 736709.25 | 129.0 | XMM2 |

XMM0 - XMM2 寄存器在加上天数并乘以每年天数后，XMM2 和 XMM1 寄存器相对部分的内容

还有两个操作需要执行：

+   完成每个日期的总天数计算

+   从较早的日期中减去较晚的日期

到这时，我们需要用于计算的所有值都已存储在单个寄存器 XMM2 中。幸运的是，SSE3 引入了两条重要指令：

+   `haddps`：单精度值的水平加法

    将目标操作数的前两个双字和后两个双字中的单精度浮点值相加，并将结果分别存储到目标操作数的前两个双字中。第三个和第四个双字也会被覆盖，第三个双字的值与第一个双字相同，第四个双字的值与第二个双字相同。

+   `hsubps`：单精度值的水平减法

    从目标操作数的第二个双字中减去单精度浮点值，再从目标操作数的第三个双字中减去目标操作数第四个双字的值，并将结果分别存储到目标操作数的前两个双字和后两个双字中。

完成`hsubps`指令后，寄存器的内容应为：

| **位 96 - 127** | **位 64 - 95** | **位 32 - 63** | **位 0 - 31** | **寄存器名称** |
| --- | --- | --- | --- | --- |
| 1979.0 | 16.0 | 2017.0 | 9.0 | XMM0 |
| 1979.0 | 16.0 | 2017.0 | 129.0 | XMM1 |
| 13992.5 | 13992.5 | 13992.5 | 13992.5 | XMM2 |

XMM0 - XMM2 寄存器在加法和随后减法操作后的内容

如我们所见，XMM2 寄存器包含两个日期之间的天数（出生日期和当前日期）减去 1，因为出生当天不包括在内（此问题将在计算循环中解决）；

```
movd xmm3, [dpy]       *; Load 1.0 into the lower double word of XMM3*
movlhps xmm3, xmm3     *; Duplicate it to the third double word of XMM3*
movsldup xmm3, xmm3    *; Duplicate it to the second and fourth double words of XMM3*
```

前三行通过加载存储在`dpy`中的双字（值为`1.0`）来设置我们预测的步长，并将此值传播到整个 XMM3 寄存器中。我们将在每个新的预测日期中将 XMM3 加到 XMM2。

接下来的三行与前面三行在逻辑上类似；它们将 XMM4 寄存器的四个单精度浮点值设置为*2*PI*：

```
movd xmm4, [pi_2]
movlhps xmm4, xmm4
movsldup xmm4, xmm4
```

进入计算循环之前的最后一步：我们将 XMM1 加载上生物节律周期的长度，并将`eax`寄存器设置为指向我们将存储输出数据（预测结果）的位置。根据数据段中数据的排列，XMM1 寄存器的第四个单精度值将被加载为*2*PI*，但是，由于第四个单精度值在我们的计算中不被使用，我们将其保持原样。当然，我们也可以使用`pinsrd xmm1, eax, 3`指令将其清零：

```
movaps xmm1, xword[T]
lea eax, [output]
```

现在，我们已经设置好了数据，并准备好计算给定日期范围内的生物节律值。寄存器 XMM0 到 XMM4 现在应该具有以下值：

| **96 - 127 位** | **64 - 95 位** | **32 - 63 位** | **0 - 31 位** | **寄存器名称** |
| --- | --- | --- | --- | --- |
| 1979.0 | 16.0 | 2017.0 | 9.0 | XMM0 |
| 6.2831802 | 33.0 | 28.0 | 23.0 | XMM1 |
| 13992.5 | 13992.5 | 13992.5 | 13992.5 | XMM2 |
| 1.0 | 1.0 | 1.0 | 1.0 | XMM3 |
| 6.2831802 | 6.2831802 | 6.2831802 | 6.2831802 | XMM4 |

# 计算循环

一旦所有准备工作完成，我们生成预测的计算循环相当简单。首先，我们增加天数值，这具有双重作用——在第一次迭代中，解决了不包括出生日的问题，并在剩余迭代中将当前日期向前推一天。

第二条指令将 XMM4 寄存器复制到 XMM0，这将用于大部分计算，并将其与 XMM2 中的天数乘以第三条指令执行——实际上计算了公式中的(*2*PI*t*)部分。

第四条指令通过将 XMM0 除以生物节律周期长度来完成我们需要计算正弦值的值的计算：

```
.calc_loop:
   addps xmm2, xmm3    *; Increment the number of days by 1.0*
   movaps xmm0, xmm4   *; Set XMM0 to contain 2*PI values*
   mulps xmm0, xmm2    *; Actually do the 2*PI*t*
   divps xmm0, xmm1    *; And complete by (2*PI*t)/T*
```

现在我们需要计算这些值的正弦值，这有点棘手，因为我们将使用正弦计算的算法和相对较大的数值。解决方案很简单——我们需要将这些值归一化，使其适合(*0.0, 2*PI*)范围。这由`adjust()`过程实现：

```
   call adjust        *; Adjust values for sine computations*
```

调整了 XMM0 中的值（忽略 XMM0 的第四部分值，因为它不相关），我们现在可以为寄存器的前三个单精度浮点部分计算正弦：

```
   call sin_taylor_series  *; Compute sine for each value*
```

我们将计算得到的正弦值存储到由`eax`寄存器指向的表中（由于该表在 16 字节边界上对齐，我们可以安全地使用`movaps`指令，比其`movups`对应指令稍快）。然后，我们将表指针前进 16 字节，递减 ECX，并在 ECX 不为 0 时继续循环，使用`loop`指令。

当 ECX 达到`0`时，我们简单地终止进程：

```
   movaps [eax], xmm0     *; Store the result of current iteration*

   add eax, 16
   loop .calc_loop

   push 0
   call [exitProcess]
```

表在循环结束时应包含以下值：

| **日期** | **身体（P）** | **情感（S）** | **智力（I）** | **无关** |
| --- | --- | --- | --- | --- |
| 2017 年 5 月 9 日 | 0.5195959 | -0.9936507 | 0.2817759 | -NAN |
| 2017 年 5 月 10 日 | 0.2695642 | -0.9436772 | 0.4582935 | -NAN |
| 2017 年 5 月 11 日 | -8.68E-06 | -0.8462944 | 0.6182419 | -NAN |
| 2017 年 5 月 12 日 | -0.2698165 | -0.7062123 | 0.7558383 | -NAN |
| 2017 年 5 月 13 日 | -0.5194022 | -0.5301577 | 0.8659862 | -NAN |
| 2017 年 5 月 14 日 | -0.7308638 | -0.3262038 | 0.9450649 | -NAN |
| 2017 年 5 月 15 日 | -0.8879041 | -0.1039734 | 0.9898189 | -NAN |
| 2017 年 5 月 16 日 | -0.9790764 | 0.1120688 | 0.9988668 | -NAN |
| 2017 年 5 月 17 日 | -0.9976171 | 0.3301153 | 0.9718016 | -NAN |
| 2017 年 5 月 18 日 | -0.9420508 | 0.5320629 | 0.909602 | -NAN |
| 2017 年 5 月 19 日 | -0.8164254 | 0.7071083 | 0.8145165 | -NAN |
| 2017 年 5 月 20 日 | -0.6299361 | 0.8467072 | 0.6899831 | -NAN |
| 2017 年 5 月 21 日 | -0.3954292 | 0.9438615 | 0.5407095 | -NAN |
| 2017 年 5 月 22 日 | -0.128768 | 0.9937283 | 0.3714834 | -NAN |
| 2017 年 5 月 23 日 | 0.1362932 | 0.9936999 | 0.1892722 | -NAN |
| 2017 年 5 月 24 日 | 0.3983048 | 0.9438586 | -8.68E-06 | -NAN |
| 2017 年 5 月 25 日 | 0.6310154 | 0.8467024 | -0.18929 | -NAN |
| 2017 年 5 月 26 日 | 0.8170633 | 0.7069295 | -0.371727 | -NAN |
| 2017 年 5 月 27 日 | 0.9422372 | 0.5320554 | -0.5407244 | -NAN |
| 2017 年 5 月 28 日 | 0.9976647 | 0.3303373 | -0.6901718 | -NAN |

# 正弦输入值的调整

如我们所见，使用 SSE 指令非常方便和有效；尽管我们大多是在从内存加载数据到寄存器并在寄存器内移动数据，但我们还没有看到它的实际效果。计算循环中有两个过程执行实际的计算，其中一个是 `adjust()` 过程。

由于算法整体非常简单，而且由于两个过程仅从一个地方调用，因此我们没有遵循任何特定的调用约定；相反，我们使用 XMM0 寄存器传递浮点值，使用 ECX 寄存器传递整数参数。

对于 `adjust()` 过程，我们只有一个参数，它已经加载到 XMM0 寄存器中，因此我们只需调用该过程：

```
*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;*
*;*
*; Value adjustment before calculation of SIN()*
*; Parameter is in XMM0 register*
*; Return value is in XMM0 register*
*;-----------------------------------------------------*
adjust:
   push ebp
   mov ebp, esp
   sub esp, 16 * 2      *; Create the stack frame for local variables*
```

这是为局部变量和临时存储程序中使用的非通用寄存器创建堆栈帧的标准方式，方法是将堆栈指针 ESP/RSP 保存到 EBP/RBP 寄存器中（我们可以自由使用其他通用寄存器）。通用寄存器可以通过在分配局部变量空间后立即发出 push 指令保存到堆栈中。局部变量空间的分配通过从 ESP/RSP 寄存器中减去变量的总大小来实现。

分配空间的寻址方式在以下代码中显示：

```
   movups [ebp - 16], xmm1      *; Store XMM1 and XMM2 registers*
   movups [ebp - 16 * 2], xmm2
```

在前两行中，我们临时存储了 XMM1 和 XMM2 寄存器的内容，因为我们将要使用它们，但需要保留它们的值。

输入值的调整非常简单，可以通过以下 C 语言代码表示：

```
return v - 2*PI*floorf(v/(2*PI));
```

然而，在 C 语言中，我们必须对每个值调用此函数（除非使用内建函数），而在汇编语言中，我们可以通过一些简单的 SSE 指令同时调整这三个值：

```
movd xmm1, [pi_2]        *; Load singles of the XMM1 register with 2*PI*
movlhps xmm1, xmm1
movsldup xmm1, xmm1
```

我们已经熟悉了上述的顺序，它将一个双字加载到 XMM 寄存器并复制到其中的每个单精度浮点部分。这里，我们将 *2*PI* 加载到 XMM1。

以下算法执行实际的计算：

+   我们将输入参数复制到 XMM2 寄存器中

+   将它的单精度浮点数除以 *2*PI*

+   向下舍入结果（SSE 没有地板或天花板指令，取而代之的是我们可以使用`roundps`并在第三个操作数中指定舍入模式；在我们的案例中，我们指示处理器粗略地向下舍入）

+   将向下舍入的结果乘以*2*PI*

+   从初始值中减去它们，得到适合于（*0.0, 2*PI*）范围的结果

其汇编实现如下：

```
   movaps xmm2, xmm0           *; Move the input parameter to XMM2*
   divps xmm2, xmm1            *; Divide its singles by 2*PI*
   roundps xmm2, xmm2, 1b      *; Floor the results*
   mulps xmm2, xmm1            *; Multiply floored results by 2*PI*
   subps xmm0, xmm2            *; Subtract resulting values from the* 
 *; input parameter*

   movups xmm2, [ebp - 16 * 2] *; Restore the XMM2 and XMM1 registers*
   movups xmm1, [ebp - 16]

   mov esp, ebp                *; "Destroy" the stack frame and return*
   pop ebp
   ret
```

最后一次操作的结果已经在 XMM0 中，因此我们只需从过程返回到计算循环。

# 计算正弦

我们很少会考虑如何计算正弦或余弦，而不实际拥有一个已知直角三角形的两条直角边和斜边长度。至少有两种方法可以快速高效地进行这些计算：

+   **CORDIC 算法**：这代表**坐标旋转数字计算机**。它在简单计算器或原始硬件设备中实现。

+   **泰勒级数**：一种快速的近似算法。它不提供准确值，但足以满足我们的需求。

另一方面，LIBC 使用不同的算法，我们可以在这里实现，但这将远远超过一个简单的示例。因此，我们在代码中使用的是最简单的近似算法的简单实现，它为我们提供了相当不错的精度（比本程序需要的精度更高），精度可达到小数点后六位——这是用于三角函数的泰勒级数（也称为麦克劳林级数）。

使用泰勒级数计算正弦的公式如下：

*sin(x) = x - x³/3! + x⁵/5! - x⁷/7! + x⁹/9! ...*

这里，省略号表示一个无限函数。然而，我们不需要无限运行它来获得令人满意的精度（毕竟，我们只关心小数点后两位），相反，我们将运行它 8 次迭代。

就像`adjust()`过程一样，我们不会遵循任何特定的调用约定，并且由于我们需要计算正弦的参数已经在 XMM0 中，因此我们将其保留在那里。`sin_taylor_series`过程的头部对我们来说没有任何新内容：

```
*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;*
*;*
*; Calculation of SIN() using the Taylor Series*
*; approximation:*
*; sin(x) = x - x³/3! + x⁵/5! - x⁷/7! + x⁹/9! ...*
*; Values to calculate the SIN() of are in XMM0 register*
*; Return values are in XMM0 register*
*;-----------------------------------------------------*
sin_taylor_series:
   push ebp                       *; Create stack frame for 5 XMM registers*
   mov ebp, esp
   sub esp, 5 * 16
   push eax ecx                   *; Temporarily store EAX and ECX*
   xor eax, eax                   *; and set them to 0*
   xor ecx, ecx

   movups [ebp - 16], xmm1        *; Temporarily store XMM1 to XMM5 on stack or, to be more*
   movups [ebp - 16 * 2], xmm2    *; precise, in local variables.*
   movups [ebp - 16 * 3], xmm3
   movups [ebp - 16 * 4], xmm4
   movups [ebp - 16 * 5], xmm5

   movaps xmm1, xmm0              *; Copy the parameter to XMM1 and XMM2*
   movaps xmm2, xmm0

   mov ecx, 3                     *; Set ECX to the first exponent*
```

以下计算循环很简单，且不包含我们尚未见过的指令。然而，有两个过程调用，每个调用有两个参数。参数通过 XMM0 寄存器传递（三个单精度浮点数），ECX 寄存器包含当前使用的指数值：

```

.l1:
   movaps xmm0, xmm2     *; Exponentiate the initial parameter*
   call pow
   movaps xmm3, xmm0

   call fact             *; Calculate the factorial of current exponent*
   movaps xmm4, xmm0

   divps xmm3, xmm4      *; Divide the exponentiated parameter by the factorial of the exponent*
   test eax, 1           *; Check iteration for being odd number, add the result to accumulator*
 *; subtract otherwise*
   jnz .plus
   subps xmm1, xmm3
   jmp @f
.plus:
   addps xmm1, xmm3
@@:                     *; Increment current exponent by 2*
   add ecx, 2           
   inc eax
   cmp eax, 8           *; and continue till EAX is 8*
   jb .l1

   movaps xmm0, xmm1    *; Store results into XMM0*
```

所有计算已完成，现在我们得到了三个输入的正弦值。对于第一次迭代，XMM0 中的输入如下：

| **位 96 - 127** | **位 64 - 95** | **位 32 - 63** | **位 0 - 31** | **寄存器名称** |
| --- | --- | --- | --- | --- |
| （无关紧要） | 0.28564453 | 4.8244629 | 2.5952148 | XMM0 |

此外，我们的`sin()`近似值通过泰勒级数八次迭代后的结果如下：

| **位 96 - 127** | **位 64 - 95** | **位 32 - 63** | **位 0 - 31** | **寄存器名称** |
| --- | --- | --- | --- | --- |
| （无关） | 0.28177592 | -0.99365967 | 0.51959586 | XMM0 |

这展示了一个完美的（至少对于我们的需求来说）近似级别。然后，我们恢复之前保存的 XMM 寄存器并返回到调用程序：

```
   movups xmm1, [ebp - 16]
   movups xmm2, [ebp - 16 * 2]
   movups xmm3, [ebp - 16 * 3]
   movups xmm4, [ebp - 16 * 4]
   movups xmm5, [ebp - 16 * 5]

   pop ecx eax
   mov esp, ebp
   pop ebp
   ret
```

# 指数运算

我们在`sin_taylor_series`过程中使用了指数运算，这个算法在处理实数作为指数时并不像看起来那么简单；然而，我们很幸运，因为泰勒级数仅使用自然数来进行这类运算。但值得一提的是，如果我们需要更大的指数，算法将会变得非常缓慢。因此，我们的指数运算算法实现尽可能简单——我们仅仅将参数 XMM0 自乘 ECX-1 次。ECX 会减少 1 次，因为不需要计算`x¹`：

```
*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;*
*;*
*; Trivial exponentiation function*
*; Parameters are:*
*; Values to exponentiate in XMM0*
*; Exponent is in ECX*
*; Return values are in XMM0*
*;-----------------------------------------------------*
pow:
   push ebp
   mov ebp, esp
   sub esp, 16

   push ecx
   dec ecx                    *; The inputs are already x1 so we decrement the exponent*
   movups [ebp - 16], xmm1

   movaps xmm1, xmm0          *; We will be mutliplying XMM0 by XMM1*
.l1:
   mulps xmm0, xmm1
   loop .l1

   movups xmm1, [ebp - 16]
   pop ecx
   mov esp, ebp
   pop ebp
   ret
```

# 阶乘

我们还使用了阶乘，因为我们将指数值除以其阶乘。给定数字`n`的阶乘是所有小于或等于`n`的正整数的积：

```
*;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;*
*;*
*; Simple calculation of factorial*
*; Parameter is in ECX (number to calculate the factorial of)*
*; Return value is in XMM0 register*
*;-----------------------------------------------------*
fact:
   push ebp
   mov ebp, esp
   sub esp, 16 * 3

   push ecx
   movups [ebp - 16], xmm1
   movups [ebp - 16 * 2], xmm2
   mov dword[ebp - 16 * 3], 1.0
   movd xmm2, [ebp - 16 * 3]
   movlhps xmm2, xmm2
   movsldup xmm2, xmm2
   movaps xmm0, xmm2
   movaps xmm1, xmm2

.l1:
   mulps xmm0, xmm1
   addps xmm1, xmm2
   loop .l1

   movups xmm2, [ebp - 16 * 2]
   movups xmm1, [ebp - 16]
   pop ecx
   mov esp, ebp
   pop ebp
   ret
```

# AVX-512

本章如果没有提到 AVX-512（高级矢量扩展 512 位）将不完整。事实上，它由多个扩展组成，而其中只有核心扩展——AVX-512F（"F"代表基础）是所有处理器的必需部分。AVX-512 不仅增加了新的指令，还极大增强了并行（矢量化）计算的实现，使得可以对最长达 512 位的单精度或双精度浮点值的向量进行计算。此外，增加了 32 个新的 512 位寄存器（ZMM0 - ZMM31），其三元逻辑使其类似于专用平台。

# 总结

本章中的示例代码旨在展示现代基于 Intel 的处理器的并行数据处理能力。当然，所使用的技术远不能提供如 CUDA 等架构的强大功能，但它确实能够显著加速某些算法。尽管我们这里工作的算法非常简单，几乎不需要任何优化，因为它仅使用 FPU 指令就能实现，我们几乎看不出任何区别，但它仍然展示了如何同时处理多个数据。一个更好的应用场景可能是解决*n*体问题，因为 SSE 允许在三维空间内同时计算所有向量，甚至可以实现多层感知器（人工神经网络的一种类型），这使得能够一次性处理多个神经元；如果网络足够小，还可以将它们都存放在可用的 XMM 寄存器中，无需从/向内存移动数据。特别需要注意的是，有时看似复杂的过程，当使用 SSE 实现时，可能仍然比单条 FPU 指令更快。

现在我们至少了解了一项可能让我们生活更轻松的技术，我们将学习汇编器如何通过宏指令，尽管不能简化工作，但肯定能减轻汇编开发者的工作负担。类似于 C 语言或其他支持类似功能的编程语言中的宏，宏指令能够带来显著的积极影响，允许通过一个宏指令替换一系列指令，反复或有条件地汇编或跳过某些指令序列，甚至在汇编器不支持我们所需指令时，创建新的指令（虽然我还没有遇到过这种情况，但“永远不要说永远”）。

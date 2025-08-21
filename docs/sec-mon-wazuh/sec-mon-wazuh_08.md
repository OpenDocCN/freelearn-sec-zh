

# 附录

我们现在已经进入了*附录*章节。在这里，我们将介绍几个自定义 Wazuh 规则。Wazuh 已经构建了数千条规则以增强其检测能力。然而，我们将编写一些重要的自定义 Wazuh 规则，以检测 PowerShell、Linux Auditd、Kaspersky 和 Sysmon 相关的警报。本章节涵盖以下主题：

+   自定义 PowerShell 规则

+   自定义 Auditd 规则

+   自定义 Kaspersky Endpoint Security 规则

+   自定义 Sysmon 规则

# 自定义 PowerShell 规则

为了增强 Wazuh 对 Windows 机器的检测能力，我们需要集成一些自定义 PowerShell Wazuh 规则。每个规则可以根据特定条件、严重性级别和其他可选配置进行创建。在本节中，我们将涵盖以下几种类型的规则：

+   PowerShell 事件信息

+   PowerShell 错误日志

+   PowerShell 警告日志

+   PowerShell 关键日志

## PowerShell 事件信息

我们可以创建一个自定义 PowerShell 规则来获取事件信息，如下所示：

```
<rule id="200101" level="1">
    <if_sid>60009</if_sid>
    <field name="win.system.providerName">^PowerShell$</field>
    <options>no_full_log</options>
    <group>windows_powershell,</group>
    <description>PowerShell Log Information</description>
  </rule>
```

这里，我们有以下内容：

+   `<if_sid>60009</if_sid>`：这表示规则 ID 列表。当列表中的某个规则 ID 与之匹配时，它将触发。规则 ID `60009` 是一个用于 Windows 信息性事件的预构建 Wazuh 规则。

+   `<field name="win.system.providerName">^PowerShell$</field>`：`<field>` 标签用作触发规则的必要条件。它将检查解码器提取的字段内容是否匹配。在这种情况下，它将检查 `win.system.providerName` 日志字段是否包含 `PowerShell` 关键字。

+   `<group>windows_powershell,</group>`：这强制将警报分类到特定组中。在这种情况下，它是 `windows_powershell`。

## PowerShell 错误日志

PowerShell 错误日志通常包含与错误、警告和其他事件相关的信息。为了检测这些 PowerShell 错误日志，我们可以创建自定义 Wazuh 规则，如下所示：

```
<rule id="200102" level="7">
    <if_sid>60011</if_sid>
    <field name="win.system.providerName">^Microsoft-Windows-PowerShell$</field>
    <mitre>
      <id>T1086</id>
    </mitre>
    <options>no_full_log</options>
    <group>windows_powershell,</group>
    <description>Powershell Error logs</description>
  </rule>
```

这里，我们有以下内容：

+   `<if_sid>60011</if_sid>`：这表示规则 ID 列表。当列表中的某个规则 ID 与之匹配时，它将触发。规则 ID `60011` 是一个用于 Windows 错误事件的预构建 Wazuh 规则。

+   `<field name="win.system.providerName">^Microsoft-Windows-PowerShell$</field>`：`<field>` 标签用作触发规则的必要条件。它将检查解码器提取的字段内容是否匹配。在这种情况下，它将检查 `win.system.providerName` 日志字段是否包含 `Microsoft-Windows-PowerShell` 关键字。

+   `<group>windows_powershell,</group>`：这强制将警报分类到特定组中。在这种情况下，它是 `windows_powershell`。

## PowerShell 警告日志

PowerShell 在脚本执行期间还会生成非关键警报。这对于安全调查很有帮助。为了在 Wazuh 管理器上检测这些警报，我们可以创建自定义 Wazuh 规则，如下所示：

```
<rule id="200103" level="5">
    <if_sid>200101</if_sid>
    <field name="win.system.providerName">^Microsoft-Windows-PowerShell$</field>
    <field name="win.system.severityValue">^WARNING$</field>
    <options>no_full_log</options>
    <group>windows_powershell,</group>
    <description>Powershell Warning Event</description>
  </rule>
```

这里，我们有以下内容：

+   `<field name="win.system.providerName">^Microsoft-Windows-PowerShell$</field>`: `<field>`标签用作触发规则的必要条件。它将检查解码器提取的字段内容是否匹配。在这种情况下，它将检查`win.system.providerName`日志字段是否包含`Microsoft-Windows-PowerShell`关键字。

+   `<field name="win.system.severityValue">^WARNING$</field>`: 它将检查`win.system.severityValue`日志字段是否包含`WARNING`关键字。

+   `<group>windows_powershell,</group>`: 这将强制警报被分类到一个特定的组中。在这种情况下，它是`windows_powershell`。

## PowerShell 关键日志

PowerShell 生成关键警报，当执行过程中出现严重错误时。为了检测此类警报，我们可以创建自定义 Wazuh 规则，如下所示：

```
<rule id="200103" level="12">
    <if_sid>60012</if_sid>
    <field name="win.system.providerName">^Microsoft-Windows-PowerShell$</field>
    <mitre>
      <id>T1086</id>
    </mitre>
    <options>no_full_log</options>
    <group>windows_powershell,</group>
    <description>Powershell Critical EventLog</description>
  </rule>
```

这里，我们有如下内容：

+   `<field name="win.system.severityValue">^WARNING$</field>`: 它将检查`win.system.severityValue`日志字段是否包含`WARNING`关键字。

+   `<group>windows_powershell,</group>`: 这将强制警报被分类到一个特定的组中。在这种情况下，它是`windows_powershell`。

这完成了一些重要的自定义 PowerShell 规则。在下一部分，我们将介绍 Linux Auditd 模块的 Wazuh 规则。

# 针对 Auditd 的自定义 Wazuh 规则

针对 Auditd 的自定义 Wazuh 规则提供了一种增强 Wazuh 检测 Linux 命令执行能力的定制方法。这也将帮助安全团队检测关键的安全事件，追踪用户活动，并确保合规性。

## Auditd 系统调用规则

我们可以创建一个 Wazuh 规则来检测任何系统调用（syscall）事件，如下所示：

```
  <rule id="200200" level="3">
    <decoded_as>auditd-syscall</decoded_as>
    <description>Auditd: System Calls Event </description>
    <group>syscall,</group>
  </rule>
```

这里，我们有如下内容：

+   `<decoded_as>auditd-syscall</decoded_as>`: 这是触发规则的必要条件。只有当事件被特定的`decoder`解码时，它才会被触发。在这种情况下，它是`auditd-syscall`。

## Auditd 路径

Linux Auditd 会为每个路径记录生成一个事件。我们将创建一个 Wazuh 规则来捕获 Auditd 路径消息事件，如下所示：

```
  <rule id="200201" level="3">
    <decoded_as>auditd-path</decoded_as>
    <description>Auditd: Path Message event.</description>
    <group>path,</group>
  </rule>
```

这里，我们有如下内容：

+   `<decoded_as>auditd-syscall</decoded_as>`: 这是触发规则的必要条件。只有当事件被特定的`decoder`解码时，它才会被触发。在这种情况下，它是`auditd-path`。

## 检测用户环境中的变化

为了检测用户环境中的任何变化，我们可以创建一个自定义 Wazuh 规则来检测`bash_profile`的变化，如下所示：

```
<rule id="200202" level="12">
  <if_sid>200201</if_sid>
  <list field="audit.directory.name" lookup="address_match_key">etc/lists/bash_profile</list>
  <description> Auditd: Detects change of user environment</description>
  <group>path,</group>
  </rule>
```

这里，我们有如下内容：

+   `<list field="audit.directory.name" lookup="address_match_key">etc/lists/bash_profile</list>`: `<list>`标签执行 CDB 查找，`field`属性用作 CBD 列表中的关键字。在这种情况下，使用 CDB 列表`audit.directory.name`，并使用`address_match_key`来查找 IP 地址和关键字。

我们已经学习了如何为 Linux Auditd 模块构建自定义的 Wazuh 规则。在下一节中，我们将为卡巴斯基终端安全解决方案构建 Wazuh 规则。

# 卡巴斯基终端安全的自定义 Wazuh 规则

**卡巴斯基终端安全** 是一家领先的安全提供商，提供云安全、嵌入式安全、威胁管理和工业安全。为了增强 Wazuh 检测卡巴斯基终端警报的能力，我们需要创建自定义的 Wazuh 规则。在本节中，我们将涵盖以下主题：

+   卡巴斯基的通用规则

+   检测卡巴斯基代理重新启动的规则

+   隔离警报的规则

## 卡巴斯基的通用规则

卡巴斯基终端安全会生成一些常规警报。要检测这些警报，需要创建以下 Wazuh 规则：

```
  <rule id="200300" level="0">
    <if_sid>60009</if_sid>
    <field name="win.system.channel">^Kaspersky Event Log$</field>
    <options>no_full_log</options>
    <description>Kapersky rule for the System channel</description>
  </rule>
```

在这里，我们有以下内容：

+   `<field name="win.system.channel">^Kaspersky Event Log$</field>`：它将检查 `win.system.channel` 日志字段是否包含 `Kaspersky Event` `Log` 关键字

## 用于检测卡巴斯基代理重新启动事件的规则

要检测卡巴斯基代理重新启动的事件，需要创建自定义的 Wazuh 规则，如下所示：

```
<rule id="200301" level="10">
   <if_sid>200300</if_sid>
   <field name="win.system.providerName">klnagent</field>
     <field name="win.system.eventID">1</field>
     <description>Kaspersky Agent Restarted</description>
  </rule>
```

在这里，我们有以下内容：

+   `<field name="win.system.providerName">klnagent</field>`：它将检查 `win.system.providerName` 日志字段是否包含 `klnagent<field name="win.system.eventID">1</field>` 关键字。这表示 Windows 事件日志中的另一个字段。此规则将在 `eventID` 值为 `1` 时触发。在 Windows 事件日志中，`eventID` 1 通常表示系统启动或日志会话的开始，或者 Windows 时间服务的重新启动。

## 隔离警报的规则

要检测可疑文件是否已被隔离，我们可以创建自定义的 Wazuh 规则来触发警报，如下所示：

```
<rule id="200302" level="10">
   <if_sid>200300</if_sid>
   <field name="win.system.providerName">klnagent</field>
   <field name="win.system.message" type="pcre2">(?i)^"Quarantine</field>
     <description>Kaspersky Agent - Quarantine Event</description>
  </rule>
```

在这里，我们有以下内容：

+   `<field name="win.system.message" type="pcre2">(?i)^"Quarantine</field>`：它将检查 `win.system.message` 日志字段是否包含 `Quarantine.<field name="win.system.message" type="pcre2">(?i)^"Quarantine</field>` 关键字。这指定 Windows 事件日志中的另一个字段；这次是 `message` 字段。此规则将在消息中包含 `Quarantine` 关键字时触发。这是通过使用称为 **Perl Compatible Regular Expressions**（**PCRE2**）的正则表达式库完成的。

我们已经学习了如何构建自定义的 Wazuh 规则来检测卡巴斯基终端安全事件。在下一节中，我们将构建用于检测 Sysmon 事件的自定义规则。

# Sysmon 的自定义 Wazuh 规则

**Sysmon** – 一款 Windows Sysinternals 工具 – 提供了系统相关活动的深入视图。Sysmon 帮助我们检测广泛的活动，如进程创建、文件创建与修改、注册表更改、驱动加载、DLL 加载、命名管道创建、进程访问和 DNS 查询日志记录。为了扩展 Wazuh 的检测能力，我们需要构建一个自定义 Wazuh 规则来生成警报。总共有 30 个 Sysmon 事件，如微软官网所述（[`learn.microsoft.com/en-us/sysinternals/downloads/sysmon`](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)）。不过，我们将涵盖与一些特定 MITRE ATT&CK 技术关联的最重要的 Sysmon 事件。这些规则参考了 SOCFortress 官方 GitHub 账户 – 一个基于 SaaS 的网络安全平台。你也可以参考以下链接，查看所有与 MITRE 技术关联的 Wazuh 规则列表：[`github.com/socfortress/Wazuh-Rules/tree/main/Windows_Sysmon`](https://github.com/socfortress/Wazuh-Rules/tree/main/Windows_Sysmon)。在本节中，我们将介绍一些重要的 Sysmon 事件，如下所示：

+   Sysmon 事件 1：进程创建

+   Sysmon 事件 2：进程更改了文件创建时间

+   Sysmon 事件 3：网络连接

+   Sysmon 事件 7：加载的映像

+   Sysmon 事件 10：进程访问

+   Sysmon 事件 11：文件创建

+   Sysmon 事件 12：注册表事件（对象创建与删除）

+   Sysmon 事件 13：注册表事件（值设置）

+   Sysmon 事件 14：注册表事件（键和值重命名）

+   Sysmon 事件 15：文件创建 StreamHash

+   Sysmon 事件 17：管道创建

+   Sysmon 事件 18：管道事件

+   Sysmon 事件 22：DNS 请求

## Sysmon 事件 1：进程创建

Wazuh 规则用于检测 *进程创建* 事件，帮助安全团队监控可疑的未经授权的进程执行，其写法如下：

```
<rule id="200401" level="3">
    <if_sid>61603</if_sid>
    <description>Sysmon - Event 1: Process creation $(win.eventdata.description)</description>
    <mitre>
<id>T1546</id>
</mitre>
    <options>no_full_log</options>
    <group>sysmon_event1,windows_sysmon_event1,</group>
  </rule>
```

在这里，我们有以下内容：

+   `<if_sid>61603</if_sid>`：`<if_sid>` 标签作为触发规则的前提条件。在这种情况下，规则 `200401` 仅在父规则 `61603` 匹配时触发。规则 ID `61603` 已在 Wazuh 管理器中的文件 `0595-win-sysmon_rules.xml` 下创建。

## Sysmon 事件 2：进程更改了文件创建时间

Sysmon 模块的文件创建事件检测潜在感染的文件或意外的文件更改，提供有关基于文件的恶意软件威胁的见解。Sysmon 事件 2 的自定义 Wazuh 规则可以如下创建：

```
<rule id="200402" level="3">
  <if_sid>61604</if_sid>
  <field name="win.eventdata.RuleName">^technique_id=T1099,technique_name=Timestomp$</field>
  <description>Sysmon - Event 2: A process changed a file creation time by $(win.eventdata.image)</description>
  <mitre>
  <id>T1099</id>
  </mitre>
  <options>no_full_log</options>
  <group>sysmon_event2,</group>
  </rule>
</group>
```

在这里，我们有以下内容：

+   `<if_sid>61604</if_sid>`：`<if_sid>` 标签作为触发规则的前提条件。在这种情况下，规则 `200402` 仅在父规则 `61604` 匹配时触发。规则 ID `61604` 已在 Wazuh 管理器中的文件 `0595-win-sysmon_rules.xml` 下创建。

## Sysmon 事件 3：网络连接

Sysmon 事件 3 在检测到任何异常或未经授权的网络连接时生成。 要检测此类网络连接，我们可以创建一个自定义的 Wazuh 规则，如下所示：

```
<rule id="200403" level="3">
<if_sid>61605</if_sid>
<field name="win.eventdata.RuleName">^technique_id=T1021,technique_name=Remote Services$</field>
<description>Sysmon - Event 3: Network connection by $(win.eventdata.image)</description>
<mitre>
<id>T1021</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event3,</group>
</rule>
```

在这里，我们有以下内容：

+   `<if_sid>61605</if_sid>`：`<if_sid>` 标签用作触发规则的先决条件。 在本例中，仅当父规则 `61605` 匹配时，规则 `200403` 才会被触发。 规则 ID `61605` 已经在 Wazuh 管理器中的文件名 `0595-win-sysmon_rules.xml` 下创建。

## Sysmon 事件 7：图像加载

当恶意代码注入到正常进程中时，将生成图像加载事件。 Wazuh 规则用于检测此类事件如下：

```
<rule id="200404" level="3">
<if_sid>61609</if_sid>
<field name="win.eventdata.RuleName">^technique_id=T1059.001,technique_name=PowerShell$</field>
<description>Sysmon - Event 7: Image loaded by $(win.eventdata.image)</description>
<mitre>
<id>T1059</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event7,</group>
</rule>
```

在这里，我们有以下内容：

+   `<if_sid>61609</if_sid>`：`<if_sid>` 标签用作触发规则的先决条件。 在本例中，仅当父规则 `61609` 匹配时，规则 `200404` 才会被触发。 规则 ID `61609` 已经在 Wazuh 管理器中的文件名 `0595-win-sysmon_rules.xml` 下创建。

## Sysmon 事件 10：进程访问

进程访问事件帮助安全团队检测可疑活动，如进程内存修改或注入，通常与高级攻击链相关。 要可视化此类事件，需要创建以下 Wazuh 规则：

```
<rule id="200405" level="3">
<if_sid>61612</if_sid>
<field name="win.eventdata.RuleName">^technique_id=T1003,technique_name=Credential Dumping$</field>
<description>Sysmon - Event 10: ProcessAccess by $(win.eventdata.sourceimage)</description>
<mitre>
<id>T1003</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event_10,</group>
</rule>
```

在这里，我们有以下内容：

+   `<if_sid>61612</if_sid>`：`<if_sid>` 标签用作触发规则的先决条件。 在本例中，仅当父规则 `61612` 匹配时，规则 `200405` 才会被触发。 规则 ID `61612` 已经在 Wazuh 管理器中的文件名 `0595-win-sysmon_rules.xml` 下创建。

## Sysmon 事件 11：文件创建

文件创建事件为文件创建监控提供了冗余，并帮助提供了面向基于文件的恶意软件威胁的最大覆盖范围。 可以创建一个 Wazuh 规则来检测此类事件，如下所示：

```
<rule id="200406" level="3">
<if_sid>61613</if_sid>
<field name="win.eventdata.RuleName">^technique_id=T1546.011,technique_name=Application Shimming$</field>
<description>Sysmon - Event 11: FileCreate by $(win.eventdata.image)</description>
<mitre>
<id>T1546</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event_11,</group>
</rule>
```

在这里，我们有以下内容：

+   `<if_sid>61613</if_sid>`：`<if_sid>` 标签用作触发规则的先决条件。 在本例中，仅当父规则 `61613` 匹配时，规则 `200406` 才会被触发。 规则 ID `61609` 已经在 Wazuh 管理器中的文件名 `0595-win-sysmon_rules.xml` 下创建。

## Sysmon 事件 12：注册表事件（对象创建和删除）

Sysmon 事件 12 在创建新的注册表键或子键或删除现有键时捕获日志。 这对于检测未经授权的注册表更改非常有用，这可能表明存在无文件恶意软件。 可以创建一个 Wazuh 规则来检测此类事件，如下所示：

```
<rule id="200407" level="3">
<if_sid>61614</if_sid>
<field name="win.eventdata.RuleName">^technique_id=T1546.011,technique_name=Application Shimming$</field>
<description>Sysmon - Event 12: RegistryEvent (Object create and delete) by $(win.eventdata.image)</description>
<mitre>
<id>T1546</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event_12,</group>
</rule>
```

在这里，我们有以下内容

+   `<if_sid>61614</if_sid>`：`<if_sid>` 标签用作触发规则的先决条件。 在本例中，仅当父规则 `61614` 匹配时，规则 `200407` 才会被触发。 规则 ID `61614` 已经在 Wazuh 管理器中的文件名 `0595-win-sysmon_rules.xml` 下创建。

## Sysmon 事件 13：注册表事件（值设置）

Sysmon 事件 13 在设置新值或修改现有值时触发，发生在注册表键内。这一事件对于检测与恶意软件持久性或权限升级技术相关的变化至关重要。可以创建 Wazuh 规则来检测此类事件，如下所示：

```
<rule id="200408" level="3">
<if_sid>61615</if_sid>
<field name="win.eventdata.RuleName">^technique_id=T1546.011,technique_name=Application Shimming$</field>
<description>Sysmon - Event 13: RegistryEvent (Value Set) by $(win.eventdata.image)</description>
<mitre>
<id>T1546</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event_13,</group>
</rule>
```

这里，我们有以下内容：

+   `<if_sid>61615</if_sid>`：`<if_sid>` 标签用于触发规则的必要条件。在这种情况下，规则 `200408` 只有在父规则 `61615` 匹配时才会触发。规则 ID `61615` 已在 Wazuh 管理器中创建，文件名为 `0595-win-sysmon_rules.xml`。

+   `<field name="win.eventdata.RuleName">^technique_id=T1546.011,technique_name=Application Shimming$</field>`：`<field>` 标签用于触发规则的必要条件。它将检查由解码器提取的字段内容是否匹配。在这种情况下，它将检查 `win.eventdata.RuleName` 日志字段是否包含 `technique_id=T1546.011,technique_name=Application Shimming` `l` 关键字。

## Sysmon 事件 14：注册表事件（键和值重命名）

Sysmon 事件 14 在注册表键或值重命名时触发。这些技术可以被高级攻击者用来逃避反恶意软件检测或破坏系统。可以创建 Wazuh 规则来检测此类事件，如此处所写：

```
<rule id="200409" level="3">
  <if_sid>61616</if_sid>
  <field name="win.eventdata.RuleName">^technique_id=T1546.011,technique_name=Application Shimming$</field>
  <description>Sysmon - Event 14: RegistryEvent (Key and Value Rename) by $(win.eventdata.image)</description>
  <mitre>
  <id>T1546</id>
  </mitre>
  <options>no_full_log</options>
  <group>sysmon_event_14,</group>
  </rule>
```

这里，我们有以下内容：

+   `<if_sid>61616</if_sid>`：`<if_sid>` 标签用于触发规则的必要条件。在这种情况下，规则 `200409` 只有在父规则 `61615` 匹配时才会触发。规则 ID `61615` 已在 Wazuh 管理器中创建，文件名为 `0595-win-sysmon_rules.xml`。

+   `<field name="win.eventdata.RuleName">^technique_id=T1546.011,technique_name=Application Shimming$</field>`：`<field>` 标签用于触发规则的必要条件。它将检查由解码器提取的字段内容是否匹配。在这种情况下，它将检查 `win.eventdata.RuleName` 日志字段是否包含 `technique_id=T1546.011,technique_name=Application Shimming` `l` 关键字。

## Sysmon 事件 15：文件创建 StreamHash

Sysmon 事件 15 捕获带有文件哈希的文件创建活动。要创建 Wazuh 规则以检测此类事件，我们可以创建一个自定义规则，如下所示：

```
  <rule id="200410" level="3">
  <if_sid>61617</if_sid>
  <field name="win.eventdata.RuleName">^technique_id=T1089,technique_name=Drive-by Compromise$</field>
  <description>Sysmon - Event 15: FileCreateStreamHash by $(win.eventdata.image)</description>
  <mitre>
  <id>T1089</id>
  </mitre>
  <options>no_full_log</options>
  <group>sysmon_event_15,</group>
  </rule>
```

这里，我们有以下内容：

+   `<if_sid>61617</if_sid>`：`<if_sid>` 标签用于触发规则的必要条件。在这种情况下，规则 `200410` 只有在父规则 `61617` 匹配时才会触发。规则 ID `61617` 已在 Wazuh 管理器中创建，文件名为 `0595-win-sysmon_rules.xml`。

+   `<field name="win.eventdata.RuleName">^technique_id=T1089,technique_name=Drive-by Compromise$</field>`：`<field>` 标签用于触发规则的必要条件。它将检查由解码器提取的字段内容是否匹配。在这种情况下，它将检查 `win.eventdata.RuleName` 日志字段是否包含 `technique_id=T1089,technique_name=Drive-by Compromise` `l` 关键字。

## Sysmon 事件 17：管道创建

Sysmon 事件 17 记录命名管道的创建，这允许在系统中进行进程间通信。这有助于识别与设置命名管道相关的可疑活动。可以创建自定义 Wazuh 规则来检测此类事件，如下所示：

```
<rule id="200411" level="3">
<if_sid>61646</if_sid>
<field name="win.eventdata.RuleName">^technique_id=T1021.002,technique_name=SMB/Windows Admin Shares$</field>
<description>Sysmon - Event 17: PipeEvent (Pipe Created) by $(win.eventdata.image)</description>
<mitre>
<id>T1021</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event_17,</group>
</rule>
```

这里，我们有以下内容：

+   `<if_sid>61646</if_sid>`：`<if_sid>` 标签作为触发规则的必要条件。在这种情况下，只有当父规则 `61646` 匹配时，规则 `200411` 才会被触发。规则 ID `61646` 已在 Wazuh 管理器中创建，文件名为 `0595-win-sysmon_rules.xml`。

+   `<field name="win.eventdata.RuleName">^technique_id=T1021.002,technique_name=SMB/Windows Admin Shares$</field>`：`<field>` 标签作为触发规则的必要条件。它将检查解码器提取的字段内容是否匹配。在这种情况下，它将检查 `win.eventdata.RuleName` 日志字段是否包含 `"technique_id=T1021.002,technique_name=SMB/Windows Admin` `Shares` 关键字。

## Sysmon 事件 18：管道事件

Sysmon 事件 18 捕获有关管道的额外信息，例如打开、关闭或读取命名管道，有助于检测系统中的异常行为。可以创建 Wazuh 规则来检测此类事件，如下所示：

```
<rule id="200412" level="3">
<if_sid>61647</if_sid>
<field name="win.eventdata.RuleName">^technique_id=T1021.002,technique_name=SMB/Windows Admin Shares$</field>
<description>Sysmon - Event 18: PipeEvent (Pipe Connected) by $(win.eventdata.image)</description>
<mitre>
<id>T1021</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event_18,</group>
</rule>
```

这里，我们有以下内容

+   `<if_sid>61647</if_sid>`：`<if_sid>` 标签作为触发规则的必要条件。在这种情况下，只有当父规则 `61647` 匹配时，规则 `200412` 才会被触发。规则 ID `61646` 已在 Wazuh 管理器中创建，文件名为 `0595-win-sysmon_rules.xml`。

+   `<field name="win.eventdata.RuleName">^technique_id=T1021.002,technique_name=SMB/Windows Admin Shares$</field>`：`<field>` 标签作为触发规则的必要条件。它将检查解码器提取的字段内容是否匹配。在这种情况下，它将检查 `win.eventdata.RuleName` 日志字段是否包含 `technique_id=T1021.002,technique_name=SMB/Windows Admin` `Shares` 关键字。

## Sysmon 事件 22：DNS 请求

Sysmon 事件 22 记录由机器上的进程发起的 DNS 请求。这有助于我们监控可能指向恶意服务器或指挥控制中心的请求。可以创建 Wazuh 规则来检测此类 DNS 请求，如下所示：

```
<rule id="200413" level="3">
<if_sid>61644</if_sid>
<description>Sysmon - Event 22: DNS Request by $(win.eventdata.image)</description>
<mitre>
<id>T1071</id>
</mitre>
<options>no_full_log</options>
<group>sysmon_event_22,</group>
</rule>
```

这里，我们有以下内容：

+   `<if_sid>61644</if_sid>`：`<if_sid>` 标签作为触发规则的必要条件。在这种情况下，只有当父规则 `61644` 匹配时，规则 `200412` 才会被触发。规则 ID `61644` 已在 Wazuh 管理器中创建，文件名为 `0595-win-sysmon_rules.xml`。

我们已经学习了如何为 Wazuh 创建自定义 Sysmon 规则。我们可以在每个 Sysmon 事件类别下创建多个粒度化的规则。要查看所有 Wazuh 自定义 Sysmon 规则的列表，您可以访问官方的 SOCFortress GitHub 仓库：[`github.com/socfortress/Wazuh-Rules/tree/main/Windows_Sysmon`](https://github.com/socfortress/Wazuh-Rules/tree/main/Windows_Sysmon)。

# 总结

在本章中，我们介绍了一些重要的自定义 Wazuh 规则，涵盖了不同类型的事件，如 PowerShell 事件、Linux Auditd 事件、卡巴斯基端点保护事件和 Sysmon 事件。在下一章中，我们将介绍与 Wazuh 平台相关的一些重要术语。

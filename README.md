# TASSL
## 北京江南天安科技有限公司支持国密证书和协议的TASSL

OpenSSL是一套件开放源代码的安全套接字密码学基础库，囊括主要的密码算法、常用的密钥和证书封装管理功能及SSL/TLS协议，并提供丰富的API，以供应用程序开发、测试或其它目的使用。它广泛地集成在各种类型的操作系统中，作为其基础组件之一，深爱广大IT爱好者的喜爱。即使用某些操作系统没有将其集成为组件，通过源代码下载，也是十分轻松地构建OpenSSL的开发及应用环境。
 
尽管OpenSSL的功能十分强大且丰富，也包含了国密的相关算法，但是对于国密的SSL协议并不支持。这对于推广及研究中国商用密码体系的广大密码爱好者来说，却是十分无奈的事情。
 国内也存在着不少密码界同仁，尝试着将OpenSSL国密化，但其大多都局限于公司内部交流使用，这对于国密SSL的推广不利。针对这种现状，北京江南天安公司经过长时间的研究分析，于2017年上半年推出天安版国密OpenSSL，也就是TaSSL，解决了中国商用密码体系无法构建基于OpenSSL应用的实际问题。现在我们又推出了给予openssl-1.1.1b版本的tassl-1.1.1b_R_0.8版本。现以源码的形式提供出来，供大家参考使用，为促进国密的推广和应用贡献自己的一份力量。

### (一)天安TaSSL-1.1.1b_v1.0版本的功能特点
1.支持调用江南天安加密机或加密卡进行加速和物理安全防护。

2.适配了nginx-1.16.0支持国密，nginx开源地址：https://github.com/jntass/Nginx_Tassl

3.适配了360浏览器和密信浏览器的访问。

4.修复了bug和一些其他问题。

#### ssl相关的API
1. CNTLS_client_method()：获取国密TLSv1.1标准协议的相关SSL/TLS相关方法，以使用客户端使用标准的TLSv1.1协议进行握手、通讯；
2. *SSL_CTX_check_enc_private_key()、SSL_check_enc_private_key()、SSL_use_enc_PrivateKey()、SSL_use_enc_PrivateKey_ASN1()、SSL_CTX_use_enc_PrivateKey()、SSL_CTX_use_enc_PrivateKey_ASN1()、SSL_use_enc_PrivateKey_file()、SSL_CTX_use_enc_PrivateKey_file()*
为支持国密双证书体系而添加的函数。

### (三)TASSL使用说明
1. 目前开源的版本是基于OpenSSL 1.1.1b  26 Feb 2019版本；

2.	下载tassl-1.1.1b_v0.8版本。
下载地址：https://github.com/jntass/TASSL-1.1.1b/archive/v0.8.tar.gz

3.	上传至编译环境，进行解压编译。

    tar xvf TASSL-1.1.1b-0.8.tar.gz

    cd TASSL-1.1.1b-0.8

    chmod u+x ./config

    ./config --prefix=/root/lib_r/tassl

    make

    make install

4.	进入安装目录，除了标准的openssl库和头文件外，还会有tassl_demo的例子目录

    cd /root/lib_r/tassl/tassl_demo，其中：

    a)	cert目录:

    包含生成测试证书的脚本gen_sm2_cert.sh

    执行./ gen_sm2_cert.sh则生成测试证书目录certs

    b)	crypto目录：

    包含测试国密算法的示例

    执行./mk.sh进行编译测试

    c)	ssl目录：

    包含国密ssl通讯的客户端和服务端

    执行./mk.sh进行编译测试


### (四)关于江南天安

地址：北京市海淀区马甸东路17号金澳国际大厦11层1110室

邮编：100088 

电话：010-82326383 

传真：010-82328039 

邮箱：tassl@tass.com.cn 

网址：www.tass.com.cn 

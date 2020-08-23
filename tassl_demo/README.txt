20200823_V_1.4:
1.修改查找加密证书逻辑：从证书链的最后一个开始查找,找到第一个带有数据加密功能的证书后，作为加密证书。
2.修改client_key_exchange时，签名时分配的字节数为最大的022100，所以真正签名完成时要设置真实数值，因为有的服务端不认后面带00的加密密文。

20200526_V_1.3:
1:优化取加密证书的逻辑，在证书栈中查找第一个具有数据加密的用途的证书作为加密证书。
2:屏蔽掉当国密版本为0x0101时，不要进行downgrade，防止ssl_fill_hello_random()随机数的最后8字节被填充为固定值。
3:默认的sm2 curve_id为00， 如果用249则条件编译 -DSTD_CURVE_ID; 默认的sm2秘钥协商用ZB+ZA的顺序，如果需要颠倒，条件编译-DSTD_ZAZB.
4.修改tls_construct_cke_sm2dh()中，使用签名私钥的引擎来产生临时秘钥对，如果不存在，则使用软算法产生。
5.增加ECDSA_sign中当eckey存在sign方法，且设置了EC_FLAG_TASS_CUSTOM_SIGN标志后，调用eckey中的方法。
6.增加支持SSL握手时进行裸签标志，EC_FLAG_TASS_NO_Z_SIGN,通过EC_KEY_set_flags()设置。
7.openssl sm4-cbc支持通过-K 40指定使用tasscard_sm4引擎进行加解密通过40号索引的秘钥。
8.增加card_engine 目录，提供调用卡的例子。

20200328_V_1.2:
1:调整变量声明位置，支持Windows下64位编译。
2:支持国密信封转换到卡加密的密文秘钥输出.

20200315_V_1.1:
1:跟新关于tasscard_engine的调用逻辑，支持单独调用sm2和sm4系列算法。

20200218_V_1.0:
1:修改ssl建链时，加载加密证书的方法为SSL_CTX_use_enc_certificate_file，替换原来使用SSL_CTX_use_certificate_file自动选择，因为有的证书用法不规范。
2.更新util/libcrypto.num和libssl.num文件，修复安装到操作系统后导致的链接问题。

20200210_V_0.9:
1:增加引擎支持tasscard_sm4，调用加密卡进行运算sm4.
2.修复部分内存泄漏。

20191127_V_0.8:
1:修复部分内存泄漏。
2:增加自动安装tassl_demo功能。

20190821_V_0.7:
1:支持tasshsm引擎的pkey模式。
2:支持tasscard引擎的pkey模式。

20190821_V_0.6:
1:修复在客户端不使用CNTLS_client_method()时，进行ssl握手时，clienthello不在发送国密算法套件和扩展选项中支持的签名算法中的国密算法的签名算法。
2.修复在重用session时，获取的ssl版本为国密的0x0101, 判断为非标准ssl版本而报错的问题。

20190605_V_0.5:
1:修复了在windows下编译时，cl编译器无法识别的一些临时变量的定义。
2:修复了int_ctx_new对于NID_sm2初始化时的id的重新赋值，为了调用EVP_PKEY_encrypt_init()成功初始化。

20190523_V_0.4:
1:修复了一些提交PR后的，反馈的一些bug.

20190509_V_0.3:
1:增加支持最多10个sm2曲线id的设置，通过set_sm2_group_id_custom()多次调用设置，设置成功返回1。
2:增加了rsa+sm3(0x0701)签名算法，在国密ssl握手时，sm2+sm3(0x0703)优先级最高，其次是rsa+sm3(0x0701).
3.增加了unix-Makefile.tmpl中对于国密头文件的config安装。
4:修复客户端套件为ECC-SM4-SM3且版本号为tls1.2时，服务端使用了ecdsa+sha256(0x0403)而没有使用国密的sigalg对(0x0703)的问题。
5:修复编译时增加-Werror选项时，在IOS平台(其他平台类似)编译时的报错告警导致的停止编译问题。
6.修复utils/mkdef.pl中对于CNSM算法无法识别而告警的问题。

20190313_V_0.2:
1:修复openssl命令s_client和s_server创建测试客户端和服务端无法连接的问题。
2:增加openssl命令s_client和s_server创建国密的测试客户端和服务端。通过-cert_enc,-key_enc指定加密证书和加密私钥。
3:修改sm2曲线的默认group_id为249，并且增加int set_sm2_group_id_custom(uint16_t value)函数进行配置,需要在ssl连接之前调用。
4:openssl更新为1.1.1b。

20190222_V_0.1:
1.通过cert目录下的SM2certgen.sh生成测试证书在certs目录下。
2.通过ssl目录下的sm2cli和sm2svr进行ssl握手的建立，使用的证书是第一步中产生的测试证书。
3.通过crypto目录下的程序，进行sm系列的算法测试，目前暂时有些国密算法没有全部测试。
4.每个目录下通过执行./mk.sh 编译测试程序, ./mk.sh clean删除测试程序。
5.安装目录默认放在/root/tassl-1.1.1b_lib中, 所以执行./config --prefix=/root/tassl-1.1.1b_lib。

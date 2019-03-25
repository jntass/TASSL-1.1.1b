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
5.安装目录默认放在/root/tassl-1.1.1_lib中, 所以执行./config --prefix=/root/tassl-1.1.1_lib。
6.国密算法的sm*.h 头文件目前暂时不能通过make install安装，需要通过./install_sm_header.sh(与./config同一目录)安装，就是在/root/tassl-1.1.1_lib/include/中创建sm目录，然后把sm*.h拷贝一份。

## 域名dig解析脚本

### Usage

```
Flags:
-h  or --help        find help                      帮助信息
-f  or --f5          f5 user:password@host1/host2   f5格式(必传)    用户:密码@数据服务器ip:port/解析服务器ip
-z  or --zdns        zdns user:password@host1/host2 ZDNS格式(必传)  用户:密码@数据服务器ip:port/解析服务器ip
-m  or --model       normal|check; Default=check    检查模式(非必传) <1-常规 2-对比> 默认对比模式
```

### Example

```shell
python3 dig_check.py -f=user:pswd@10.0.0.1:8080/10.0.0.2 -z=user:pswd@20.0.0.3:8888/20.0.0.3 -m=check  # 自动对比不一致数据
python3 dig_check.py -f=user:pswd@10.0.0.1:8080/10.0.0.2 -z=user:pswd@20.0.0.3:8888/20.0.0.3 -m=normal # 只输出解析结果
```

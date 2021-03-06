import requests

import urllib3
import subprocess
import shlex
import math
import logging
import getopt
import sys
from collections import Counter

urllib3.disable_warnings()
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(filename="dig.log", level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)

# common_params
headers = {"Content-type": "application/json"}
f5_zones = ["a", "aaaa", "cname"]
page_size_max = 500
# 当dig结果不一致时的重试次数
dig_retry_times = 5


def get_res_from_f5(**kwargs):
    """
    f5数据请求
    :param args:
    :param kwargs:
    :return:
    """
    f5_auth = kwargs.get("f5_auth")
    f5_data_host = kwargs.get("f5_data_host")
    f5_base_url = f"https://{f5_data_host}/mgmt/tm/gtm/wideip"

    f5_name_arr = []
    f5_name_dict = {}
    for zone in f5_zones:
        url = f"{f5_base_url}/{zone}"
        res = get_resp(url=url, auth=f5_auth)
        items = res.get("items")
        if items is None:
            continue
        else:
            for item in items:
                f5_name_arr.append(str.lower(item.get("name") + "."))
        f5_name_dict[zone] = f5_name_arr
    return f5_name_arr, f5_name_dict


def get_res_from_zdns(**kwargs):
    """
    zdns数据请求
    :param kwargs:
    :return:
    """

    zdns_data_host = kwargs.get("zdns_data_host")
    zdns_auth = kwargs.get("zdns_auth")
    zdns_zone_url = f"https://{zdns_data_host}:20120/views/ADD/dzone"

    params = {
        "page_num": 1,
        "page_size": page_size_max,
        "with_add": "yes"
    }
    zdns_gmap_arr = []
    res = get_resp(url=zdns_zone_url, params=params, auth=zdns_auth)
    resources = res.get("resources")
    total_size = int(res.get("total_size"))
    _zdns_gmap_parse(zdns_gmap_arr, resources)

    if total_size > page_size_max:
        cnt = math.ceil(int(total_size) / page_size_max) - 1
        for i in range(cnt):
            params["page_num"] += 1
            res = get_resp(url=zdns_zone_url, params=params, auth=zdns_auth)
            resources = res.get("resources")
            _zdns_gmap_parse(zdns_gmap_arr, resources)

    return zdns_gmap_arr


def _zdns_gmap_parse(zdns_gmap_arr, resources):
    """
    解析resource到zdns_gmap_arr
    :param zdns_gmap_arr:
    :param resources:
    :return:
    """
    if len(resources) == 0 or resources is None:
        return
    for resource in resources:
        gmaps = resource.get("gmaps")
        if len(gmaps) > 0:
            zdns_gmap_arr.extend(resource.get("gmaps"))
        else:
            continue


def _check_diff(base, obj):
    """
    取差集
    :param base: 基准
    :param obj:  对象
    :return: 
    """
    res = list(set(base).difference(set(obj)))
    return res


def get_resp(**kwargs):
    """
    通用请求方法
    :param kwargs:
    :return:
    """
    url = kwargs.get("url")
    params = kwargs.get("params")
    auth = kwargs.get("auth")
    res = requests.get(url=url, auth=auth, params=params, headers=headers, verify=False)
    if res.status_code != 200:
        raise Exception("request error!")
    res = res.json()
    return res


def get_dig_resp(server_name, domain_name, type):
    """
    dig 解析
    :param server_name: 服务器名字
    :param domain_name: 域名
    :return:
    """
    cmd = f"dig @{server_name} {domain_name} {type} +noall +answer"

    proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    out, err = proc.communicate()  # bytes
    if err is not None:
        logging.error("dig command error!")
    normal_str = out.decode('UTF-8')
    idx = normal_str.find("+cmd")
    parse_str = normal_str[idx + 5:-1].replace('\t', '', 1)
    parse_list = parse_str.split('\n')
    res = []
    for c_str in parse_list:
        c_list = c_str.split("\t")
        res.extend(c_list)
    return res


def check_dig_res(dns_dict, flag="check", **kwargs):
    """
    检测dig解析数据是否一致
    :param arr: domain arr
    :param flag: 全部解析是否写入文件
    :param kwargs: config
    :return:
    """
    zdns_parse_host = kwargs.get("zdns_parse_host")
    f5_parse_host = kwargs.get("f5_parse_host")
    res = False
    for domain_type, arr in dns_dict:
        for domain_name in arr:
            zdns_res = get_dig_resp(server_name=zdns_parse_host, domain_name=domain_name, type=domain_type)
            f5_res = get_dig_resp(server_name=f5_parse_host, domain_name=domain_name, type=domain_type)
            z_dict = Counter(zdns_res)  # dig返回多条数据采用Counter来统计
            f_dict = Counter(f5_res)

            if flag == "normal":
                logging.info(f"domain_name:{domain_name}\nzdns: {zdns_res}\nf5: {f5_res}")
            if flag == "check":
                retry_times = dig_retry_times
                while True:
                    if z_dict == f_dict or retry_times == 0:
                        res = True
                        logging.error(f"dig analysis result different: {domain_name}\n zdns: {zdns_res}\nf5: {f5_res}")
                        break
                    f5_res = get_dig_resp(server_name=f5_parse_host, domain_name=domain_name, type=domain_type)
                    f_dict = Counter(f5_res)
                    retry_times -= 1

    return res


def get_args_config(argv):
    """
    命令行获取参数
    :param argv:
    :return:
    """
    zdns_config = ""
    f5_config = ""
    model = "check"

    try:
        opts, args = getopt.getopt(argv, "hf:z:m:", ["help", "f5=", "zdns=", "model="])
    except getopt.GetoptError:
        print('Error: error args! use <--help> to find usage.')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h, --help"):
            print('Flags: ')
            print('-h  or --help        find help                      帮助信息')
            print('-f  or --f5          f5 user:password@host1/host2   f5格式(必传)    用户:密码@数据服务器ip:port/解析服务器ip')
            print('-z  or --zdns        zdns user:password@host1/host2 ZDNS格式(必传)  用户:密码@数据服务器ip:port/解析服务器ip')
            print('-m  or --model       normal|check; Default=check    检查模式(非必传) <1-常规 2-对比> 默认对比模式')
            sys.exit(0)
        elif opt in ("-f", "--f5"):
            f5_config = arg
        elif opt in ("-z", "--zdns"):
            zdns_config = arg
        elif opt in ("-m", "--model"):
            model = arg

    if f5_config == "":
        print("Error: missing f5 config, use <--help> to find usage.")
        sys.exit(2)

    if zdns_config == "":
        print("Error: missing zdns config, use <--help> to find usage.")
        sys.exit(2)

    f5_config_list = f5_config.split('@')
    f5_host_list = f5_config_list[-1].split('/')
    f5_data_host = f5_host_list[0]
    f5_parse_host = f5_host_list[-1]
    f5_user = f5_config_list[0].split(':')[0]
    f5_password = f5_config_list[0].split(':')[-1]

    zdns_config_list = zdns_config.split('@')
    zdns_host_list = zdns_config_list[-1].split('/')
    zdns_data_host = zdns_host_list[0]
    zdns_parse_host = zdns_host_list[-1]
    zdns_user = zdns_config_list[0].split(':')[0]
    zdns_password = zdns_config_list[0].split(':')[-1]

    config_dict = {
        "zdns_data_host": zdns_data_host,
        "zdns_parse_host": zdns_parse_host,
        "f5_data_host": f5_data_host,
        "f5_parse_host": f5_parse_host,
        "f5_auth": (f"{f5_user}", f"{f5_password}"),
        "zdns_auth": (f"{zdns_user}", f"{zdns_password}"),
        "model": model

    }
    return config_dict


if __name__ == "__main__":
    # =============命令行获取配置文件=============
    config_dict = get_args_config(sys.argv[1:])

    # =============获取zdns数据=============
    print("loading data from zdns...")
    zdns_arr = get_res_from_zdns(**config_dict)

    # =============获取f5数据=============
    print("loading data from f5...")
    f5_arr, f5_dict = get_res_from_f5(**config_dict)

    # =============检查数据是否一致=============
    print("checking...")
    res = _check_diff(zdns_arr, f5_arr)
    if len(res) > 0:
        print(f"error! missing data: (can not find wideIp from f5): {res}")
        sys.exit(1)

    # =============dig解析对比(对比结果是否一致)=============
    if config_dict.get("model") == "check":
        if check_dig_res(f5_dict, **config_dict):
            print("find different data! you can open dig.log file to check")
            sys.exit(1)
        print("check passed!")
        sys.exit(0)

    # =============dig解析输出(不作对比)=============
    if config_dict.get("model") == "normal":
        check_dig_res(f5_dict, flag="normal", **config_dict)
        print("finished! open dig.log file to check")
        sys.exit(0)
    else:
        print("unknown error!")
        sys.exit(1)

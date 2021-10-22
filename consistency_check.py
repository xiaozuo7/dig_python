import requests

import urllib3
import subprocess
import shlex
import math
import logging
import getopt
import sys

urllib3.disable_warnings()
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(filename="dig.log", level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)

# common_params
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"}
f5_zones = ["a", "aaaa", "cname", "mx", "naptr", "srv"]
page_size_max = 500


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
    for zone in f5_zones:
        url = f"{f5_base_url}/{zone}"
        res = get_resp(url=url, auth=f5_auth)
        items = res.get("items")
        if items is None:
            continue
        else:
            for item in items:
                f5_name_arr.append(item.get("name") + ".")
    return f5_name_arr


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


def get_dig_resp(server_name, domain_name):
    """
    dig 解析
    :param server_name: 服务器名字
    :param domain_name: 域名
    :return:
    """
    cmd = f"dig @{server_name} {domain_name} +noall +answer"

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


def check_dig_res(arr, flag="check", **kwargs):
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
    for domain_name in arr:
        zdns_res = get_dig_resp(server_name=zdns_parse_host, domain_name=domain_name)
        f5_res = get_dig_resp(server_name=f5_parse_host, domain_name=domain_name)
        if flag == "normal":
            logging.info(f"domain_name:{domain_name}\nzdns: {zdns_res}\nf5: {f5_res}")
        if flag == "check":
            if zdns_res != f5_res:
                res = True
                logging.error(f"dig analysis result different: {domain_name}\n zdns: {zdns_res}\nf5: {f5_res}")
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
        opts, args = getopt.getopt(argv, "hf:z:m:", ["help", "f5=", "zdns=", "modle="])
    except getopt.GetoptError:
        print('Error: error args! use <--help> to find usage.')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h, --help"):
            print('Flags: ')
            print('-h  or --help        find help                      帮助信息')
            print('-f  or --f5          f5 user:password@host1:host2   f5格式(必传)    用户:密码@数据服务器ip:解析服务器ip')
            print('-z  or --zdns        zdns user:password@host1:host2 ZDNS格式(必传)  用户:密码@数据服务器ip:解析服务器ip')
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
    f5_host_list = f5_config_list[-1].split(':')
    f5_data_host = f5_host_list[0]
    f5_parse_host = f5_host_list[-1]
    f5_user = f5_config_list[0].split(':')[0]
    f5_password = f5_config_list[0].split(':')[-1]

    zdns_config_list = zdns_config.split('@')
    zdns_host_list = zdns_config_list[-1].split(':')
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
    config_dict = get_args_config(sys.argv[1:])
    zdns_arr = get_res_from_zdns(**config_dict)
    f5_arr = get_res_from_f5(**config_dict)

    res = _check_diff(zdns_arr, f5_arr)
    if len(res) > 0:
        logging.error(f"missing data: (can not find wideIp from f5): {res}")
        sys.exit(1)

    if config_dict.get("model") == "check":
        if check_dig_res(zdns_arr, **config_dict):
            print("find different data! you can open dig.log file to check")
            sys.exit(1)
        print("check passed!")
        sys.exit(0)

    if config_dict.get("model") == "normal":
        check_dig_res(zdns_arr, flag="normal", **config_dict)
        print("finished! open dig.log file to check")
        sys.exit(0)
    else:
        print("unknown error!")
        sys.exit(1)

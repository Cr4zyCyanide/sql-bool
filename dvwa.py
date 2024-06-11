import requests
from bs4 import BeautifulSoup


def dvwa_get_cookie(login_url, username, passwd):
    login_html = requests.get(login_url).text
    soup = BeautifulSoup(login_html, 'html.parser')
    input_token = soup.find_all("input", {"type": "hidden", "name": "user_token"})
    login_data = {
        'username': username,
        'password': passwd,
        'Login': 'Login',
        'user_token': input_token[0]["value"]
    }
    print(input_token[0]["value"])
    response = requests.post(login_url, data=login_data)
    print(response.text, response.cookies)
    return response.cookies
import json
import secrets
from bs4 import BeautifulSoup
import pkce
import requests


class preHeaders:
    def H1():
        return {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Language": "en-US,en;q=0.9,el-GR;q=0.8,el;q=0.7",
                "Connection": "keep-alive",
                "Host": "oauth2.it.auth.gr",
                "Referer": "https://students.auth.gr/",
                "Upgrade-Insecure-Request": "1",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64; rv:41.0) Gecko/20100101 Firefox/41.0",
        }

    def H2():
        return {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "login.auth.gr",
                "Origin": "https://oauth2.it.auth.gr",
                "Referer": "https://oauth2.it.auth.gr/",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64; rv:41.0) Gecko/20100101 Firefox/41.0",
    }

    def H3(param1):
        return {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "login.auth.gr",
                "Origin": "https://login.auth.gr",
                "Referer": param1,
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64; rv:41.0) Gecko/20100101 Firefox/41.0",
    }
        
    def H4():
        return {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "oauth2.it.auth.gr",
                "Origin": "https://login.auth.gr",
                "Referer": "https://login.auth.gr/",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64; rv:41.0) Gecko/20100101 Firefox/41.0",
            }
        
        
    def H5(): 
        return {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "max-age=0",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://students.auth.gr",
                "Referer": "https://students.auth.gr/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64; rv:41.0) Gecko/20100101 Firefox/41.0",
            }


authorizeURL= "https://oauth2.it.auth.gr/auth/realms/universis/protocol/openid-connect/auth"
logoutURL= "https://oauth2.it.auth.gr/auth/realms/universis/protocol/openid-connect/logout?redirect_uri=https://students.auth.gr/#/auth/login"
userProfileURL= "https://universis-api.it.auth.gr/api/users/me"
oauth2= {
        "clientID": "students",
        "callbackURL": "https://students.auth.gr/auth/callback/index.html",
        "tokenURL": "https://oauth2.it.auth.gr/auth/realms/universis/protocol/openid-connect/token",
        "scope": [
          "students"
        ]
}



def generate_token(username: str, password: str) -> dict:
    state: str = secrets.token_hex(nbytes=8)
    code_verifier: str = pkce.generate_code_verifier(length=128)
    code_challenge: str = pkce.get_code_challenge(code_verifier)
    
    # cookiejar.CookieJar() #TODO
    session = requests.Session()
    
    # Step 1: Initial GET request
    initial_url = authorizeURL
    params = {
        "redirect_uri": oauth2["callbackURL"],
        "response_type": "code",
        "client_id": oauth2["clientID"],
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "scope": oauth2["scope"][0],
        "state": state
    }
    headers = preHeaders.H1()
    
    response = session.get(url=initial_url, params=params, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    form_url = soup.find("form")["action"]
    saml_request = soup.find("input", {"name": "SAMLRequest"})["value"]
    relay_state = soup.find("input", {"name": "RelayState"})["value"]

    # Step 2: POST SAMLRequest and RelayState
    form_data = {
        "SAMLRequest": saml_request,
        "RelayState": relay_state,
    }
    
    headers = preHeaders.H2()
    
    response = session.post(form_url, data=form_data, headers=headers)
    form_url = response.url.split("?")[0]
    soup = BeautifulSoup(response.text, "html.parser")
    auth_state = soup.find("input", {"name": "AuthState"})["value"]
    
    # Step 3: POST username, password, and AuthState
    form_data = {
        "username": username,
        "password": password,
        "AuthState": auth_state,
    }
    
    headers = preHeaders.H3(response.url)
    

    response = session.post(form_url, data=form_data, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")

    if "το όνομα χρήστη ή ο κωδικός πρόσβασης ήταν λάθος" in soup.text:
        raise Exception("Wrong password")
    
    form_url = soup.find("form")["action"]
    saml_response = soup.find("input", {"name": "SAMLResponse"})["value"]
    relay_state = soup.find("input", {"name": "RelayState"})["value"]

    # Step 4: POST SAMLResponse and RelayState
    form_data = {
        "SAMLResponse": saml_response,
        "RelayState": relay_state,
    }
    
    
    headers = preHeaders.H4()
    response = session.post(form_url, data=form_data, headers=headers, allow_redirects=False)
    redirect_url = response.headers["location"]

    if "code=" not in redirect_url:
        raise Exception("URL does not contain access_token or token_type")

    code = redirect_url.split("code=")[1]
    
    # Step 5: Exchange code for access_token
    form_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": "students",
        "redirect_uri": "https://students.auth.gr/auth/callback/index.html",
        "code_verifier": code_verifier,
    }
    
    headers = preHeaders.H5()
    
    response = session.post("https://oauth2.it.auth.gr/auth/realms/universis/protocol/openid-connect/token", data=form_data, headers=headers)
    response_data = json.loads(response.text)
    token = response_data.get("access_token")

    ret = token
    return ret

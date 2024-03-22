import re
import os
import json
import sys
import time

import requests

from loguru import logger
from fastapi import FastAPI, Request, HTTPException, Depends
from apscheduler.schedulers.background import BackgroundScheduler

logger.add("logs_{time}.log", rotation="1 day", retention="7 days", level="DEBUG")

app = FastAPI()

UNLOCK_RESULT_CACHE = None
CONN_INFO = os.environ.get("CONN_INFO", "")
REGION = os.environ.get("REGION", "")

if CONN_INFO and REGION:
    logger.info(f"Get Connection Info Success, Region: {REGION}")
else:
    logger.warning("Failed to get Connection Info.")
    sys.exit(-1)

scheduler = BackgroundScheduler()

USER_AGENT = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
}

SYSTEM_PROXY = {
    "http": "socks5h://127.0.0.1:7890",
    "https": "socks5h://127.0.0.1:7890"
}


def token_authenticator(request: Request):
    token = request.headers.get("Authorization")
    if token != "Bearer H5YN89C1LgPT8yibNNEkJMpNCLeVgszJfpD":
        raise HTTPException(status_code=401, detail="Invalid token")
    return True


def unlock_status_checker() -> dict:
    session = requests.Session()
    session.headers.update(USER_AGENT)
    session.proxies = SYSTEM_PROXY

    try:
        media_cookie_response = requests.get(
            "https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/cookies", timeout=10)
        media_cookie_response.raise_for_status()
        media_cookie = media_cookie_response.text
    except requests.RequestException as e:
        logger.error(f"Failed to fetch Media_Cookie: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch Media_Cookie")

    def __openai_status__() -> bool:
        website_url = "https://api.openai.com/compliance/cookie_requirements"
        ios_url = "https://ios.chat.openai.com"

        website_headers = {'authority': 'api.openai.com', 'accept': '*/*', 'accept-language': 'zh-CN,zh;q=0.9',
                           'authorization': 'Bearer null', 'content-type': 'application/json',
                           'origin': 'https://platform.openai.com', 'referer': 'https://platform.openai.com/',
                           'sec-ch-ua': '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
                           'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty',
                           'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-site',
                           'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}
        ios_headers = {'authority': 'ios.chat.openai.com',
                       'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                       'accept-language': 'zh-CN,zh;q=0.9',
                       'sec-ch-ua': '"Microsoft Edge";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
                       'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'document',
                       'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'none', 'sec-fetch-user': '?1',
                       'upgrade-insecure-requests': '1',
                       'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0'}

        website_response = session.get(website_url, headers=website_headers)
        ios_response = session.get(ios_url, headers=ios_headers)

        _unlock_status_ = False if "unsupported_country" in website_response.text or "VPN" in ios_response.text else True
        logger.debug(
            f"Website Response: {website_response.text}, IOS Response: {ios_response.text}, Unlock Status: {_unlock_status_}".replace(
                '\n', '\\n'))

        return _unlock_status_

    def __claude_status__() -> bool:
        claude_url = "https://claude.ai"
        claude_response = session.get(claude_url)
        return False if "App unavailable" in claude_response.text else True

    def __netflix_status__() -> bool:
        netflix_url_list = ["https://www.netflix.com/title/81280792", "https://www.netflix.com/title/70143836"]
        netflix_response_list = [session.get(url) for url in netflix_url_list]
        regexp_results = [re.search(r'"isPlayable":(true|false)', response.text) for response in netflix_response_list]

        if all([netflix_response.status_code == 200 for netflix_response in netflix_response_list]):
            if all([result for result in regexp_results]):
                logger.debug(regexp_results)
                if all([result.group(1) == "true" for result in regexp_results]):
                    return True
        logger.debug(f"{regexp_results}, Unlock Status: False")
        return False

    def __disney_plus__():
        pre_assertion_response = ""
        headers = {
            "authorization": "Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84",
            "content-type": "application/json; charset=UTF-8"
        }
        headers.update(USER_AGENT)

        pre_disney_cookie = media_cookie.split('\n')[0]

        device_payload = {"deviceFamily": "browser", "applicationRuntime": "chrome", "deviceProfile": "windows",
                          "attributes": {}}
        try:
            pre_assertion_response = session.post("https://disney.api.edge.bamgrid.com/devices", headers=headers,
                                                  data=device_payload, timeout=10)
            pre_assertion_response.raise_for_status()

        except requests.RequestException:
            print("Disney+:\t\t\t\tFailed (Network Connection)")
            return False

        assertion = pre_assertion_response.json().get('assertion', None)
        if not assertion:
            print("Failed to obtain assertion.")
            return False

        disney_cookie = pre_disney_cookie.replace("DISNEYASSERTION", assertion)

        try:
            token_response = session.post("https://disney.api.edge.bamgrid.com/token", headers=headers,
                                          data=disney_cookie, timeout=10)
            token_response.raise_for_status()
        except requests.RequestException:
            print("Token request failed.")
            return

        token_content = token_response.json()
        if "forbidden-location" in token_content or "403 ERROR" in token_content.get('error', ''):
            print("Disney+:\t\t\t\tNo")
            return

        fake_content = media_cookie.split('\n')[7]
        refresh_token = token_content.get('refresh_token', None)
        if not refresh_token:
            print("Failed to obtain refresh token.")
            return

        disney_content = fake_content.replace("ILOVEDISNEY", refresh_token)

        try:
            tmp_result = session.post("https://disney.api.edge.bamgrid.com/graph/v1/device/graphql", headers=headers,
                                      data=disney_content, timeout=10)
            tmp_result.raise_for_status()
        except requests.RequestException:
            print("GraphQL request failed.")
            return

        result_json = tmp_result.json()
        region = result_json.get('countryCode', None)
        in_supported_location = result_json.get('inSupportedLocation', None)

        if region == "JP":
            print("Disney+:\t\t\t\tYes (Region: JP)")
        elif region and in_supported_location == "false":
            print(f"Disney+:\t\t\t\tAvailable For [Disney+ {region}] Soon")
        elif region and in_supported_location == "true":
            print(f"Disney+:\t\t\t\tYes (Region: {region})")
        else:
            print("Disney+:\t\t\t\tNo")

    unlock_result = {
        "openai": __openai_status__(),
        "claude": __claude_status__(),
        "netflix": __netflix_status__(),
        # "disney": __disney_plus__()
    }

    logger.info(json.dumps(unlock_result))
    return unlock_result


def update_unlock_status_cache() -> None:
    global UNLOCK_RESULT_CACHE
    UNLOCK_RESULT_CACHE = {
        "timestamp": int(time.time()),
        "region": REGION,
        "connection_info": CONN_INFO,
        "unlock_status": unlock_status_checker()
    }


@app.on_event("startup")
def start_scheduler():
    scheduler.add_job(update_unlock_status_cache, 'interval', minutes=10)
    scheduler.start()
    update_unlock_status_cache()


@app.on_event("shutdown")
def shutdown_scheduler():
    scheduler.shutdown()


@app.post("/unlock_status_check")
async def unlock_status_check_api(_=Depends(token_authenticator)):
    global UNLOCK_RESULT_CACHE
    return UNLOCK_RESULT_CACHE


# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=6900)

import json
import datetime
import requests

from loguru import logger
from fastapi import FastAPI, Request, HTTPException, Depends
from apscheduler.schedulers.background import BackgroundScheduler

date = datetime.datetime.now().strftime("%Y-%m-%d")
logger.add(f"/var/logs/airport_unlock_status/{date}.log", rotation="1 day", retention="7 days", level="DEBUG")

app = FastAPI()

UNLOCK_RESULT_CACHE = None

scheduler = BackgroundScheduler()

USER_AGENT = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36"
}

SYSTEM_PROXY = {
    "http": "http://127.0.0.1:7890",
    "https": "https://127.0.0.1:7890"
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
    session.verify = False

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

        try:
            website_response = session.get(website_url, headers=website_headers)
            ios_response = session.get(ios_url, headers=ios_headers)

            _unlock_status_ = False if "unsupported_country" in website_response.text or "VPN" in ios_response.text else True
            logger.debug(
                f"Website Response: {website_response.text}, IOS Response: {ios_response.text}, Unlock Status: {_unlock_status_}".replace(
                    '\n', '\\n'))

            return _unlock_status_
        except Exception as e:
            logger.error(f"OpenAI Status Check Error: {e}")
            return False

    def __claude_status__() -> bool:
        claude_url = "https://claude.ai"
        try:
            claude_response = session.get(claude_url)
            return False if "App unavailable" in claude_response.text else True
        except Exception as e:
            logger.error(f"Claude Status Check Error: {e}")
            return False

    unlock_result = {
        "openai": __openai_status__(),
        "claude": __claude_status__(),
    }

    logger.info(json.dumps(unlock_result))
    return unlock_result


def update_unlock_status_cache() -> None:
    global UNLOCK_RESULT_CACHE
    UNLOCK_RESULT_CACHE = {
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

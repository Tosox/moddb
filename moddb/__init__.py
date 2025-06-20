from curl_adapter import CurlCffiAdapter
import requests

from .base import front_page, login, logout, parse_page, parse_results, rss, search, search_tags
from .client import Client, TwoFactorAuthClient, Thread
from .enums import *
from .pages import *
from .utils import BASE_URL, LOGGER, Object, get_page, request, soup

SESSION = requests.Session()
SESSION.mount("http://", CurlCffiAdapter())
SESSION.mount("https://", CurlCffiAdapter())

__version__ = "0.14.0"

__all__ = [
    "front_page",
    "login",
    "logout",
    "parse_page",
    "parse_results",
    "rss",
    "search",
    "search_tags",
    "Client",
    "TwoFactorAuthClient",
    "Thread",
    "BASE_URL",
    "LOGGER",
    "Object",
    "get_page",
    "request",
    "soup",
]

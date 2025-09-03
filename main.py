import base64
import json
import sys
from binascii import Error as BinasciiError
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

TARGET_URL_TO_PROXY = "https://api.deepinfra.com/v1/openai/chat/completions"
CROXY_BASE_URL = "https://www.croxyproxy.com"
FORM_URLENCODED = "application/x-www-form-urlencoded"
JSON_CONTENT_TYPE = "application/json"

SELECTOR_CSRF_TOKEN_MAIN_PAGE = "form#request input[name=\"csrf\"]"
SELECTOR_SCRIPT_SERVER_SELECTOR = "script#serverSelectorScript"
SELECTOR_SCRIPT_INIT_SCRIPT = "script#initScript"


def step(msg: str) -> None:
    print(f"[STEP] {msg}")


def info(msg: str) -> None:
    print(f"[INFO] {msg}")


@dataclass
class ServerInfo:
    id: str
    name: str


@dataclass
class FinalUrlInfo:
    proxied_api_url: str
    cpi_url: str
    origin: str


class DeepInfraProxyClient:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.verify = True
        self._final_info: Optional[FinalUrlInfo] = None

    def reset(self) -> None:
        self._final_info = None

    @staticmethod
    def _extract_attr(html: str, selector: str, attr: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        el = soup.select_one(selector)
        if not el:
            raise RuntimeError(f"selector not found: {selector}")
        val = el.get(attr)
        if val is None:
            raise RuntimeError(f"attr '{attr}' not found on selector {selector}")
        return val

    def negotiate_proxy_url(self) -> FinalUrlInfo:
        if self._final_info is not None:
            return self._final_info

        step("1/7 Fetch main page")
        r = self.session.get(CROXY_BASE_URL, timeout=20)
        r.raise_for_status()
        csrf1 = self._extract_attr(r.text, SELECTOR_CSRF_TOKEN_MAIN_PAGE, "value")

        step("2/7 Fetch server list")
        r2 = self.session.post(f"{CROXY_BASE_URL}/servers",
                               headers={"Content-Type": FORM_URLENCODED, "Referer": f"{CROXY_BASE_URL}/", },
                               data={"url": TARGET_URL_TO_PROXY, "csrf": csrf1}, timeout=20, )
        r2.raise_for_status()
        html = r2.text
        csrf2_json = self._extract_attr(html, SELECTOR_SCRIPT_SERVER_SELECTOR, "data-csrf")
        try:
            csrf2 = json.loads(csrf2_json)
        except json.JSONDecodeError:
            csrf2 = csrf2_json

        step("3/7 Pick proxy server")
        server = self._select_server(html)
        info(f"server: {server.name} ({server.id})")

        step("4/7 Start proxy session")
        r3 = self.session.post(f"{CROXY_BASE_URL}/requests?fso=",
                               headers={"Content-Type": FORM_URLENCODED, "Referer": f"{CROXY_BASE_URL}/servers", },
                               data={"url": TARGET_URL_TO_PROXY, "proxyServerId": server.id, "csrf": csrf2, "demo": "0",
                                     "frontOrigin": CROXY_BASE_URL, }, timeout=20, )
        r3.raise_for_status()
        final_url = r3.url
        cpi_html = r3.text

        step("5/7 Decode final API URL")
        data_r_b64 = self._extract_attr(cpi_html, SELECTOR_SCRIPT_INIT_SCRIPT, "data-r")
        proxied_api_url = base64.b64decode(data_r_b64).decode("utf-8")
        parsed = urlparse(final_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        final_info = FinalUrlInfo(proxied_api_url=proxied_api_url, cpi_url=final_url, origin=origin, )
        self._final_info = final_info
        step("6/7 Cache final URL")
        info(f"proxied: {final_info.proxied_api_url}")
        step("7/7 Negotiation complete")
        return final_info

    def _select_server(self, server_list_html: str) -> ServerInfo:
        def server_from_obj(obj: Any) -> Optional[ServerInfo]:
            if isinstance(obj, dict) and "id" in obj and "name" in obj:
                return ServerInfo(id=str(obj["id"]), name=str(obj["name"]))
            return None

        data_ss = self._extract_attr(server_list_html, SELECTOR_SCRIPT_SERVER_SELECTOR, "data-ss")
        try:
            values = json.loads(data_ss)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse server list JSON: {e}")

        candidates: List[ServerInfo] = []

        for v in values:
            if isinstance(v, dict) and "id" in v and "name" in v:
                server_candidate = server_from_obj(v)
                if server_candidate:
                    candidates.append(server_candidate)
                    continue

            if isinstance(v, str):
                decoded: Optional[bytes] = None
                for decoder in (base64.b64decode, lambda t: base64.urlsafe_b64decode(t + "==")):
                    try:
                        decoded = decoder(v)
                        break
                    except (BinasciiError, ValueError, TypeError):
                        continue

                if decoded is not None:
                    try:
                        as_str = decoded.decode("utf-8")
                        try:
                            json_bytes = bytes.fromhex(as_str)
                            server_obj = json.loads(json_bytes)
                            server_candidate = server_from_obj(server_obj)
                            if server_candidate:
                                candidates.append(server_candidate)
                                continue
                        except (ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
                            pass
                        try:
                            server_obj = json.loads(as_str)
                            server_candidate = server_from_obj(server_obj)
                            if server_candidate:
                                candidates.append(server_candidate)
                                continue
                        except json.JSONDecodeError:
                            pass
                    except UnicodeDecodeError:
                        pass
                    try:
                        server_obj = json.loads(decoded)
                        server_candidate = server_from_obj(server_obj)
                        if server_candidate:
                            candidates.append(server_candidate)
                            continue
                    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
                        pass
                try:
                    server_obj = json.loads(v)
                    server_candidate = server_from_obj(server_obj)
                    if server_candidate:
                        candidates.append(server_candidate)
                        continue
                except json.JSONDecodeError:
                    pass

        if not candidates:
            raise RuntimeError("No working proxy server could be found")

        return candidates[0]

    def chat_stream(self, model: str, prompt: str) -> None:
        ctx = self.negotiate_proxy_url()

        payload: Dict[str, Any] = {"model": model, "stream": True,
                                   "messages": [{"role": "user", "content": prompt}, ], }

        headers = {"Accept": "text/event-stream", "Content-Type": JSON_CONTENT_TYPE, "Referer": ctx.cpi_url,
                   "Origin": ctx.origin, }

        step("POST stream -> proxied API")
        r = self.session.post(ctx.proxied_api_url, headers=headers, json=payload, stream=True, timeout=30)

        if 400 <= r.status_code < 500:
            sys.stdout.write(r.text)
            sys.stdout.flush()
            return

        if not r.ok:
            info("retrying once with fresh negotiation")
            self.reset()
            ctx = self.negotiate_proxy_url()
            headers["Referer"] = ctx.cpi_url
            headers["Origin"] = ctx.origin
            r = self.session.post(ctx.proxied_api_url, headers=headers, json=payload, stream=True, timeout=30)

        r.raise_for_status()

        info("streaming…")
        for line in r.iter_lines(decode_unicode=True):
            if line is None:
                continue
            try:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                break


def main() -> int:
    # Usage
    # python main.py               -> prompt='hi', model default
    # python main.py "your prompt" -> prompt=argv[1]
    # python main.py "p" "model"  -> prompt=argv[1], model=argv[2]
    model = "openai/gpt-oss-120b"
    prompt = "hi"
    if len(sys.argv) >= 2:
        prompt = sys.argv[1]
    if len(sys.argv) >= 3:
        model = sys.argv[2]
    try:
        DeepInfraProxyClient().chat_stream(model=model, prompt=prompt)
    except (requests.RequestException, RuntimeError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

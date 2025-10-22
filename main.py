import base64
import json
import sys
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


@dataclass
class Server:
    id: str
    name: str


@dataclass
class ProxySession:
    api_url: str
    page_url: str
    origin: str


class ProxyClient:
    BASE_URL = "https://www.croxyproxy.com"
    TARGET_API = "https://api.deepinfra.com/v1/openai/chat/completions"

    def __init__(self):
        self.session = requests.Session()
        self.cached_proxy: Optional[ProxySession] = None

    def _log(self, message: str):
        print(f"[{message}]", file=sys.stderr)

    def _get_element_attr(self, html: str, selector: str, attr: str) -> str:
        element = BeautifulSoup(html, "html.parser").select_one(selector)
        if not element or attr not in element.attrs:
            raise RuntimeError(f"Missing {attr} in {selector}")
        value = element[attr]
        if isinstance(value, list):
            return value[0] if value else ""
        return str(value)

    def _decode_server(self, encoded: str) -> Optional[Server]:
        try:
            hex_string = base64.b64decode(encoded).decode("utf-8")
            server_data = json.loads(bytes.fromhex(hex_string))
            return Server(id=str(server_data["id"]), name=server_data["name"])
        except Exception:
            return None

    def _get_first_server(self, html: str) -> Server:
        data = self._get_element_attr(html, "script#serverSelectorScript", "data-ss")
        encoded_servers = json.loads(data)

        for encoded in encoded_servers:
            if server := self._decode_server(encoded):
                return server

        raise RuntimeError("No available proxy servers")

    def _setup_proxy(self) -> ProxySession:
        if self.cached_proxy:
            return self.cached_proxy

        self._log("Initializing proxy")
        main_page = self.session.get(self.BASE_URL, timeout=20)
        main_page.raise_for_status()

        csrf_token = self._get_element_attr(
            main_page.text, "form#request input[name='csrf']", "value"
        )

        self._log("Fetching servers")
        server_page = self.session.post(
            f"{self.BASE_URL}/servers",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"url": self.TARGET_API, "csrf": csrf_token},
            timeout=20,
        )
        server_page.raise_for_status()

        csrf_data = self._get_element_attr(
            server_page.text, "script#serverSelectorScript", "data-csrf"
        )
        csrf_token = json.loads(csrf_data) if csrf_data.startswith('"') else csrf_data

        server = self._get_first_server(server_page.text)
        self._log(f"Using server: {server.name}")

        self._log("Starting session")
        session_page = self.session.post(
            f"{self.BASE_URL}/requests?fso=",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "url": self.TARGET_API,
                "proxyServerId": server.id,
                "csrf": csrf_token,
                "demo": "0",
                "frontOrigin": self.BASE_URL,
            },
            timeout=20,
        )
        session_page.raise_for_status()

        encoded_url = self._get_element_attr(
            session_page.text, "script#initScript", "data-r"
        )
        api_url = base64.b64decode(encoded_url).decode("utf-8")

        parsed = urlparse(session_page.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        self.cached_proxy = ProxySession(
            api_url=api_url, page_url=session_page.url, origin=origin
        )

        self._log("Proxy ready")
        return self.cached_proxy

    def _send_request(self, proxy: ProxySession, payload: Dict) -> requests.Response:
        return self.session.post(
            proxy.api_url,
            headers={
                "Accept": "text/event-stream",
                "Content-Type": "application/json",
                "Referer": proxy.page_url,
                "Origin": proxy.origin,
            },
            json=payload,
            stream=True,
            timeout=30,
        )

    def chat(self, prompt: str, model: str = "openai/gpt-oss-120b"):
        proxy = self._setup_proxy()

        payload = {
            "model": model,
            "stream": True,
            "messages": [{"role": "user", "content": prompt}],
        }

        response = self._send_request(proxy, payload)

        if 400 <= response.status_code < 500:
            sys.stdout.write(response.text)
            return

        if not response.ok:
            self._log("Retrying with fresh proxy")
            self.cached_proxy = None
            proxy = self._setup_proxy()
            response = self._send_request(proxy, payload)

        response.raise_for_status()

        self._log("Streaming response")
        for line in response.iter_lines(decode_unicode=True):
            if line:
                try:
                    print(line)
                    sys.stdout.flush()
                except (BrokenPipeError, OSError):
                    break


def main():
    model = "openai/gpt-oss-120b"
    prompt = "hi"

    if len(sys.argv) >= 2:
        prompt = sys.argv[1]
    if len(sys.argv) >= 3:
        model = sys.argv[2]

    try:
        ProxyClient().chat(prompt, model)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

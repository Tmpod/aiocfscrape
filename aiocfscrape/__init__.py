#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

"""
__all__ = ("CloudflareError", "CloudflareCaptchaError", "CloudflareScraper")

# Imports
import aiohttp
import asyncio
from base64 import b64encode
from collections import OrderedDict
import copy

# import js2py
import logging
from py_mini_racer import py_mini_racer
import random
import re
import ssl
import subprocess
import time
from urllib.parse import urlparse, urlunparse

#: Pool of random user-agents.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.79 Safari/537.36",
]

#: Gets a user-agent from the pool.
DEFAULT_USER_AGENT = random.choice(USER_AGENTS)

#: Default headers with the picked user-agent.
DEFAULT_HEADERS = OrderedDict(
    (
        ("Host", None),
        ("Connection", "keep-alive"),
        ("Upgrade-Insecure-Requests", "1"),
        ("User-Agent", DEFAULT_USER_AGENT),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
        ("Accept-Encoding", "gzip, deflate"),
    )
)

BUG_REPORT = """\
Cloudflare may have changed their technique, or there may be a bug in the script.

Please read https://github.com/pavlodvornikov/aiocfscrape#updates, then file a \
bug report at https://github.com/pavlodvornikov/aiocfscrape/issues."\
"""

ANSWER_ACCEPT_ERROR = """\
The challenge answer was not properly accepted by Cloudflare. This can occur if \
the target website is under heavy load, or if Cloudflare is experiencing issues. You can
potentially resolve this by increasing the challenge answer delay (default: 8 seconds). \
For example: cfscrape.create_scraper(delay=15)

If increasing the delay does not help, please open a GitHub issue at \
https://github.com/Anorov/cloudflare-scrape/issues\
"""

# Remove a few problematic TLSv1.0 ciphers from the defaults
DEFAULT_CIPHERS = (
    "ECDHE+AESGCM:"
    "ECDHE+CHACHA20:"
    "DHE+AESGCM:"
    "DHE+CHACHA20:"
    "ECDH+AESGCM:"
    "DH+AESGCM:"
    "ECDH+AES:"
    "DH+AES:"
    "RSA+AESGCM:"
    "RSA+AES:"
    "!aNULL:"
    "!eNULL:"
    "!MD5:!DSS:"
    "!ECDHE+SHA:"
    "!AES128-SHA:"
    "!AESCCM:"
    "!DHE:"
    "!ARIA"
)


class CloudflareError(aiohttp.ClientResponseError):
    """Generic error related to CloudFlare."""

    pass


class CloudflareCaptchaError(CloudflareError):
    """Error raised when CloudFlare presents a CAPTCHA problem, which is currently unsupported."""

    pass


class CloudflareScraper(aiohttp.ClientSession):
    """
    Drop in replacement class for :class:`aiohttp.ClientSession`.
    """

    def __init__(self, *args, **kwargs):
        self.delay = kwargs.pop("delay", None)
        self.org_method = None

        # Use headers with a random User-Agent if no custom headers have been set
        headers = OrderedDict(kwargs.pop("headers", DEFAULT_HEADERS))

        # Set the User-Agent header if it was not provided
        headers.setdefault("User-Agent", DEFAULT_USER_AGENT)

        super().__init__(*args, **kwargs)

        # Define headers to force using an OrderedDict and preserve header order
        # self.headers = headers

        # Initialize the JS engine.
        #: Python implementation of the V8 JS engine.
        self.js_engine = py_mini_racer.MiniRacer()

        # SSL context with custom ciphers to be used in all requests.
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.set_ciphers(DEFAULT_CIPHERS)

    async def _request(self, method, url, *args, allow_403=False, **kwargs):
        resp = await super()._request(
            method, url, *args, ssl=self._ssl_context, **kwargs
        )

        # Check if Cloudflare captcha challenge is presented
        if await self.is_cloudflare_captcha_challenge(resp, allow_403):
            self.handle_captcha_challenge(resp, url)

        # Check if Cloudflare anti-bot "I'm Under Attack Mode" is enabled
        if await self.is_cloudflare_iuam_challenge(resp):
            return await self.solve_cf_challenge(resp, **kwargs)
        return resp

    async def is_cloudflare_iuam_challenge(self, resp):
        html = await resp.read()
        return (
            resp.status in (503, 429)
            and resp.headers.get("Server", "").startswith("cloudflare")
            and b"jschl_vc" in html
            and b"jschl_answer" in html
        )

    async def is_cloudflare_captcha_challenge(self, resp, allow_403):
        return (
            resp.status == 403
            and not allow_403
            and resp.headers.get("Server", "").startswith("cloudflare")
            and b"/cdn-cgi/l/chk_captcha" in await resp.read()
        )

    def cloudflare_is_bypassed(self, url, resp=None):
        cookie_domain = ".{}".format(urlparse(url).netloc)
        return self.cookies.get("cf_clearance", None, domain=cookie_domain) or (
            resp and resp.cookies.get("cf_clearance", None, domain=cookie_domain)
        )

    def handle_captcha_challenge(self, resp, url):
        error = (
            "Cloudflare captcha challenge presented for %s (aiocfscrape cannot solve captchas)"
            % urlparse(url).netloc
        )
        if ssl.OPENSSL_VERSION_NUMBER < 0x10101000:
            error += ". Your OpenSSL version is lower than 1.1.1. Please upgrade your OpenSSL library and recompile Python."

        raise CloudflareCaptchaError(
            resp.request_info,
            history=(),
            status=resp.status,
            message=error,
            headers=resp.headers,
        )

    async def solve_cf_challenge(self, resp, **original_kwargs):
        start_time = time.time()

        body = await resp.text()
        parsed_url = urlparse(str(resp.url))
        domain = parsed_url.netloc
        challenge_form = re.search(
            r"\<form.*?id=\"challenge-form\".*?\/form\>", body, flags=re.S
        ).group(
            0
        )  # find challenge form
        method = re.search(r"method=\"(.*?)\"", challenge_form, flags=re.S).group(1)
        if self.org_method is None:
            self.org_method = resp.method
        submit_url = "%s://%s%s" % (
            parsed_url.scheme,
            domain,
            re.search(r"action=\"(.*?)\"", challenge_form, flags=re.S)
            .group(1)
            .split("?")[0],
        )

        cloudflare_kwargs = copy.deepcopy(original_kwargs)

        headers = cloudflare_kwargs.setdefault("headers", {})
        headers["Referer"] = resp.url

        try:
            cloudflare_kwargs["params"] = dict()
            cloudflare_kwargs["data"] = dict()
            if (
                len(
                    re.search(r"action=\"(.*?)\"", challenge_form, flags=re.S)
                    .group(1)
                    .split("?")
                )
                != 1
            ):
                for param in (
                    re.search(r"action=\"(.*?)\"", challenge_form, flags=re.S)
                    .group(1)
                    .split("?")[1]
                    .split("&")
                ):
                    cloudflare_kwargs["params"].update(
                        {param.split("=")[0]: param.split("=")[1]}
                    )

            for input_ in re.findall(
                r"\<input.*?(?:\/>|\<\/input\>)", challenge_form, flags=re.S
            ):
                if (
                    re.search(r"name=\"(.*?)\"", input_, flags=re.S).group(1)
                    != "jschl_answer"
                ):
                    if method == "POST":
                        cloudflare_kwargs["data"].update(
                            {
                                re.search(r"name=\"(.*?)\"", input_, flags=re.S)
                                .group(1): re.search(
                                    r"value=\"(.*?)\"", input_, flags=re.S
                                )
                                .group(1)
                            }
                        )
                    elif method == "GET":
                        cloudflare_kwargs["params"].update(
                            {
                                re.search(r"name=\"(.*?)\"", input_, flags=re.S)
                                .group(1): re.search(
                                    r"value=\"(.*?)\"", input_, flags=re.S
                                )
                                .group(1)
                            }
                        )
            if method == "POST":
                for k in ("jschl_vc", "pass"):
                    if k not in cloudflare_kwargs["data"]:
                        raise ValueError("%s is missing from challenge form" % k)
            elif method == "GET":
                for k in ("jschl_vc", "pass"):
                    if k not in cloudflare_kwargs["params"]:
                        raise ValueError("%s is missing from challenge form" % k)

        except Exception as e:
            # Something is wrong with the page.
            # This may indicate Cloudflare has changed their anti-bot
            # technique. If you see this and are running the latest version,
            # please open a GitHub issue so I can update the code accordingly.
            raise ValueError(
                "Unable to parse Cloudflare anti-bot IUAM page: %s\n%s"
                % (e, BUG_REPORT)
            )

        # Solve the Javascript challenge
        answer, delay = await self.solve_challenge(body, domain)
        if method == "POST":
            cloudflare_kwargs["data"]["jschl_answer"] = answer
        elif method == "GET":
            cloudflare_kwargs["params"]["jschl_answer"] = answer

        # Requests transforms any request into a GET after a redirect,
        # so the redirect has to be handled manually here to allow for
        # performing other types of requests even as the first request.
        cloudflare_kwargs["allow_redirects"] = False

        # Cloudflare requires a delay before solving the challenge
        await asyncio.sleep(max(delay - (time.time() - start_time), 0))

        # Send the challenge response and handle the redirect manually
        redirect = await self._request(method, submit_url, **cloudflare_kwargs)
        if "Location" in redirect.headers:
            redirect_location = urlparse(redirect.headers["Location"])

            if not redirect_location.netloc:
                redirect_url = urlunparse(
                    (
                        parsed_url.scheme,
                        domain,
                        redirect_location.path,
                        redirect_location.params,
                        redirect_location.query,
                        redirect_location.fragment,
                    )
                )
                return await self._request(method, redirect_url, **original_kwargs)
            return await self._request(
                method, redirect.headers["Location"], **original_kwargs
            )
        elif "Set-Cookie" in redirect.headers:
            if "cf_clearance" in redirect.headers["Set-Cookie"]:
                resp = await self._request(
                    self.org_method, submit_url, cookies=redirect.cookies
                )
                return resp
            else:
                return await self._request(method, submit_url, **original_kwargs)
        else:
            resp = await self._request(self.org_method, submit_url, **cloudflare_kwargs)
            return resp

    async def solve_challenge(self, body, domain):
        try:
            all_scripts = re.findall(
                r"\<script type\=\"text\/javascript\"\>\n(.*?)\<\/script\>",
                body,
                flags=re.S,
            )
            javascript = next(
                filter(lambda w: "jschl-answer" in w, all_scripts)
            )  # find the script tag which would have obfuscated js
            challenge, ms = re.search(
                r"setTimeout\(function\(\){\s*(var "
                r"s,t,o,p,b,r,e,a,k,i,n,g,f.+?\r?\n[\s\S]+?a\.value\s*=.+?)\r?\n"
                r"(?:[^{<>]*},\s*(\d{4,}))?",
                javascript,
                flags=re.S,
            ).groups()

            # The challenge requires `document.getElementById` to get this content.
            # Future proofing would require escaping newlines and double quotes
            innerHTML = ""
            for i in javascript.split(";"):
                if (
                    i.strip().split("=")[0].strip() == "k"
                ):  # from what i found out from pld example K var in
                    k = (
                        i.strip().split("=")[1].strip(" '")
                    )  #  javafunction is for innerHTML this code to find it
                    innerHTML = re.search(
                        r"\<div.*?id\=\"" + k + r"\".*?\>(.*?)\<\/div\>", body
                    ).group(
                        1
                    )  # find innerHTML

            # Prefix the challenge with a fake document object.
            # Interpolate the domain, div contents, and JS challenge.
            # The `a.value` to be returned is tacked onto the end.
            challenge = """
                var document = {
                    createElement: function () {
                      return { firstChild: { href: "http://%s/" } }
                    },
                    getElementById: function () {
                      return {"innerHTML": "%s"};
                    }
                  };

                %s; a.value
            """ % (
                domain,
                innerHTML,
                challenge,
            )
            # Encode the challenge for security while preserving quotes and spacing.
            challenge = b64encode(challenge.encode("utf-8")).decode("ascii")
            # Use the provided delay, parsed delay, or default to 8 secs
            delay = self.delay or (float(ms) / float(1000) if ms else 8)
        except Exception:
            raise ValueError(
                "Unable to identify Cloudflare IUAM Javascript on website. %s"
                % BUG_REPORT
            )

        # Use vm.runInNewContext to safely evaluate code
        # The sandboxed code cannot use the Node.js standard library
        js = (
            """\
            var atob = Object.setPrototypeOf(function (str) {\
                try {\
                    return Buffer.from("" + str, "base64").toString("binary");\
                } catch (e) {}\
            }, null);\
            var challenge = atob("%s");\
            var context = Object.setPrototypeOf({ atob: atob }, null);\
            var options = {\
                filename: "iuam-challenge.js",\
                contextOrigin: "cloudflare:iuam-challenge.js",\
                contextCodeGeneration: { strings: true, wasm: false },\
                timeout: 5000\
            };\
            process.stdout.write(String(\
                require("vm").runInNewContext(challenge, context, options)\
            ));\
            """
            % challenge
        )
        stderr = ""

        # try:
        #     result = js2py.eval_js(js)
        # except Exception:
        #     logging.error("Error executing Cloudflare IUAM Javascript. %s" % BUG_REPORT)
        #     raise

        # try:
        #     result = self.js_engine.eval(js)
        # except Exception:
        #     logging.error("Error executing Cloudflare IUAM Javascript. %s" % BUG_REPORT)
        #     raise

        try:
            node = await asyncio.create_subprocess_shell(
                f"node -e '{js}'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # universal_newlines=True
            )
            result, stderr = await node.communicate()
            if node.returncode != 0:
                stderr = "Node.js Exception:\n%s" % (stderr or None)
                raise subprocess.CalledProcessError(node.returncode, "node -e ...", stderr)
        except OSError as e:
            if e.errno == 2:
                raise EnvironmentError(
                    "Missing Node.js runtime. Node is required and must be in the PATH (check with `node -v`). Your Node binary may be called `nodejs` rather than `node`, in which case you may need to run `apt-get install nodejs-legacy` on some Debian-based systems. (Please read the cfscrape"
                    " README's Dependencies section: https://github.com/Anorov/cloudflare-scrape#dependencies."
                )
            raise
        except Exception:
            logging.error("Error executing Cloudflare IUAM Javascript. %s" % BUG_REPORT)
            raise

        try:
            float(result)
        except Exception:
            raise ValueError(
                "Cloudflare IUAM challenge returned unexpected answer. %s" % BUG_REPORT
            )

        return result, delay

import base64
import bisect
import html
import ipaddress
import json
import os
import random
import socket
import sys
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

__version__ = "1.0.0"

ANDROID_PACKAGE = "com.dbgid.browser"
ANDROID_ACTIVITY = ".SplashActivity"
EXECUTE_SCRIPT_RESULT_ATTR = "data-seledroid-script-result"
EXECUTE_SCRIPT_STATUS_ATTR = "data-seledroid-script-status"
IP2ASN_DB_FILE = os.path.join(os.path.dirname(__file__), "ip2asn-v4-u32.tsv")


class By:
    ID = "id"
    XPATH = "xpath"
    LINK_TEXT = "link text"
    PARTIAL_LINK_TEXT = "partial link text"
    NAME = "name"
    TAG_NAME = "tag name"
    CLASS_NAME = "class name"
    CSS_SELECTOR = "css selector"


class WebDriverException(Exception):
    pass


class ApplicationClosed(WebDriverException):
    pass


class NoSuchElementException(WebDriverException):
    pass


class InvalidElementStateException(WebDriverException):
    pass


class UnexpectedTagNameException(WebDriverException):
    pass


class Keys:
    ENTER = 66
    TAB = 61


no_encode_again = False


def decode_data(data):
    try:
        return html.unescape(data.decode("unicode-escape").encode("latin1").decode("utf8"))
    except Exception:
        try:
            return data.decode("unicode-escape").encode("latin1").decode("utf8")
        except Exception:
            return data


def b64encode(value):
    value = value.encode() if type(value) is str else ("%s" % value).encode()
    return decode_data(base64.b64encode(value))


def b64decode(value):
    value = value.encode() if type(value) is str else ("%s" % value).encode()
    result = decode_data(base64.b64decode(value)).replace("\r", "\\r").replace("\n", "\\n")
    try:
        if result in ["null", "undefined"]:
            result = None
        if result in ["true", "false"]:
            result = result.capitalize()
        return eval(result)
    except Exception:
        return result


def _iter_request_cookies(cookies):
    if cookies is None:
        return []

    extracted = []
    try:
        for cookie in cookies:
            if hasattr(cookie, "name") and hasattr(cookie, "value"):
                extracted.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": getattr(cookie, "domain", ""),
                    "path": getattr(cookie, "path", "/"),
                })
        if extracted:
            return extracted
    except TypeError:
        pass

    if hasattr(cookies, "get_dict"):
        return [{"name": key, "value": value, "domain": "", "path": "/"} for key, value in cookies.get_dict().items()]

    if hasattr(cookies, "items"):
        return [{"name": key, "value": value, "domain": "", "path": "/"} for key, value in cookies.items()]

    if isinstance(cookies, (list, tuple)):
        result = []
        for item in cookies:
            if isinstance(item, dict) and "name" in item:
                result.append({
                    "name": item["name"],
                    "value": item.get("value", ""),
                    "domain": item.get("domain", ""),
                    "path": item.get("path", "/"),
                })
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                result.append({"name": item[0], "value": item[1], "domain": "", "path": "/"})
        if result:
            return result

    raise TypeError("cookies must be a mapping, RequestsCookieJar, or iterable of cookie pairs")


def _cookie_target_url(target_url, cookie_domain):
    if target_url:
        parsed = urlsplit(target_url)
        scheme = parsed.scheme or "https"
        if cookie_domain:
            return "%s://%s/" % (scheme, cookie_domain.lstrip("."))
        return target_url
    if cookie_domain:
        return "https://%s/" % cookie_domain.lstrip(".")
    return ""


def _parse_cookie_loader_option(option):
    if option is None:
        return False, None
    if isinstance(option, bool):
        return option, None
    if isinstance(option, dict):
        return bool(option.get("state", True)), option.get("cookies_dict", option.get("cookies"))
    if isinstance(option, (tuple, list)):
        if len(option) == 0:
            return False, None
        if len(option) == 1:
            return bool(option[0]), None
        return bool(option[0]), option[1]
    return bool(getattr(option, "state", True)), getattr(option, "cookies_dict", getattr(option, "cookies", None))


def load_cookies_from_requests(driver, cookies, url=""):
    applied = []
    for cookie in _iter_request_cookies(cookies):
        cookie_url = _cookie_target_url(url, cookie.get("domain", ""))
        driver.set_cookie(cookie["name"], cookie["value"], url=cookie_url)
        applied.append(cookie["name"])
    return applied


def clear_browser(driver, clear_cache=True):
    clear_method = getattr(driver, "clear_browser", None)
    if callable(clear_method):
        return clear_method(clear_cache=clear_cache)
    return False


@dataclass(frozen=True)
class AsnHit:
    ip: str
    asn: int
    country: str
    name: str


def load_ip2asn_u32_tsv(path=IP2ASN_DB_FILE):
    starts = []
    ends = []
    asns = []
    countries = []
    names = []

    with open(path, "r", encoding="utf-8", errors="replace") as file_obj:
        for line in file_obj:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            try:
                starts.append(int(parts[0]))
                ends.append(int(parts[1]))
                asns.append(int(parts[2]))
            except ValueError:
                continue
            countries.append(parts[3])
            names.append(parts[4])

    return starts, ends, asns, countries, names


def lookup_asn(ip, starts, ends, asns, countries, names):
    ip_int = int(ipaddress.IPv4Address(ip))
    index = bisect.bisect_right(starts, ip_int) - 1
    if index >= 0 and ip_int <= ends[index]:
        return AsnHit(ip=ip, asn=asns[index], country=countries[index], name=names[index])
    return None


def random_public_ip_from_db(starts, ends):
    while True:
        index = random.randrange(0, len(starts))
        ip_int = random.randint(starts[index], ends[index])
        ip = ipaddress.IPv4Address(ip_int)
        if ip.is_global:
            return str(ip)


def generate_ip(db_path=IP2ASN_DB_FILE):
    starts, ends, asns, countries, names = load_ip2asn_u32_tsv(db_path)
    while True:
        ip = random_public_ip_from_db(starts, ends)
        hit = lookup_asn(ip, starts, ends, asns, countries, names)
        if hit:
            return {"ip": hit.ip, "country": hit.country, "name": hit.name, "asn": hit.asn}


def normalize_spoof(spoof=None):
    if spoof is True or spoof is None:
        spoof = generate_ip()
    if isinstance(spoof, dict):
        return {
            "ip": str(spoof.get("ip", "") or ""),
            "country": str(spoof.get("country", "") or ""),
            "name": str(spoof.get("name", "") or ""),
            "asn": spoof.get("asn"),
        }
    return {"ip": str(spoof or ""), "country": "", "name": "", "asn": None}


def build_spoof_headers(spoof=None):
    spoof = normalize_spoof(spoof)
    ip = spoof["ip"]
    country = spoof["country"]
    headers = {
        "X-Forwarded-For": ip,
        "X-Real-Ip": ip,
        "HTTP_X_FORWARDED_FOR": ip,
        "X-CLIENT-IP": ip,
        "REMOTE_ADDR": ip,
        "True-Client-Ip": ip,
        "Client-Ip": ip,
        "Forwarded": 'for="%s"' % ip,
    }
    if country:
        headers["Cf-Ipcountry"] = country
    return headers


def use_spoof(driver, spoof=None, merge=True):
    spoof = normalize_spoof(spoof)
    headers = build_spoof_headers(spoof)
    if merge:
        try:
            current = driver.headers
            if isinstance(current, dict):
                headers = {**current, **headers}
        except Exception:
            pass
    driver.headers = headers
    try:
        driver._goto_spoof_info = spoof
    except Exception:
        pass
    return headers


def goto(driver, url, **kwargs):
    wait_until = kwargs.pop("wait_until", "javascript")
    fallback_wait_until = kwargs.pop("fallback_wait_until", None)
    fallback_after = kwargs.pop("fallback_after", None)
    spoof = kwargs.pop("use_spoof", None)
    clear_browser_state = kwargs.pop("clear_browser_state", True)
    locator = kwargs.pop("locator", kwargs.pop("wait_for", None))
    timeout = kwargs.pop("timeout", 30)
    poll_frequency = kwargs.pop("poll_frequency", 0.12)
    settle_time = kwargs.pop("settle_time", 0.8)
    log = kwargs.pop("log", True)
    if clear_browser_state:
        clear_browser(driver)
    if spoof:
        use_spoof(driver, None if spoof is True else spoof)
    driver.get(url, **kwargs)
    wait_method = getattr(driver, "_wait_for_page_state", None)
    if callable(wait_method):
        wait_method(
            wait_until=wait_until,
            fallback_wait_until=fallback_wait_until,
            fallback_after=fallback_after,
            locator=locator,
            timeout=timeout,
            poll_frequency=poll_frequency,
            settle_time=settle_time,
            log=log,
        )
    return driver


class DictMap(dict):

    def __init__(self, *args, **kwargs):
        global no_encode_again
        if "no_encode_again" in args:
            no_encode_again = True
            args = [arg for arg in args if "no_encode_again" != arg]
        args = [arg for arg in args if arg]
        super(DictMap, self).__init__(*args, **kwargs)

        if args:
            for arg in args:
                if isinstance(arg, dict):
                    for key, value in arg.items():
                        self[key] = DictMap(value) if isinstance(value, dict) else value

        if kwargs:
            for key, value in kwargs.items():
                self[key] = DictMap(value) if isinstance(value, dict) else value
        no_encode_again = False

    def __getattr__(self, attr):
        return b64decode(self.get(attr))

    def __getitem__(self, key):
        super(DictMap, self).__getitem__(key)
        return b64decode(self.__dict__.get(key))

    def __getattribute__(self, attr):
        if attr in self:
            return b64decode(self.__dict__[attr])
        return super(DictMap, self).__getattribute__(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        if not no_encode_again:
            value = b64encode(value)
        super(DictMap, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(DictMap, self).__delitem__(key)
        del self.__dict__[key]


class Command:
    CLOSE = "close"
    CLICK_JAVA = "click java"
    CLEAR_COOKIE = "clear cookie"
    CLEAR_COOKIES = "clear cookies"
    CURRENT_URL = "current url"
    CLEAR_LOCAL_STORAGE = "clear local storage"
    CLEAR_SESSION_STORAGE = "clear session storage"
    DELETE_ALL_COOKIE = "delete all cookie"
    EXECUTE_SCRIPT = "execute script"
    FIND_ELEMENT = "find element"
    FIND_ELEMENTS = "find elements"
    GET = "get"
    GET_ATTRIBUTE = "get attribute"
    GET_COOKIE = "get cookie"
    GET_COOKIES = "get cookies"
    GET_USER_AGENT = "get user agent"
    GET_HEADERS = "get headers"
    GET_LOCAL_STORAGE = "get local storage"
    GET_SESSION_STORAGE = "get session storage"
    GET_RECAPTCHA_V3_TOKEN = "get recaptcha v3 token"
    INIT = "init"
    OVERRIDE_JS_FUNCTION = "override js function"
    PAGE_SOURCE = "page source"
    REMOVE_ATTRIBUTE = "remove attribute"
    SEND_KEY = "send key"
    SEND_TEXT = "send text"
    SET_ATTRIBUTE = "set attribute"
    SWIPE = "swipe"
    SWIPE_DOWN = "swipe down"
    SWIPE_UP = "swipe up"
    SET_COOKIE = "set cookie"
    SET_USER_AGENT = "set user agent"
    SET_PROXY = "set proxy"
    SCROLL_TO = "scroll to"
    SET_HEADERS = "set headers"
    SET_LOCAL_STORAGE = "set local storage"
    SET_SESSION_STORAGE = "set session storage"
    TITLE = "title"
    WAIT_UNTIL_ELEMENT = "wait until element"
    WAIT_UNTIL_NOT_ELEMENT = "wait until not element"


class RemoteConnection(socket.socket):

    def __init__(self, accept_time_out):
        socket.setdefaulttimeout(accept_time_out)
        super(RemoteConnection, self).__init__(socket.AF_INET, socket.SOCK_STREAM)

        self.max_listen = 128
        self.max_recv = 4096
        self.host = "127.0.0.1"
        self.port = random.randint(1000, 9999)

        self.init_socket_server()

    def init_socket_server(self):
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while True:
            try:
                self.bind((self.host, self.port))
                break
            except OSError:
                self.port = random.randint(1000, 9999)
        self.listen(self.max_listen)


class WebElement:

    def __init__(self, execute, element):
        self.execute = execute
        self.element = element

    def __repr__(self):
        return "WebElement(%s)" % self.element.result

    def click(self):
        return self.get_attribute("click()")

    def click_java(self):
        position = "%f %f" % self.position
        return self.execute(Command.CLICK_JAVA, position=position).result

    def clear(self):
        return self.set_attribute("value", "")

    def focus(self):
        self.get_attribute("focus()")

    def find_element_by_id(self, id_):
        return self.find_element(by=By.ID, value=id_)

    def find_element_by_name(self, name):
        return self.find_element(by=By.NAME, value=name)

    def find_element_by_xpath(self, xpath):
        return self.find_element(by=By.XPATH, value=xpath)

    def find_element_by_link_text(self, link_text):
        return self.find_element(by=By.LINK_TEXT, value=link_text)

    def find_element_by_partial_link_text(self, partial_link_text):
        return self.find_element(by=By.PARTIAL_LINK_TEXT, value=partial_link_text)

    def find_element_by_tag_name(self, tag_name):
        return self.find_element(by=By.TAG_NAME, value=tag_name)

    def find_element_by_class_name(self, class_name):
        return self.find_element(by=By.CLASS_NAME, value=class_name)

    def find_element_by_css_selector(self, css_selector):
        return self.find_element(by=By.CSS_SELECTOR, value=css_selector)

    def find_elements_by_id(self, id_):
        return self.find_elements(by=By.ID, value=id_)

    def find_elements_by_name(self, name):
        return self.find_elements(by=By.NAME, value=name)

    def find_elements_by_xpath(self, xpath):
        return self.find_elements(by=By.XPATH, value=xpath)

    def find_elements_by_link_text(self, link_text):
        return self.find_elements(by=By.LINK_TEXT, value=link_text)

    def find_elements_by_partial_link_text(self, partial_link_text):
        return self.find_elements(by=By.PARTIAL_LINK_TEXT, value=partial_link_text)

    def find_elements_by_tag_name(self, tag_name):
        return self.find_elements(by=By.TAG_NAME, value=tag_name)

    def find_elements_by_class_name(self, class_name):
        return self.find_elements(by=By.CLASS_NAME, value=class_name)

    def find_elements_by_css_selector(self, css_selector):
        return self.find_elements(by=By.CSS_SELECTOR, value=css_selector)

    def find_element(self, by, value, command=""):
        if command:
            element = self.execute(Command.FIND_ELEMENT, request=command, path=self.element.path, by=by, value=value)
        else:
            element = self.execute(Command.FIND_ELEMENT, path=self.element.path, by=by, value=value)

        if not element.result:
            raise NoSuchElementException("No element match with by=By.%s value=%s" % (by, value))
        return WebElement(self.execute, element)

    def find_elements(self, by, value):
        elements = self.execute(Command.FIND_ELEMENTS, path=self.element.path, by=by, value=value)
        result = []
        for element in elements.result:
            data = DictMap(elements)
            data.command = Command.FIND_ELEMENT
            data.path = "%s[%s]" % (elements.path, element[0])
            data.result = element[1]
            result.append(WebElement(self.execute, data))
        return result

    def get_attribute(self, attribute_name):
        if attribute_name == "class":
            attribute_name = "className"
        return self.execute(
            self.element.command,
            request=Command.GET_ATTRIBUTE,
            attribute_name=attribute_name,
            path=self.element.path,
            by=self.element.by,
            value=self.element.value,
        ).result

    @property
    def height(self):
        return self.get_attribute("getBoundingClientRect().height")

    @property
    def width(self):
        return self.get_attribute("getBoundingClientRect().width")

    @property
    def inner_html(self):
        return self.get_attribute("innerHTML")

    @inner_html.setter
    def inner_html(self, text):
        self.set_attribute("innerHTML", text)

    @property
    def outer_html(self):
        return self.get_attribute("outerHTML")

    @outer_html.setter
    def outer_html(self, text):
        self.set_attribute("outerHTML", text)

    @property
    def position(self):
        x = self.get_attribute("getBoundingClientRect().x")
        y = self.get_attribute("getBoundingClientRect().y")
        return x, y

    @property
    def disabled(self):
        return self.get_attribute("disabled")

    @disabled.setter
    def disabled(self, value):
        if value:
            self.set_attribute("disabled", "true", is_string=False)
        else:
            self.remove_attribute("disabled")

    @property
    def is_displayed(self):
        if self.height > 0 and self.width > 0:
            return True
        return False

    @property
    def read_only(self):
        return self.get_attribute("readOnly")

    def remove_attribute(self, attribute_name):
        return self.execute(
            self.element.command,
            request=Command.REMOVE_ATTRIBUTE,
            attribute_name=attribute_name,
            path=self.element.path,
            by=self.element.by,
            value=self.element.value,
        ).result

    def send_key(self, key):
        if self.read_only:
            raise InvalidElementStateException("Element is read-only: %s" % self.element.result)
        self.focus()
        return self.execute(
            self.element.command,
            request=Command.SEND_KEY,
            key=key,
            path=self.element.path,
            by=self.element.by,
            value=self.element.value,
        ).result

    def send_text(self, text):
        if self.read_only:
            raise InvalidElementStateException("Element is read-only: %s" % self.element.result)
        self.focus()
        return self.execute(
            self.element.command,
            request=Command.SEND_TEXT,
            text=text,
            path=self.element.path,
            by=self.element.by,
            value=self.element.value,
        ).result

    def set_attribute(self, attribute_name, attribute_value, is_string=True):
        is_string = "true" if is_string else "false"
        return self.execute(
            self.element.command,
            request=Command.SET_ATTRIBUTE,
            attribute_name=attribute_name,
            attribute_value=attribute_value,
            is_string=is_string,
            path=self.element.path,
            by=self.element.by,
            value=self.element.value,
        ).result

    @property
    def value(self):
        return self.get_attribute("value")

    @value.setter
    def value(self, value):
        self.set_attribute("value", value)


def find_element(driver, locator, command):
    locator = driver.find_element(*locator, command)
    return locator if isinstance(locator, WebElement) else False


def presence_of_element_located(locator):
    def _predicate(driver, _locator, command):
        _locator = find_element(driver, _locator, command)
        return True if _locator and _locator.element.result else _locator

    return lambda driver, command: _predicate(driver, locator, command)


def visibility_of_element_located(locator):
    def _predicate(driver, _locator, command):
        _locator = find_element(driver, _locator, command)
        return _locator if _locator and _locator.element.result and _locator.is_displayed else False

    return lambda driver, command: _predicate(driver, locator, command)


def invisibility_of_element_located(locator):
    def _predicate(driver, _locator, command):
        _locator = find_element(driver, _locator, command)
        return _locator if _locator and _locator.element.result and not _locator.is_displayed else False

    return lambda driver, command: _predicate(driver, locator, command)


def element_to_be_clickable(locator):
    def _predicate(driver, _locator, command):
        _locator = find_element(driver, _locator, command)
        return _locator if _locator and _locator.element.result and _locator.is_displayed and not _locator.disabled else False

    return lambda driver, command: _predicate(driver, locator, command)


class Select:

    def __init__(self, element):
        if element.get_attribute("tagName") != "SELECT":
            raise UnexpectedTagNameException(
                "Select only works on <select> elements, not on <%s>" % element.get_attribute("tagName")
            )
        self._element = element
        self.is_multiple = self._element.get_attribute("multiple")

    @staticmethod
    def _unset_selected(option):
        if option.get_attribute("selected"):
            option.set_attribute("selected", "false")

    @staticmethod
    def _set_selected(option):
        if not option.get_attribute("selected"):
            option.set_attribute("selected", "true")

    @property
    def options(self):
        return self._element.find_elements(By.TAG_NAME, "option")

    @property
    def all_selected_options(self):
        ret = []
        for otp in self.options:
            if otp.get_attribute("selected"):
                ret.append(otp)
        return ret

    @property
    def first_selected_option(self):
        for otp in self.options:
            if otp.get_attribute("selected"):
                return otp
        raise NoSuchElementException("No options are selected")

    def select_by_value(self, value):
        css = "option[value='%s']" % value
        opts = self._element.find_elements(By.CSS_SELECTOR, css)
        matched = False
        for opt in opts:
            self._set_selected(opt)
            if not self.is_multiple:
                return
            matched = True
        if not matched:
            raise NoSuchElementException("Cannot locate option with value: %s" % value)

    def select_by_index(self, index):
        for opt in self.options:
            if opt.get_attribute("index") == index:
                self._set_selected(opt)
                return
        raise NoSuchElementException("Could not locate element with index %d" % index)

    def select_by_visible_text(self, text):
        matched = False
        for opt in self.options:
            if opt.inner_html == text:
                self._set_selected(opt)
                if not self.is_multiple:
                    return
                matched = True
        if not matched:
            raise NoSuchElementException("Could not locate element with visible text: %s" % text)

    def deselect_all(self):
        if not self.is_multiple:
            raise NotImplementedError("You may only deselect all options of a multi-select")
        for opt in self.options:
            self._unset_selected(opt)

    def deselect_by_value(self, value):
        if not self.is_multiple:
            raise NotImplementedError("You may only deselect options of a multi-select")
        matched = False
        css = "option[value='%s']" % value
        opts = self._element.find_elements(By.CSS_SELECTOR, css)
        for opt in opts:
            self._unset_selected(opt)
            matched = True
        if not matched:
            raise NoSuchElementException("Could not locate element with value: %s" % value)

    def deselect_by_index(self, index):
        if not self.is_multiple:
            raise NotImplementedError("You may only deselect options of a multi-select")
        for opt in self.options:
            if opt.get_attribute("index") == index:
                self._unset_selected(opt)
                return
        raise NoSuchElementException("Could not locate element with index %d" % index)

    def deselect_by_visible_text(self, text):
        if not self.is_multiple:
            raise NotImplementedError("You may only deselect options of a multi-select")
        matched = False
        for opt in self.options:
            if opt.inner_html == text:
                self._set_selected(opt)
                if not self.is_multiple:
                    return
                matched = True
        if not matched:
            raise NoSuchElementException("Could not locate element with visible text: %s" % text)


class WebDriverWait:

    def __init__(self, driver, timeout):
        self.driver = driver
        self.timeout = timeout
        self.kill = False
        self.result = None

    def time(self):
        end_time = time.time() + self.timeout
        while True:
            if self.kill:
                self.kill = False
                break
            if time.time() > end_time:
                self.kill = True
                raise TimeoutError("Time out to wait element")

    def recv_result(self, method, command):
        self.result = method(self.driver, command)

    def until(self, method):
        time_thread = threading.Thread(target=self.time, daemon=True)
        recv_thread = threading.Thread(target=self.recv_result, args=(method, Command.WAIT_UNTIL_ELEMENT), daemon=True)
        time_thread.start()
        recv_thread.start()
        while True:
            if self.kill or not time_thread.is_alive():
                os._exit(0)
            try:
                if self.result:
                    if time_thread.is_alive():
                        self.kill = True
                    return self.result
            except Exception as ex:
                raise ex

    def until_not(self, method):
        time_thread = threading.Thread(target=self.time, daemon=True)
        recv_thread = threading.Thread(target=self.recv_result, args=(method, Command.WAIT_UNTIL_NOT_ELEMENT), daemon=True)
        time_thread.start()
        recv_thread.start()
        while True:
            if self.kill or not time_thread.is_alive():
                os._exit(0)
            try:
                if self.result:
                    if time_thread.is_alive():
                        self.kill = True
                    return None
            except Exception as ex:
                raise ex


class WebDriver(RemoteConnection):

    def __init__(self, gui=True, pip_mode=False, lang="en", debug=False, accept_time_out=60, recv_time_out=60 * 60):
        super(WebDriver, self).__init__(accept_time_out=accept_time_out)
        self.debug = debug
        self.encode_req = lambda _data, encode=True: ("%s\n" % DictMap(_data)).encode() if encode else "%s\n" % _data
        self.shut_up = False
        self._execute_lock = threading.RLock()
        data = {
            "command": Command.INIT,
            "pip_mode": pip_mode,
            "lang": lang,
            "debug": debug,
            "host": self.host,
            "port": self.port,
            "state": gui,
        }
        if "HOME" in os.environ and any(platform in os.environ["HOME"] for platform in ["termux", "pydroid3"]):
            if "pydroid3" in os.environ["HOME"]:
                data = {
                    "method": "launch-intent",
                    "action": "android.intent.action.VIEW",
                    "data": "webdriver://%s/?data=%s" % (
                        ANDROID_PACKAGE,
                        base64.b64encode(json.dumps(data).encode()).decode(),
                    ),
                }
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.connect(os.environ["PYDROID_RPC"])
                    sock.sendall((json.dumps(data) + "\n").encode())
            if "termux" in os.environ["HOME"]:
                data = self.encode_req(data, False)
                os.system(self.command("start", "%s/%s" % (ANDROID_PACKAGE, ANDROID_ACTIVITY), data))
        else:
            raise Exception("Only supports termux and pydroid3 at this moment")

        try:
            self.client_accept = self.accept()[0]
            self.client_accept.settimeout(recv_time_out)
        except TimeoutError:
            raise TimeoutError("Could not connect chrome webdriver")
        self.get("about:blank")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def command(action, name, data=""):
        return "am %s -n %s -d '%s' > /dev/null" % (action, name, data)

    @staticmethod
    def check_result(commnad, recv):
        data = DictMap(json.loads(recv), "no_encode_again")
        if commnad == data.command:
            return data
        raise TimeoutError("Unexpected command in webdriver response")

    def execute(self, command, **kwargs):
        acquired = self._execute_lock.acquire(timeout=0.2)
        if not acquired:
            raise TimeoutError("Webdriver channel busy")
        try:
            data = self.encode_req({
                "command": command,
                **kwargs,
            })
            self.client_accept.sendall(data)
            recv = self.recv_all()
            return self.check_result(command, recv)
        finally:
            self._execute_lock.release()

    def recv_all(self):
        result = b""
        length = b""
        while True:
            try:
                data = self.client_accept.recv(1)
            except Exception:
                raise TimeoutError("Time out to receive data")
            if data == b"":
                raise ApplicationClosed("Connection closed while waiting response header")
            if not data.decode().isdigit():
                result += data
                break
            length += data
        try:
            length = int(length.decode())
        except Exception:
            raise ApplicationClosed("Please close me by driver.close() conmand")
        while len(result) < length:
            try:
                chunk = self.client_accept.recv(min(self.max_recv, length - len(result)))
            except Exception:
                raise TimeoutError("Time out to receive data")
            if chunk == b"":
                raise ApplicationClosed("Connection closed while receiving response payload")
            result += chunk
        return decode_data(result)

    def close(self):
        return self.execute(Command.CLOSE).result

    @property
    def current_url(self):
        return self.execute(Command.CURRENT_URL).result

    def clear_cookie(self, cookie_name, url=""):
        return self.execute(Command.CLEAR_COOKIE, url=url, cookie_name=cookie_name).result

    def clear_cookies(self, url=""):
        return self.execute(Command.CLEAR_COOKIES, url=url).result

    def click_java(self, x, y):
        position = "%f %f" % (x, y)
        return self.execute(Command.CLICK_JAVA, position=position).result

    def clear_local_storage(self):
        return self.execute(Command.CLEAR_LOCAL_STORAGE).result

    def clear_session_storage(self):
        return self.execute(Command.CLEAR_SESSION_STORAGE).result

    def delete_all_cookie(self):
        return self.execute(Command.DELETE_ALL_COOKIE).result

    def clear_browser(self, clear_cache=True):
        cleared = {
            "cookies": False,
            "local_storage": False,
            "session_storage": False,
            "cache": False,
        }
        try:
            self.delete_all_cookie()
            cleared["cookies"] = True
        except Exception:
            pass
        try:
            self.clear_cookies()
            cleared["cookies"] = True
        except Exception:
            pass
        try:
            self.clear_local_storage()
            cleared["local_storage"] = True
        except Exception:
            pass
        try:
            self.clear_session_storage()
            cleared["session_storage"] = True
        except Exception:
            pass
        if clear_cache:
            try:
                self.execute_script(
                    """
                    try {
                        if (window.caches && caches.keys) {
                            caches.keys().then(function(keys) {
                                keys.forEach(function(key) {
                                    caches.delete(key);
                                });
                            });
                        }
                        if (window.navigator && navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
                            navigator.serviceWorker.getRegistrations().then(function(registrations) {
                                registrations.forEach(function(registration) {
                                    registration.unregister();
                                });
                            });
                        }
                    } catch (error) {}
                    return true;
                    """
                )
                cleared["cache"] = True
            except Exception:
                pass
        return cleared

    def load_cookies_from_requests(self, cookies, url=""):
        return load_cookies_from_requests(self, cookies, url=url)

    def use_spoof(self, spoof=None, merge=True):
        return use_spoof(self, spoof=spoof, merge=merge)

    @staticmethod
    def _wrap_execute_script(script):
        script = (script or "").strip()
        if not script:
            return "return null;"
        body = script if "return" in script else "return (%s);" % script
        prefix = """
        const __seledroid_root = document.documentElement || document.body || null;
        const __seledroid_store = function(status, payload) {
            if (!__seledroid_root) {
                return;
            }
            try {
                __seledroid_root.setAttribute("__SELEDROID_STATUS_ATTR__", status);
                __seledroid_root.setAttribute("__SELEDROID_RESULT_ATTR__", payload || "");
            } catch (error) {}
        };
        const __seledroid_seen = new WeakSet();
        const __seledroid_serialize = function(value) {
            if (value === undefined || value === null) {
                return null;
            }
            if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
                return value;
            }
            if (typeof Node !== "undefined" && value instanceof Node) {
                return {
                    nodeType: value.nodeType || null,
                    tagName: value.tagName || "",
                    id: value.id || "",
                    name: value.name || "",
                    className: value.className || "",
                    value: value.value || "",
                    textContent: (value.textContent || "").trim(),
                    outerHTML: value.outerHTML || ""
                };
            }
            if (typeof NodeList !== "undefined" && value instanceof NodeList) {
                return Array.from(value).map(__seledroid_serialize);
            }
            if (typeof HTMLCollection !== "undefined" && value instanceof HTMLCollection) {
                return Array.from(value).map(__seledroid_serialize);
            }
            if (Array.isArray(value)) {
                return value.map(__seledroid_serialize);
            }
            if (typeof value === "object") {
                if (__seledroid_seen.has(value)) {
                    return "[Circular]";
                }
                __seledroid_seen.add(value);
                const out = {};
                for (const key of Object.keys(value)) {
                    try {
                        out[key] = __seledroid_serialize(value[key]);
                    } catch (error) {
                        out[key] = "[Unserializable]";
                    }
                }
                return out;
            }
            return String(value);
        };
        try {
            __seledroid_store("running", "");
            const __seledroid_result = (function() {
        """.replace("__SELEDROID_STATUS_ATTR__", EXECUTE_SCRIPT_STATUS_ATTR).replace(
            "__SELEDROID_RESULT_ATTR__", EXECUTE_SCRIPT_RESULT_ATTR
        )
        suffix = """
            })();
            const __seledroid_payload = JSON.stringify({
                __seledroid_wrapped__: true,
                ok: true,
                value: __seledroid_serialize(__seledroid_result)
            });
            __seledroid_store("ok", __seledroid_payload);
            return __seledroid_payload;
        } catch (error) {
            const __seledroid_payload = JSON.stringify({
                __seledroid_wrapped__: true,
                ok: false,
                error: String(error && error.message ? error.message : error)
            });
            __seledroid_store("error", __seledroid_payload);
            return __seledroid_payload;
        }
        """
        return prefix + body + suffix

    @staticmethod
    def _wrap_execute_script_attribute(script):
        script = (script or "").strip()
        if not script:
            script = "return null;"
        elif "return" not in script:
            script = "return (%s);" % script
        return (
            "ownerDocument.defaultView.JSON.stringify((function(){"
            "const __seledroid_seen = new ownerDocument.defaultView.WeakSet();"
            "const __seledroid_serialize = function(value) {"
            "if (value === undefined || value === null) { return null; }"
            "if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') { return value; }"
            "if (typeof ownerDocument.defaultView.Node !== 'undefined' && value instanceof ownerDocument.defaultView.Node) {"
            "return {nodeType: value.nodeType || null, tagName: value.tagName || '', id: value.id || '', name: value.name || '', className: value.className || '', value: value.value || '', textContent: (value.textContent || '').trim(), outerHTML: value.outerHTML || ''};"
            "}"
            "if (typeof ownerDocument.defaultView.NodeList !== 'undefined' && value instanceof ownerDocument.defaultView.NodeList) { return ownerDocument.defaultView.Array.from(value).map(__seledroid_serialize); }"
            "if (typeof ownerDocument.defaultView.HTMLCollection !== 'undefined' && value instanceof ownerDocument.defaultView.HTMLCollection) { return ownerDocument.defaultView.Array.from(value).map(__seledroid_serialize); }"
            "if (ownerDocument.defaultView.Array.isArray(value)) { return value.map(__seledroid_serialize); }"
            "if (typeof value === 'object') {"
            "if (__seledroid_seen.has(value)) { return '[Circular]'; }"
            "__seledroid_seen.add(value);"
            "const out = {};"
            "for (const key of ownerDocument.defaultView.Object.keys(value)) {"
            "try { out[key] = __seledroid_serialize(value[key]); } catch (error) { out[key] = '[Unserializable]'; }"
            "}"
            "return out;"
            "}"
            "return ownerDocument.defaultView.String(value);"
            "};"
            "try {"
            "const __seledroid_run = ownerDocument.defaultView.Function(%s);"
            "const __seledroid_result = __seledroid_run.call(ownerDocument.defaultView);"
            "return __seledroid_serialize(__seledroid_result);"
            "} catch (error) {"
            "return {__seledroid_error__: ownerDocument.defaultView.String(error && error.message ? error.message : error)};"
            "}"
            "})())"
        ) % json.dumps(script)

    def _decode_execute_script_result(self, result):
        if isinstance(result, str):
            try:
                payload = json.loads(result)
            except Exception:
                payload = None
            if isinstance(payload, dict) and payload.get("__seledroid_wrapped__"):
                if not payload.get("ok", False):
                    error = payload.get("error", "Unknown JavaScript execution error")
                    self._debug_print("execute_script javascript error: %s" % error)
                    raise RuntimeError(error)
                return payload.get("value")
            if isinstance(payload, dict) and "__seledroid_error__" in payload:
                error = payload.get("__seledroid_error__", "Unknown JavaScript execution error")
                self._debug_print("execute_script fallback javascript error: %s" % error)
                raise RuntimeError(error)
            if payload is not None:
                return payload
        return result

    def _execute_script_via_document(self, script):
        root = self.find_element(By.TAG_NAME, "html")
        expression = self._wrap_execute_script_attribute(script)
        self._debug_print("execute_script fallback | attr=%s" % (expression[:120] + "..." if len(expression) > 120 else expression))
        return root.get_attribute(expression)

    def _read_execute_script_side_channel(self):
        root = self.find_element(By.TAG_NAME, "html")
        status = root.get_attribute("getAttribute('%s')" % EXECUTE_SCRIPT_STATUS_ATTR)
        payload = root.get_attribute("getAttribute('%s')" % EXECUTE_SCRIPT_RESULT_ATTR)
        return status, payload

    def execute_script(self, script):
        preview = " ".join((script or "").strip().split())
        preview = preview[:120] + "..." if len(preview) > 120 else preview
        try:
            current_url = self.current_url
        except Exception as exc:
            self._debug_print("execute_script current_url failed: %r" % exc)
            raise
        if not current_url:
            self._debug_print("execute_script skipped: no current_url | script=%s" % (preview or "-"))
            return
        self._debug_print("execute_script send | url=%s | script=%s" % (current_url, preview or "-"))
        wrapped_script = self._wrap_execute_script(script)
        try:
            result = self.execute(Command.EXECUTE_SCRIPT, script=wrapped_script).result
        except Exception as exc:
            self._debug_print("execute_script failed: %r" % exc)
            raise
        if result is None:
            self._debug_print("execute_script primary returned None; trying DOM side channel")
            result = None
            for _ in range(20):
                status, payload = self._read_execute_script_side_channel()
                if payload:
                    self._debug_print("execute_script side channel status=%r" % status)
                    result = payload
                    break
                time.sleep(0.05)
        if result is None:
            self._debug_print("execute_script side channel empty; trying DOM fallback")
            result = self._execute_script_via_document(script)
        result = self._decode_execute_script_result(result)
        self._debug_print("execute_script result: %r" % result)
        return result

    def _safe_current_url(self):
        try:
            return self.current_url
        except Exception:
            return ""

    def _safe_execute_script(self, script, default=None):
        try:
            result = self.execute_script(script)
        except Exception:
            return default
        if result is None:
            return default
        return result

    def _debug_print(self, message):
        if self.debug:
            print("[webdriver-debug] %s" % message, flush=True)

    def _navigation_snapshot(self):
        data = self._safe_execute_script(
            """
            var navigation = null;
            if (window.performance && performance.getEntriesByType) {
                navigation = performance.getEntriesByType("navigation")[0] || null;
            }
            var ajaxPending = 0;
            try {
                ajaxPending = window.jQuery ? window.jQuery.active : 0;
            } catch (error) {
                ajaxPending = 0;
            }
            return JSON.stringify({
                href: window.location.href,
                readyState: document.readyState,
                title: document.title || "",
                hasBody: !!document.body,
                bodyChildren: document.body ? document.body.children.length : 0,
                pendingImages: document.images ? Array.from(document.images).filter(function(image) {
                    return !image.complete;
                }).length : 0,
                htmlLength: document.documentElement ? document.documentElement.outerHTML.length : 0,
                timeOrigin: window.performance && performance.timeOrigin ? performance.timeOrigin : 0,
                domContentLoaded: navigation ? navigation.domContentLoadedEventEnd > 0 : document.readyState !== "loading",
                loadEventFired: navigation ? navigation.loadEventEnd > 0 : document.readyState === "complete",
                ajaxPending: ajaxPending
            });
            """,
            "",
        )
        if data:
            try:
                return json.loads(data)
            except Exception:
                self._debug_print("navigation snapshot parse failed; using fallback state")
        return {
            "href": self._safe_current_url(),
            "readyState": "",
            "title": "",
            "hasBody": False,
            "bodyChildren": 0,
            "pendingImages": 0,
            "htmlLength": 0,
            "timeOrigin": 0,
            "domContentLoaded": False,
            "loadEventFired": False,
            "ajaxPending": 0,
        }

    def _navigation_element_ready(self, locator):
        if locator is None:
            return True
        try:
            element = self.find_element(*locator)
        except Exception:
            return False
        if element and element.element.result and element.is_displayed:
            return element
        return False

    @staticmethod
    def _normalize_wait_locator(locator):
        if locator is None:
            return None
        if isinstance(locator, str):
            by = By.XPATH if locator.strip().startswith(("/", "(")) else By.CSS_SELECTOR
            return by, locator
        return locator

    @staticmethod
    def _supports_ansi():
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    @staticmethod
    def _ansi(text, color):
        if not WebDriver._supports_ansi():
            return text
        return "%s%s\033[0m" % (color, text)

    @staticmethod
    def _short_text(value, limit):
        value = (value or "").replace("\n", " ").strip()
        if len(value) <= limit:
            return value or "-"
        return value[: max(0, limit - 3)] + "..."

    @staticmethod
    def _page_is_ready(snapshot, wait_until):
        target = (wait_until or "complete").lower()
        if target in ("url_only", "url", "network_blind"):
            return bool(snapshot["href"])
        dom_ready = snapshot["hasBody"] and snapshot["readyState"] in ("interactive", "complete") and snapshot["domContentLoaded"]
        full_ready = dom_ready and snapshot["readyState"] == "complete" and snapshot["loadEventFired"] and snapshot["pendingImages"] == 0
        js_ready = full_ready and snapshot["ajaxPending"] == 0
        if target in ("domcontentloaded", "interactive", "dom"):
            return dom_ready
        if target in ("javascript", "js"):
            return js_ready
        return full_ready

    def _goto_log_line(self, snapshot, spinner, elapsed, wait_until, loaded):
        timeout_total = float(getattr(self, "_goto_timeout_total", 0) or 0)
        remaining = max(0.0, timeout_total - elapsed) if timeout_total else 0.0
        state = snapshot.get("readyState") or "unknown"
        if state == "unknown":
            state = "unk"
        url = self._short_text(snapshot.get("href", ""), 54)
        title = self._short_text(snapshot.get("title", ""), 30)
        state_color = "\033[32m" if loaded else "\033[33m" if state == "interactive" else "\033[31m"
        spin = self._ansi(spinner, "\033[2;36m")
        url_text = self._ansi(url, "\033[96m")
        title_text = self._ansi(title, "\033[2;95m")
        state_text = self._ansi(state, state_color)
        timer_text = self._ansi("t-%0.1fs" % remaining, "\033[2;37m")
        line = "%s goto %s | url=%s | title=%s | state=%s" % (
            spin,
            timer_text,
            url_text,
            title_text,
            state_text,
        )
        spoof = getattr(self, "_goto_spoof_info", None)
        if isinstance(spoof, dict) and spoof.get("ip"):
            ip_text = self._ansi(self._short_text(spoof.get("ip", ""), 20), "\033[2;92m")
            country_text = self._ansi(self._short_text(spoof.get("country", ""), 8), "\033[2;93m")
            name_text = self._ansi(self._short_text(spoof.get("name", ""), 20), "\033[2;94m")
            line += " | ip=%s | country=%s | name=%s" % (ip_text, country_text, name_text)
        return line

    @staticmethod
    def _wait_mode_ignores_locator(wait_until):
        return (wait_until or "").lower() in ("url_only", "url", "network_blind")

    def _emit_goto_log(self, line, final=False):
        if self._supports_ansi():
            clear = "\033[2K"
            suffix = "\n" if final else ""
            sys.stdout.write("\r" + clear + line + suffix)
            sys.stdout.flush()
            return
        if final:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def _wait_for_page_state(
        self,
        wait_until="complete",
        fallback_wait_until=None,
        fallback_after=None,
        locator=None,
        timeout=30,
        poll_frequency=0.12,
        settle_time=0.8,
        log=False,
    ):
        locator = self._normalize_wait_locator(locator)
        deadline = time.time() + timeout
        spinner = ["|", "/", "-", "\\"]
        spin_index = 0
        last_signature = None
        stable_since = None
        final_element = True
        last_line = ""
        last_printed_line = None
        fallback_applied = False
        fallback_target = (fallback_wait_until or "").lower() or None
        self._goto_timeout_total = timeout

        while time.time() < deadline:
            elapsed = time.time() - (deadline - timeout)
            snapshot = self._navigation_snapshot()
            if (
                fallback_target
                and not fallback_applied
                and elapsed >= (fallback_after if fallback_after is not None else min(5, timeout / 2))
            ):
                fallback_applied = True
                wait_until = fallback_target
                self._debug_print("goto fallback wait mode -> %s" % wait_until)
            if self._wait_mode_ignores_locator(wait_until):
                ready_element = True
            else:
                ready_element = self._navigation_element_ready(locator)
            ready_state = self._page_is_ready(snapshot, wait_until)
            loaded = bool(ready_state and ready_element)

            if loaded:
                signature = (
                    snapshot["href"],
                    snapshot["title"],
                    snapshot["readyState"],
                    snapshot["htmlLength"],
                    snapshot["bodyChildren"],
                    snapshot["pendingImages"],
                    snapshot["ajaxPending"],
                    bool(ready_element),
                )
                if signature != last_signature:
                    last_signature = signature
                    stable_since = time.time()
                elif stable_since is not None and time.time() - stable_since >= settle_time:
                    if locator is not None and not self._wait_mode_ignores_locator(wait_until):
                        final_element = ready_element
                    if log:
                        final_line = self._goto_log_line(snapshot, spinner[spin_index % len(spinner)], elapsed, wait_until, True)
                        self._emit_goto_log(final_line, final=True)
                    self._goto_timeout_total = 0
                    return final_element
            else:
                last_signature = None
                stable_since = None

            if log:
                last_line = self._goto_log_line(snapshot, spinner[spin_index % len(spinner)], elapsed, wait_until, loaded)
                if self._supports_ansi() or last_line != last_printed_line:
                    self._emit_goto_log(last_line, final=False)
                    last_printed_line = last_line
            spin_index += 1
            time.sleep(poll_frequency)

        if log:
            timeout_line = self._ansi("timeout", "\033[31m") + " " + (last_line or "goto timed out")
            self._emit_goto_log(timeout_line, final=True)
        self._goto_timeout_total = 0
        raise TimeoutError("Timed out waiting for page state=%s" % wait_until)

    def wait_for_navigation(self, locator=None, timeout=30, poll_frequency=0.1, settle_time=0.75):
        locator = self._normalize_wait_locator(locator)
        start = self._navigation_snapshot()
        deadline = time.time() + timeout
        navigation_started = False
        last_signature = None
        stable_since = None

        while time.time() < deadline:
            snapshot = self._navigation_snapshot()
            if not navigation_started:
                navigation_started = any([
                    snapshot["href"] != start["href"],
                    snapshot["timeOrigin"] != start["timeOrigin"],
                    snapshot["readyState"] in ("loading", "interactive"),
                    snapshot["title"] != start["title"],
                    snapshot["htmlLength"] != start["htmlLength"],
                    snapshot["bodyChildren"] != start["bodyChildren"],
                ])

            page_ready = all([
                snapshot["hasBody"],
                snapshot["readyState"] == "complete",
                snapshot["pendingImages"] == 0,
            ])
            ready_element = self._navigation_element_ready(locator)
            if navigation_started and page_ready and ready_element:
                signature = (
                    snapshot["href"],
                    snapshot["title"],
                    snapshot["htmlLength"],
                    snapshot["bodyChildren"],
                    snapshot["pendingImages"],
                    snapshot["readyState"],
                    bool(ready_element),
                )
                if signature != last_signature:
                    last_signature = signature
                    stable_since = time.time()
                elif stable_since is not None and time.time() - stable_since >= settle_time:
                    return ready_element if locator is not None else True
            else:
                last_signature = None
                stable_since = None
            time.sleep(poll_frequency)

        raise TimeoutError("Timed out waiting for navigation to finish")

    def typing_like_human(self, selector, text, press_enter=False):
        by = By.XPATH if selector.strip().startswith(("/", "(")) else By.CSS_SELECTOR
        element = self.find_element(by=by, value=selector)
        element.focus()
        for char in text:
            if char in ("\n", "\r"):
                element.send_key(Keys.ENTER)
            else:
                element.send_text(char)
            time.sleep(random.uniform(0.05, 0.18))
        if press_enter:
            time.sleep(random.uniform(0.08, 0.22))
            element.send_key(Keys.ENTER)
        return element

    def get_turnstile_token(
        self,
        selector="input[name='cf-turnstile-response']",
        timeout=10,
        poll_frequency=0.25,
    ):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                element = self.find_element_by_css_selector(selector)
                value = element.get_attribute("value")
                if value:
                    return value
            except Exception:
                pass
            time.sleep(poll_frequency)
        return ""

    def find_element_by_id(self, id_):
        return self.find_element(by=By.ID, value=id_)

    def find_element_by_xpath(self, xpath):
        return self.find_element(by=By.XPATH, value=xpath)

    def find_element_by_link_text(self, link_text):
        return self.find_element(by=By.LINK_TEXT, value=link_text)

    def find_element_by_partial_link_text(self, partial_link_text):
        return self.find_element(by=By.PARTIAL_LINK_TEXT, value=partial_link_text)

    def find_element_by_name(self, name):
        return self.find_element(by=By.NAME, value=name)

    def find_element_by_tag_name(self, tag_name):
        return self.find_element(by=By.TAG_NAME, value=tag_name)

    def find_element_by_class_name(self, class_name):
        return self.find_element(by=By.CLASS_NAME, value=class_name)

    def find_element_by_css_selector(self, css_selector):
        return self.find_element(by=By.CSS_SELECTOR, value=css_selector)

    def find_elements_by_id(self, id_):
        return self.find_elements(by=By.ID, value=id_)

    def find_elements_by_xpath(self, xpath):
        return self.find_elements(by=By.XPATH, value=xpath)

    def find_elements_by_link_text(self, link_text):
        return self.find_elements(by=By.LINK_TEXT, value=link_text)

    def find_elements_by_partial_link_text(self, partial_link_text):
        return self.find_elements(by=By.PARTIAL_LINK_TEXT, value=partial_link_text)

    def find_elements_by_name(self, name):
        return self.find_elements(by=By.NAME, value=name)

    def find_elements_by_tag_name(self, tag_name):
        return self.find_elements(by=By.TAG_NAME, value=tag_name)

    def find_elements_by_class_name(self, class_name):
        return self.find_elements(by=By.CLASS_NAME, value=class_name)

    def find_elements_by_css_selector(self, css_selector):
        return self.find_elements(by=By.CSS_SELECTOR, value=css_selector)

    def find_element(self, by, value, command=""):
        if command:
            element = self.execute(Command.FIND_ELEMENT, request=command, by=by, value=value)
        else:
            element = self.execute(Command.FIND_ELEMENT, by=by, value=value)
        if not element.result:
            if not self.shut_up:
                raise NoSuchElementException("No element match with by=By.%s value=%s" % (by, value))
        return WebElement(self.execute, element)

    def find_elements(self, by, value):
        elements = self.execute(Command.FIND_ELEMENTS, by=by, value=value)
        result = []
        for element in elements.result:
            data = DictMap(elements)
            data.command = Command.FIND_ELEMENT
            data.path = "%s[%s]" % (elements.path, element[0])
            data.result = element[1]
            result.append(WebElement(self.execute, data))
        return result

    def get(self, url, **kwargs):
        use_cookie_from_requests = kwargs.pop("use_cookie_from_requests", None)
        if kwargs:
            unexpected = ", ".join(sorted(kwargs.keys()))
            raise TypeError("Unexpected keyword argument(s): %s" % unexpected)
        state, cookies = _parse_cookie_loader_option(use_cookie_from_requests)
        if state and cookies is not None:
            self._debug_print("loading request cookies for %s" % url)
            self.load_cookies_from_requests(cookies, url=url)
        self._debug_print("GET start %s" % url)
        return self.execute(Command.GET, url=url).result

    def goto(self, url, **kwargs):
        wait_until = kwargs.pop("wait_until", "javascript")
        fallback_wait_until = kwargs.pop("fallback_wait_until", None)
        fallback_after = kwargs.pop("fallback_after", None)
        spoof = kwargs.pop("use_spoof", None)
        clear_browser_state = kwargs.pop("clear_browser_state", True)
        locator = kwargs.pop("locator", kwargs.pop("wait_for", None))
        timeout = kwargs.pop("timeout", 30)
        poll_frequency = kwargs.pop("poll_frequency", 0.12)
        settle_time = kwargs.pop("settle_time", 0.8)
        log = kwargs.pop("log", True)
        if clear_browser_state:
            self.clear_browser()
        if spoof:
            self.use_spoof(None if spoof is True else spoof)
        self.get(url, **kwargs)
        self._wait_for_page_state(
            wait_until=wait_until,
            fallback_wait_until=fallback_wait_until,
            fallback_after=fallback_after,
            locator=locator,
            timeout=timeout,
            poll_frequency=poll_frequency,
            settle_time=settle_time,
            log=log,
        )
        return self

    def get_cookie(self, cookie_name, url=""):
        return self.execute(Command.GET_COOKIE, url=url, cookie_name=cookie_name).result

    def get_cookies(self, url=""):
        return self.execute(Command.GET_COOKIES, url=url).result

    def get_local_storage(self):
        result = dict(self.execute(Command.GET_LOCAL_STORAGE).result)
        return dict(zip(result.keys(), result.values()))

    def get_session_storage(self):
        result = dict(self.execute(Command.GET_SESSION_STORAGE).result)
        return dict(zip(result.keys(), result.values()))

    def get_recaptcha_v3_token(self, action=""):
        try:
            site_key = self.find_element(By.CSS_SELECTOR, "script[src*=\"https://www.google.com/recaptcha/api.js?render=\"]")
        except Exception:
            return None
        site_key = site_key.get_attribute("src").replace("https://www.google.com/recaptcha/api.js?render=", "")
        return self.execute(Command.GET_RECAPTCHA_V3_TOKEN, site_key=site_key, action=action).result

    @property
    def headers(self):
        return self.execute(Command.GET_HEADERS).result

    @headers.setter
    def headers(self, headers):
        headers = {key.title(): value for key, value in headers.items()}
        self.execute(Command.SET_HEADERS, headers=json.dumps(headers))

    def override_js_function(self, script):
        return self.execute(Command.OVERRIDE_JS_FUNCTION, script=script).result

    @property
    def page_source(self):
        page_source = self.execute(Command.PAGE_SOURCE).result
        return page_source

    def swipe(self, start_x, start_y, end_x, end_y, speed=1):
        position = "%f %f %f %f" % (start_x, start_y, end_x, end_y)
        return self.execute(Command.SWIPE, position=position, speed=speed).result

    def swipe_down(self):
        return self.execute(Command.SWIPE_DOWN).result

    def swipe_up(self):
        return self.execute(Command.SWIPE_UP).result

    def set_cookie(self, cookie_name, value, url=""):
        return self.execute(Command.SET_COOKIE, url=url, cookie_name=cookie_name, value=value).result

    def set_proxy(self, host, port):
        proxy = "%s %s" % (host, port)
        return self.execute(Command.SET_PROXY, proxy=proxy).result

    def scroll_to(self, x, y):
        position = "%d %d" % (x, y)
        return self.execute(Command.SCROLL_TO, position=position).result

    def set_local_storage(self, key, value, is_string=True):
        is_string = "true" if is_string else "false"
        return self.execute(Command.SET_LOCAL_STORAGE, key=key, value=value, is_string=is_string).result

    def set_session_storage(self, key, value, is_string=True):
        is_string = "true" if is_string else "false"
        return self.execute(Command.SET_SESSION_STORAGE, key=key, value=value, is_string=is_string).result

    @property
    def user_agent(self):
        return self.execute(Command.GET_USER_AGENT).result

    @user_agent.setter
    def user_agent(self, user_agent):
        self.execute(Command.SET_USER_AGENT, user_agent=user_agent)

    @property
    def title(self):
        return self.execute(Command.TITLE).result

    @staticmethod
    def wait(delay):
        return time.sleep(delay)


Chrome = WebDriver

__all__ = [
    "__version__",
    "ANDROID_ACTIVITY",
    "ANDROID_PACKAGE",
    "ApplicationClosed",
    "AsnHit",
    "By",
    "build_spoof_headers",
    "Chrome",
    "clear_browser",
    "Command",
    "DictMap",
    "InvalidElementStateException",
    "Keys",
    "NoSuchElementException",
    "RemoteConnection",
    "Select",
    "UnexpectedTagNameException",
    "WebDriver",
    "WebDriverException",
    "WebDriverWait",
    "WebElement",
    "b64decode",
    "b64encode",
    "decode_data",
    "element_to_be_clickable",
    "find_element",
    "generate_ip",
    "goto",
    "invisibility_of_element_located",
    "load_ip2asn_u32_tsv",
    "load_cookies_from_requests",
    "lookup_asn",
    "normalize_spoof",
    "presence_of_element_located",
    "random_public_ip_from_db",
    "use_spoof",
    "visibility_of_element_located",
]

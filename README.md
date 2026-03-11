# dbgidchromium

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Android](https://img.shields.io/badge/Android-Termux%20%7C%20Pydroid3-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://developer.android.com/)
[![Status](https://img.shields.io/badge/Automation-WebDriver%20Toolkit-111827?style=for-the-badge)](https://github.com/dbgid/dbgidchromium)
[![Repo](https://img.shields.io/badge/GitHub-dbgid%2Fdbgidchromium-181717?style=for-the-badge&logo=github)](https://github.com/dbgid/dbgidchromium)
[![Required Browser](https://img.shields.io/badge/Required%20Browser-DBG--ID%20Browser-0F766E?style=for-the-badge&logo=googlechrome&logoColor=white)](https://github.com/dbgid/DBG-ID-Browser)

Android-focused browser automation toolkit with navigation helpers, spoofed request headers, browser-state cleanup, token lookup helpers, and IP/ASN spoof generation.

## Requirement

Required browser: [DBG-ID-Browser](https://github.com/dbgid/DBG-ID-Browser)

## Highlights

- Animated `goto()` navigation with styled terminal progress
- `driver.goto(...)` and module-level `goto(driver, ...)`
- Browser cleanup before navigation
- Header spoofing via generated public IP data
- Turnstile token polling helper
- Human-like typing helper
- Local IP/ASN database helper via `generate_ip()`

## Installation

### 1. Install Required Browser

Install [DBG-ID-Browser](https://github.com/dbgid/DBG-ID-Browser) first.

### 2. GitHub

```bash
git clone https://github.com/dbgid/dbgidchromium
cd dbgidchromium
```

### 3. Install via PyPI

```bash
pip install dbgidchromium
```

### 4. Install from GitHub

```bash
pip install git+https://github.com/dbgid/dbgidchromium
```

## Import

```python
from dbgidchromium import (
    WebDriver,
    By,
    goto,
    clear_browser,
    generate_ip,
    use_spoof,
)
```

## Quick Start

This package supports both native function-style usage and `WebDriver` method-style usage.

### Function Style

```python
from dbgidchromium import WebDriver, goto

driver = WebDriver(gui=False, debug=True)

try:
    goto(
        driver,
        "https://claimyshare.io",
        wait_until="complete",
        fallback_wait_until="url_only",
        fallback_after=5,
        locator="body",
        timeout=60,
        log=True,
    )

    print(driver.current_url)
    print(driver.title)
finally:
    driver.close()
```

### Method Style

```python
from dbgidchromium import WebDriver

driver = WebDriver(gui=False, debug=True)

try:
    driver.goto(
        "https://claimyshare.io",
        wait_until="complete",
        fallback_wait_until="url_only",
        fallback_after=5,
        locator="body",
        timeout=60,
        log=True,
    )

    print(driver.current_url)
    print(driver.title)
finally:
    driver.close()
```

## API Table

| Field | Details | Description |
|---|---|---|
| `WebDriver(gui=True, debug=False)` | Main browser session object | Starts the Android browser driver session |
| `goto(driver, url, **kwargs)` | Module helper | Navigates with progress logging and wait control |
| `driver.goto(url, **kwargs)` | Method helper | Same behavior as the module helper |
| `clear_browser(driver)` | Module helper | Clears cookies, local storage, session storage, and best-effort cache state |
| `driver.clear_browser()` | Method helper | Clears browser state before or between runs |
| `generate_ip()` | Module helper | Returns a random global IPv4 with ASN, country, and ISP/org name |
| `use_spoof(driver, spoof=None)` | Module helper | Applies spoof headers using a generated or provided IP payload |
| `driver.use_spoof(spoof=None)` | Method helper | Same spoof behavior from the session object |
| `driver.get_turnstile_token()` | Method helper | Waits for `input[name='cf-turnstile-response']` and returns its value |
| `driver.typing_like_human(selector, text, press_enter=False)` | Method helper | Types with per-character delay |
| `driver.wait_for_navigation(...)` | Method helper | Waits for click-triggered navigation to settle |
| `driver.execute_script(script)` | Method helper | Sends JavaScript to the page context |

## Function vs Method

| Function | Method | Equivalent |
|---|---|---|
| `goto(driver, url, **kwargs)` | `driver.goto(url, **kwargs)` | Navigation helper |
| `clear_browser(driver)` | `driver.clear_browser()` | Clear browser state |
| `use_spoof(driver, spoof=None)` | `driver.use_spoof(spoof=None)` | Apply spoof headers |
| `generate_ip()` | `driver.use_spoof()` with generated payload | IP spoof source for headers |

## `goto()` Kwargs

| Field | Details | Description |
|---|---|---|
| `wait_until` | `javascript`, `complete`, `domcontentloaded`, `url_only`, `network_blind` | Controls how strict page readiness should be |
| `fallback_wait_until` | Optional mode string | Fallback readiness mode if the main wait mode does not resolve |
| `fallback_after` | Seconds | Time before fallback mode is used |
| `locator` / `wait_for` | CSS, XPath, or `(By, value)` tuple | Extra target to wait for |
| `timeout` | Seconds | Max navigation wait time |
| `poll_frequency` | Seconds | Poll interval while waiting |
| `settle_time` | Seconds | Stability window before navigation is considered complete |
| `log` | `True` / `False` | Enables styled progress output |
| `clear_browser_state` | `True` / `False` | Clears cookies/storage/cache before navigation |
| `use_spoof` | `True`, IP dict, or IP string | Applies spoof headers before the request |
| `use_cookie_from_requests` | Tuple or dict | Loads cookies into the browser before navigation |

## Header Spoofing

### Native Function Style

```python
from dbgidchromium import WebDriver, generate_ip, use_spoof

driver = WebDriver(gui=False)

spoof = generate_ip()
print(spoof)

use_spoof(driver, spoof)
print(driver.headers)
```

### Method Style

```python
from dbgidchromium import WebDriver

driver = WebDriver(gui=False)

spoof = driver.use_spoof()
print(spoof)
print(driver.headers)
```

### Inside `goto()`

```python
driver.goto(
    "https://example.com",
    use_spoof=True,
    log=True,
)
```

### Custom spoof payload

```python
driver.goto(
    "https://example.com",
    use_spoof={
        "ip": "1.2.3.4",
        "country": "US",
        "name": "TEST-NET",
    },
    log=True,
)
```

When spoofing is active, the navigation log can show:

```text
| goto t-59.8s | url=https://example.com | title=- | state=unk | ip=1.2.3.4 | country=US | name=TEST-NET
```

## Browser Cleanup

### Native Function Style

```python
from dbgidchromium import WebDriver, clear_browser

driver = WebDriver(gui=False)

clear_browser(driver)
driver.goto("https://example.com")
```

### Method Style

```python
driver.clear_browser()
driver.goto("https://example.com")
```

## Turnstile Token Helper

### Method Style

```python
token = driver.get_turnstile_token()
print(token)
```

Custom wait:

```python
token = driver.get_turnstile_token(
    selector="input[name='cf-turnstile-response']",
    timeout=20,
    poll_frequency=0.5,
)
```

## Human Typing

### Method Style

```python
driver.typing_like_human("input[name='q']", "hello world", press_enter=True)
driver.typing_like_human("//input[@name='q']", "hello", press_enter=False)
```

## Wait for Click Navigation

### Method Style

```python
from dbgidchromium import By

button = driver.find_element_by_css_selector("button")
button.click()
driver.wait_for_navigation(locator=(By.CSS_SELECTOR, "body"))
```

## Cookies From `requests`

### Method Style

```python
import requests

session = requests.Session()

driver.goto(
    "https://example.com",
    use_cookie_from_requests=(True, session.cookies),
)
```

## JavaScript

### Method Style

```python
result = driver.execute_script("return document.title")
print(result)
```

## IP Database

`generate_ip()` uses the bundled local database file:

| Field | Details | Description |
|---|---|---|
| `ip2asn-v4-u32.tsv` | Local TSV DB | Source for random global IPv4 + ASN lookup |
| `ip` | IPv4 string | Generated public IP |
| `country` | Country code | ASN country field |
| `name` | ASN / network name | ISP or organization label |
| `asn` | Integer | ASN number |

## Example Session

```python
from dbgidchromium import WebDriver

driver = WebDriver(gui=False, debug=True)

try:
    driver.goto(
        "https://claimyshare.io",
        wait_until="complete",
        fallback_wait_until="url_only",
        fallback_after=5,
        use_spoof=True,
        log=True,
    )

    print("URL:", driver.current_url)
    print("Title:", driver.title)
    print("Turnstile:", driver.get_turnstile_token())
finally:
    driver.close()
```

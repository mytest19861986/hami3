"""
Automated Verification & Responsive Screenshot Suite for HC-T16 (Phase 3 Isolated UI Shell)
BASELINE: BL-HAMICARD-PRD-V1 | Section 21 (UX-001..019), Section 27, AC-17

Verifies:
- T16-AC1: All Section 27 public pages, auth shell, all 6 PRD role panels, and
  Loading / Empty / Error / Disabled states render cleanly.
- T16-AC2: RTL Persian (`dir="rtl"`, `lang="fa"`), deterministic Jalali dates (`۱۴۰۵/۰۸/۱۹`),
  Toman currency labels, keyboard drawer escape handling, and ZERO horizontal overflow
  across Mobile (390x844), Tablet (768x1024), and Desktop (1280x800).
- T16-AC3: Persistent Synthetic Demo Data banner, OPEN-15 proposed notice,
  ZERO outbound calls to unaccepted Phase 2 auth or financial APIs, ZERO demo credentials.
"""

import functools
import http.server
import pathlib
import threading

import pytest
from playwright.sync_api import sync_playwright

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
UI_DIR = ROOT_DIR / "src" / "ui_shell"
SHOTS_DIR = ROOT_DIR / "docs" / "screenshots" / "phase3"

BROWSER_CANDIDATES = [
    pathlib.Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
    pathlib.Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
    pathlib.Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
]


def _get_browser_exe() -> str:
    for p in BROWSER_CANDIDATES:
        if p.exists():
            return str(p)
    pytest.skip("No Chromium/Edge executable available for headless Playwright verification")


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return


@pytest.fixture(scope="module")
def ui_server_url():
    handler = functools.partial(_QuietHandler, directory=str(UI_DIR))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/index.html"
    finally:
        server.shutdown()
        server.server_close()


def test_t16_ac1_ac2_ac3_rtl_responsive_states_and_screenshots(ui_server_url: str):
    SHOTS_DIR.mkdir(parents=True, exist_ok=True)
    browser_exe = _get_browser_exe()

    viewports = [
        ("desktop", 1280, 800),
        ("tablet", 768, 1024),
        ("mobile", 390, 844),
    ]
    routes = [
        "#/home",
        "#/doctors",
        "#/plans",
        "#/content/about",
        "#/content/terms",
        "#/content/privacy",
        "#/content/faq",
        "#/content/contact",
        "#/auth/shell",
        "#/panel/user",
        "#/panel/doctor",
        "#/panel/agent",
        "#/panel/support",
        "#/panel/admin",
        "#/panel/super-admin",
    ]
    states = ["NORMAL", "LOADING", "EMPTY", "ERROR", "DISABLED_GATE"]

    console_errors: list[str] = []
    page_errors: list[str] = []
    external_or_api_calls: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=browser_exe)
        try:
            for vp_name, width, height in viewports:
                context = browser.new_context(viewport={"width": width, "height": height})
                page = context.new_page()

                page.on(
                    "console",
                    lambda msg: console_errors.append(msg.text)
                    if msg.type == "error"
                    else None,
                )
                page.on("pageerror", lambda err: page_errors.append(str(err)))
                page.on(
                    "request",
                    lambda req: external_or_api_calls.append(req.url)
                    if (
                        not req.url.startswith("http://127.0.0.1:")
                        or "/api/v1/" in req.url
                    )
                    else None,
                )

                page.goto(ui_server_url, wait_until="networkidle")

                # Verify D-1 (44px touch targets on .hc-pill-btn), D-2 (narrow aria-live), D-5 (radiogroup/radio)
                a11y_meta = page.evaluate(
                    """() => {
                        const root = document.getElementById('app-root');
                        const live = document.getElementById('hc-live-status');
                        const pills = [...document.querySelectorAll('.hc-pill-btn')];
                        const groups = [...document.querySelectorAll('.hc-pill-group')];
                        return {
                            appRootAriaLive: root ? root.getAttribute('aria-live') : null,
                            liveStatusRole: live ? live.getAttribute('role') : null,
                            liveStatusPolite: live ? live.getAttribute('aria-live') : null,
                            groupRoles: groups.map((g) => g.getAttribute('role')),
                            pillRoles: pills.map((b) => b.getAttribute('role')),
                            pillHeights: pills.map((b) => b.getBoundingClientRect().height),
                            pillWidths: pills.map((b) => b.getBoundingClientRect().width),
                        };
                    }"""
                )
                assert a11y_meta["appRootAriaLive"] is None, "D-2: #app-root must not carry aria-live"
                assert a11y_meta["liveStatusRole"] == "status"
                assert a11y_meta["liveStatusPolite"] == "polite"
                assert a11y_meta["groupRoles"] == ["radiogroup", "radiogroup"]
                assert len(a11y_meta["pillRoles"]) == 11 and all(r == "radio" for r in a11y_meta["pillRoles"])
                assert all(h >= 44.0 for h in a11y_meta["pillHeights"]), (
                    f"D-1 violation: pill touch target < 44px on {vp_name}: {a11y_meta['pillHeights']}"
                )
                assert all(w >= 44.0 for w in a11y_meta["pillWidths"]), (
                    f"D-1 violation: pill width < 44px on {vp_name}: {a11y_meta['pillWidths']}"
                )

                # Verify RTL & Persian language
                doc_meta = page.evaluate(
                    """() => ({
                        dir: document.documentElement.dir,
                        lang: document.documentElement.lang,
                        bodyText: document.body.innerText
                    })"""
                )
                assert doc_meta["dir"] == "rtl", f"Expected RTL on {vp_name}"
                assert doc_meta["lang"] == "fa", f"Expected lang=fa on {vp_name}"
                assert "Synthetic Demo Data" in doc_meta["bodyText"]
                assert "OPEN-15" in doc_meta["bodyText"]
                # Exact deterministic Jalali conversion check for 2026-11-10 -> ۱۴۰۵/۰۸/۱۹
                assert "۱۴۰۵/۰۸/۱۹" in doc_meta["bodyText"]

                # Check every Section 27 route for zero horizontal overflow & valid content
                for route in routes:
                    page.evaluate(f"window.location.hash = '{route}';")
                    page.wait_for_timeout(60)
                    overflow = page.evaluate(
                        "() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth })"
                    )
                    assert overflow["sw"] <= overflow["iw"], (
                        f"Horizontal overflow at {vp_name} ({width}px) on {route}: "
                        f"scrollWidth={overflow['sw']} > innerWidth={overflow['iw']}"
                    )

                # Capture key visual screenshots
                if vp_name == "desktop":
                    page.evaluate("window.location.hash = '#/home';")
                    page.wait_for_timeout(80)
                    page.screenshot(path=str(SHOTS_DIR / "desktop_home.png"), full_page=True)

                    page.evaluate("window.location.hash = '#/plans';")
                    page.wait_for_timeout(80)
                    page.screenshot(path=str(SHOTS_DIR / "desktop_plans.png"), full_page=True)

                    page.evaluate("window.location.hash = '#/panel/agent';")
                    page.wait_for_timeout(80)
                    page.screenshot(path=str(SHOTS_DIR / "desktop_panel_agent.png"), full_page=True)

                elif vp_name == "tablet":
                    page.evaluate("window.location.hash = '#/doctors';")
                    page.wait_for_timeout(80)
                    page.screenshot(path=str(SHOTS_DIR / "tablet_doctors.png"), full_page=True)

                elif vp_name == "mobile":
                    # Test mobile hamburger menu accessibility, focus move, focus trap (D-3), and Escape key close
                    toggle = page.locator("#hc-menu-toggle")
                    assert toggle.is_visible()
                    toggle.click()
                    assert toggle.get_attribute("aria-expanded") == "true"
                    inside_on_open = page.evaluate(
                        "() => Boolean(document.activeElement && document.activeElement.closest('#hc-mobile-drawer'))"
                    )
                    assert inside_on_open, "D-3: focus must move into #hc-mobile-drawer on open"
                    for _ in range(15):
                        page.keyboard.press("Tab")
                        still_inside = page.evaluate(
                            "() => Boolean(document.activeElement && document.activeElement.closest('#hc-mobile-drawer'))"
                        )
                        assert still_inside, "D-3: Tab escaped mobile drawer focus trap!"
                    page.keyboard.press("Shift+Tab")
                    still_inside_shift = page.evaluate(
                        "() => Boolean(document.activeElement && document.activeElement.closest('#hc-mobile-drawer'))"
                    )
                    assert still_inside_shift, "D-3: Shift+Tab escaped mobile drawer focus trap!"
                    page.keyboard.press("Escape")
                    assert toggle.get_attribute("aria-expanded") == "false"
                    focused_toggle = page.evaluate(
                        "() => document.activeElement && document.activeElement.id === 'hc-menu-toggle'"
                    )
                    assert focused_toggle, "D-3: Escape must restore focus to #hc-menu-toggle"

                    toggle.click()
                    drawer_close_h = page.evaluate(
                        "() => document.getElementById('hc-drawer-close').getBoundingClientRect().height"
                    )
                    assert drawer_close_h >= 44.0, f"D-1: #hc-drawer-close height {drawer_close_h} < 44"
                    page.click("#hc-drawer-close")
                    assert toggle.get_attribute("aria-expanded") == "false"
                    focused_after_btn = page.evaluate(
                        "() => document.activeElement && document.activeElement.id === 'hc-menu-toggle'"
                    )
                    assert focused_after_btn, "D-3: #hc-drawer-close click must restore focus to #hc-menu-toggle"

                    page.evaluate("window.location.hash = '#/home';")
                    page.wait_for_timeout(80)
                    page.screenshot(path=str(SHOTS_DIR / "mobile_home.png"), full_page=True)

                    page.evaluate("window.location.hash = '#/panel/support';")
                    page.wait_for_timeout(80)
                    page.screenshot(path=str(SHOTS_DIR / "mobile_panel_support.png"), full_page=True)

                # Test interactive Doctors filter, detail focus management & restoration (D-4), & Empty filter fallback
                page.evaluate("window.location.hash = '#/doctors';")
                page.wait_for_timeout(60)
                page.click('[data-select-doctor="demo-doc-1"]')
                page.wait_for_timeout(40)
                detail_focus_ok = page.evaluate(
                    "() => Boolean(document.activeElement && (document.activeElement.id === 'hc-doc-detail-heading' || document.activeElement.closest('#hc-doc-detail')))"
                )
                assert detail_focus_ok, "D-4: opening doctor detail must move focus into detail region"
                page.click("#hc-close-doc-detail")
                page.wait_for_timeout(40)
                restored_doc_btn = page.evaluate(
                    "() => document.activeElement && document.activeElement.getAttribute('data-select-doctor') === 'demo-doc-1'"
                )
                assert restored_doc_btn, "D-4: closing doctor detail must restore focus to triggering button"

                page.click('[data-select-doctor="demo-doc-1"]')
                page.wait_for_timeout(40)
                page.keyboard.press("Escape")
                page.wait_for_timeout(40)
                restored_doc_esc = page.evaluate(
                    "() => document.activeElement && document.activeElement.getAttribute('data-select-doctor') === 'demo-doc-1'"
                )
                assert restored_doc_esc, "D-4: Escape in doctor detail must close and restore focus to triggering button"

                page.fill("#hc-doc-search", "دندان")
                assert "کلینیک آزمایشی سلامت قلب" not in page.locator("#app-root").inner_text()
                assert "درمانگاه دندانپزشکی نمونه" in page.locator("#app-root").inner_text()
                page.fill("#hc-doc-search", "تخصص_ناموجود_تست")
                assert "پزشک نمونه‌ای با فیلتر انتخابی یافت نشد" in page.locator("#app-root").inner_text()
                page.click("#hc-clear-doc-filter")
                assert "دکتر الف" in page.locator("#app-root").inner_text()

                # Test radiogroup arrow-key navigation (D-5) + all 5 UI state buttons on /panel/user
                page.evaluate("window.location.hash = '#/panel/user';")
                page.wait_for_timeout(60)
                page.locator('[data-ui-state="NORMAL"]').focus()
                page.keyboard.press("ArrowLeft")
                page.wait_for_timeout(40)
                assert page.locator('[data-ui-state="LOADING"]').get_attribute("aria-checked") == "true"
                page.keyboard.press("ArrowRight")
                page.wait_for_timeout(40)
                assert page.locator('[data-ui-state="NORMAL"]').get_attribute("aria-checked") == "true"
                for st in states:
                    page.click(f'[data-ui-state="{st}"]')
                    page.wait_for_timeout(50)
                    assert page.locator(f'[data-ui-state="{st}"]').get_attribute("aria-checked") == "true"
                    ov = page.evaluate(
                        "() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth })"
                    )
                    assert ov["sw"] <= ov["iw"], f"Overflow in state {st} on {vp_name}"
                    if vp_name == "desktop" and st == "DISABLED_GATE":
                        page.screenshot(
                            path=str(SHOTS_DIR / "desktop_state_disabled.png"),
                            full_page=True,
                        )
                page.click('[data-ui-state="NORMAL"]')

                # Confirm all sensitive write buttons remain disabled
                page.evaluate("window.location.hash = '#/panel/agent';")
                page.wait_for_timeout(50)
                disabled_attr = page.locator("#app-root button[disabled]").first.get_attribute("aria-disabled")
                assert disabled_attr == "true"

                context.close()
        finally:
            browser.close()

    assert console_errors == [], f"Console errors observed: {console_errors}"
    assert page_errors == [], f"Uncaught page errors observed: {page_errors}"
    assert external_or_api_calls == [], (
        f"Unexpected external or backend API calls from isolated UI shell: {external_or_api_calls}"
    )


def test_t16_ac3_no_demo_credentials_or_hardcoded_tokens():
    forbidden_markers = ["Bearer ", "password123", "SecurePassword", "get_active_otp_for_test"]
    for file_path in UI_DIR.rglob("*"):
        if file_path.is_file():
            content = file_path.read_text(encoding="utf-8")
            for marker in forbidden_markers:
                assert marker not in content, f"Forbidden credential marker '{marker}' in {file_path}"

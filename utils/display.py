"""
Console display utilities — banners, colored output, progress indicators.
"""

import sys
from typing import Optional


RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
DIM = "\033[2m"


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class Banner:
    TEXT = r"""
  _   _      _   ____            _             _ _ _
 | \ | | ___| |_/ ___|  ___  ___| |   __ _ _  _(_) |_ ___ _ __
 |  \| |/ _ \ __\___ \ / _ \/ __| |  / _` | || | |  _/ _ \ '__|
 | |\  |  __/ |_ ___) |  __/ (__| | | (_| | || | | ||  __/ |
 |_| \_|\___|\__|____/ \___|\___|_|  \__,_|\_,_|_|\__\___|_|

      Network Security Assessment Tool  v1.0.0
      For authorized use only — use responsibly
"""

    @classmethod
    def print(cls):
        if _supports_color():
            print(f"{CYAN}{BOLD}{cls.TEXT}{RESET}")
        else:
            print(cls.TEXT)


class Console:
    @staticmethod
    def _c(color: str, msg: str):
        if _supports_color():
            print(f"{color}{msg}{RESET}")
        else:
            print(msg)

    @classmethod
    def info(cls, msg: str):
        cls._c(CYAN, msg)

    @classmethod
    def success(cls, msg: str):
        cls._c(GREEN, msg)

    @classmethod
    def warning(cls, msg: str):
        cls._c(YELLOW, msg)

    @classmethod
    def error(cls, msg: str):
        cls._c(RED, msg)

    @classmethod
    def section(cls, title: str):
        line = "─" * 60
        if _supports_color():
            print(f"\n{BOLD}{BLUE}{line}{RESET}")
            print(f"{BOLD}{BLUE}  {title}{RESET}")
            print(f"{BOLD}{BLUE}{line}{RESET}")
        else:
            print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

    @classmethod
    def separator(cls):
        if _supports_color():
            print(f"{DIM}{'─'*60}{RESET}")
        else:
            print("─" * 60)

    @classmethod
    def finding(cls, severity: str, title: str, detail: str = ""):
        colors = {
            "CRITICAL": RED + BOLD,
            "HIGH": RED,
            "MEDIUM": YELLOW,
            "LOW": BLUE,
            "INFO": CYAN,
        }
        color = colors.get(severity, WHITE)
        badge = f"[{severity}]"
        if _supports_color():
            print(f"  {color}{badge:<12}{RESET} {title}")
            if detail:
                print(f"  {DIM}{'':12} {detail}{RESET}")
        else:
            print(f"  {badge:<12} {title}")
            if detail:
                print(f"  {'':12} {detail}")

    @classmethod
    def port(cls, port: int, state: str, service: str, banner: str = ""):
        state_color = GREEN if state == "open" else DIM
        if _supports_color():
            print(f"  {state_color}{port:<8}{RESET}  {state:<8}  {service:<20}  {DIM}{banner[:50]}{RESET}")
        else:
            print(f"  {port:<8}  {state:<8}  {service:<20}  {banner[:50]}")

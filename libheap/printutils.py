from __future__ import print_function

import re
import sys

colors_enabled = True

# bash color support, taken from pwndbg
NORMAL         = "\x1b[0m"
BLACK          = "\x1b[30m"
RED            = "\x1b[31m"
GREEN          = "\x1b[32m"
YELLOW         = "\x1b[33m"
BLUE           = "\x1b[34m"
PURPLE         = "\x1b[35m"
CYAN           = "\x1b[36m"
LIGHT_GREY = LIGHT_GRAY = "\x1b[37m"
FOREGROUND     = "\x1b[39m"
GREY = GRAY    = "\x1b[90m"
LIGHT_RED      = "\x1b[91m"
LIGHT_GREEN    = "\x1b[92m"
LIGHT_YELLOW   = "\x1b[93m"
LIGHT_BLUE     = "\x1b[94m"
LIGHT_PURPLE   = "\x1b[95m"
LIGHT_CYAN     = "\x1b[96m"
WHITE          = "\x1b[97m"
BOLD           = "\x1b[1m"
UNDERLINE      = "\x1b[4m"

def none(x): return str(x)
def normal(x): return colorize(x, NORMAL)
def black(x): return colorize(x, BLACK)
def red(x): return colorize(x, RED)
def green(x): return colorize(x, GREEN)
def yellow(x): return colorize(x, YELLOW)
def blue(x): return colorize(x, BLUE)
def purple(x): return colorize(x, PURPLE)
def cyan(x): return colorize(x, CYAN)
def light_gray(x): return colorize(x, LIGHT_GRAY)
def foreground(x): return colorize(x, FOREGROUND)
def gray(x): return colorize(x, GRAY)
def light_red(x): return colorize(x, LIGHT_RED)
def light_green(x): return colorize(x, LIGHT_GREEN)
def light_yellow(x): return colorize(x, LIGHT_YELLOW)
def light_blue(x): return colorize(x, LIGHT_BLUE)
def light_purple(x): return colorize(x, LIGHT_PURPLE)
def light_cyan(x): return colorize(x, LIGHT_CYAN)
def white(x): return colorize(x, WHITE)
def bold(x): return colorize(x, BOLD)
def underline(x): return colorize(x, UNDERLINE)
def colorize(x, color): return color + terminateWith(str(x), color) + NORMAL

def terminateWith(x, color):
    return re.sub('\x1b\\[0m', NORMAL + color, x)

def print_error(s):
    error = "[!] {0}".format(s)

    if colors_enabled:
        color = RED
        error = colorize(error, color)

    print(error)

def print_title(s):
    width = 80
    lwidth = (width-len(s))/2
    rwidth = (width-len(s))/2
    title = '{:=<{lwidth}}{}{:=<{rwidth}}'.format('',s,'',lwidth=lwidth,rwidth=rwidth)
    print(color_title(title))

def print_header(s):
    if colors_enabled:
        color = YELLOW
        s = colorize(s, color)

    print(s, end="")

def print_value(s, end=""):
    print(color_value(s), end=end)

def color_title(s):
    if colors_enabled:
        color = GREEN
        return colorize(s, color)
    else:
        return s

def color_value(s):
    if colors_enabled:
        color = BLUE
        return colorize(s, color)
    else:
        return s

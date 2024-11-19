#include <stdio.h>
#include "privmx/endpoint/programs/privmxcli/colors/Colors.h"

#if defined(_WIN32) || defined(__APPLE__) || defined(__unix__) || defined(__unix)
#include <unistd.h>
#include <string.h>
#else
#error unsupported platform
#endif

static int is_terminal_c(FILE *out) {
#if defined(_MSC_VER)
    return _isatty(_fileno(out)) != 0;
#else
    return isatty(fileno(out)) != 0;
#endif
}

const char* get_clear_c() {
    return "\033[2J\033[;H";
}
void clear_c() {
    if(is_terminal_c(stdout)) {
        fprintf(stdout, "%s", get_clear_c());
    }
}

const char* get_reset_c() {
    return "\033[00m";
}
void reset_c() {
    if(is_terminal_c(stdout)) {
        fprintf(stdout, "%s", get_reset_c());
    }
}

const char* get_color_c(enum Color color) {
    switch(color) {
        case BLACK:
            return "\033[30m";
        case NAVY:
            return "\033[34m";
        case GREEN:
            return "\033[32m";
        case TEAL:
            return "\033[36m";
        case MAROON:
            return "\033[31m";
        case PURPLE:
            return "\033[35m";
        case OLIVE:
            return "\033[33m";
        case SILVER:
            return "\033[37m";
        case GREY:
            return "\033[90m";
        case BLUE:
            return "\033[94m";
        case LIME:
            return "\033[92m";
        case AQUA:
            return "\033[96m";
        case RED:
            return "\033[91m";
        case PINK:
            return "\033[95m";
        case YELLOW:
            return "\033[93m";
        case WHITE:
            return "\033[97m";
    }
}

void set_color_c(enum Color color) {
    if(is_terminal_c(stdout)) {
        fprintf(stdout, "%s", get_color_c(color));
    }
}

const char* get_bgcolor_c(enum Color color) {
    switch(color) {
        case BLACK:
            return "\033[40m";
        case NAVY:
            return "\033[44m";
        case GREEN:
            return "\033[42m";
        case TEAL:
            return "\033[46m";
        case MAROON:
            return "\033[41m";
        case PURPLE:
            return "\033[45m";
        case OLIVE:
            return "\033[43m";
        case SILVER:
            return "\033[47m";
        case GREY:
            return "\033[100m";
        case BLUE:
            return "\033[104m";
        case LIME:
            return "\033[102m";
        case AQUA:
            return "\033[106m";
        case RED:
            return "\033[101m";
        case PINK:
            return "\033[105m";
        case YELLOW:
            return "\033[103m";
        case WHITE:
            return "\033[107m";
    }
}

void set_bgcolor_c(enum Color color) {
    if(is_terminal_c(stdout)) {
        fprintf(stdout, "%s", get_color_c(color));
    }
}

void set_curpos_c(int x, int y) {
    if(is_terminal_c(stdout)) {
        fprintf(stdout, "\033[%d;%dH", y+1, x+1);
    }
}
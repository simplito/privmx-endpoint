#include <stdio.h>
#include "privmx/endpoint/programs/privmxcli/colors/Colors.h"

#if defined(_WIN32)
#include <io.h>
#include <windows.h>

static WORD win_default_attributes(HANDLE hConsole) {
	static WORD defaultAttributes = 0;
	CONSOLE_SCREEN_BUFFER_INFO info;

    if (!defaultAttributes && GetConsoleScreenBufferInfo(hConsole, &info)) {
		defaultAttributes = info.wAttributes;
	}

	return defaultAttributes;
}

static void win_set_attributes(int fg, int bg) {
    WORD defaultAttributes;
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    defaultAttributes = win_default_attributes(hConsole);

    if (fg == -1 && bg == -1) {
        SetConsoleTextAttribute(hConsole, defaultAttributes);
        return;
    }

    if (!GetConsoleScreenBufferInfo(hConsole, &info)) {
        return;
    }

    if (fg != -1) {
        info.wAttributes &= ~(info.wAttributes & 0x0F);
        info.wAttributes |= (WORD)fg;
    }

    if (bg != -1) {
        info.wAttributes &= ~(info.wAttributes & 0xF0);
        info.wAttributes |= (WORD)bg;
    }

    SetConsoleTextAttribute(hConsole, info.wAttributes);
}

static void win_set_cursor_position(int x, int y) {
	COORD pos;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	
	pos.X = x;
	pos.Y = y;
	SetConsoleCursorPosition(hConsole, pos);
}

static void win_clear_console() {
    WORD defaultAttributes;
	COORD topLeft = { 0, 0 };
    DWORD written;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;

    defaultAttributes = win_default_attributes(hConsole);

    if (!GetConsoleScreenBufferInfo(hConsole, &info)) {
        return;
    }

    FillConsoleOutputCharacterA(hConsole, ' ', info.dwSize.X * info.dwSize.Y, topLeft, &written);
    FillConsoleOutputAttribute(hConsole, info.wAttributes, info.dwSize.X * info.dwSize.Y, topLeft, &written);
    win_set_cursor_position(topLeft.X, topLeft.Y);
}

#elif defined(__APPLE__) || defined(__unix__) || defined(__unix)
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

void clear_c() {
    if(is_terminal_c(stdout)) {
#if defined(_WIN32)
        win_clear_console();
#else
        fprintf(stdout, "\033[2J\033[;H");
#endif
    }
}

void reset_c() {
    if(is_terminal_c(stdout)) {
#if defined(_WIN32)
        win_set_attributes(-1, -1);
#else
        fprintf(stdout, "\033[00m");
#endif
    }
}

void setcolor_c(enum Color color) {
    if(is_terminal_c(stdout)) {
        switch(color) {
        case BLACK:
#if defined(_WIN32)
            win_set_attributes(0, -1);
#else
            fprintf(stdout, "%s", "\033[30m");
#endif
            break;
        case NAVY:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_BLUE, -1);
#else
            fprintf(stdout, "%s", "\033[34m");
#endif
            break;
        case GREEN:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_GREEN, -1);
#else
            fprintf(stdout, "%s", "\033[32m");
#endif
            break;
        case TEAL:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_BLUE | FOREGROUND_GREEN, -1);
#else
            fprintf(stdout, "%s", "\033[36m");
#endif
            break;
        case MAROON:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_RED, -1);
#else
            fprintf(stdout, "%s", "\033[31m");
#endif
            break;
        case PURPLE:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_BLUE | FOREGROUND_RED, -1);
#else
            fprintf(stdout, "%s", "\033[35m");
#endif
            break;
        case OLIVE:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_GREEN | FOREGROUND_RED, -1);
#else
            fprintf(stdout, "%s", "\033[33m");
#endif
            break;
        case SILVER:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE, -1);
#else
            fprintf(stdout, "%s", "\033[37m");
#endif
            break;
        case GREY:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_INTENSITY, -1);
#else
            fprintf(stdout, "%s", "\033[90m");
#endif
            break;
        case BLUE:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_BLUE | FOREGROUND_INTENSITY, -1);
#else
            fprintf(stdout, "%s", "\033[94m");
#endif
            break;
        case LIME:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_GREEN | FOREGROUND_INTENSITY, -1);
#else
            fprintf(stdout, "%s", "\033[92m");
#endif
            break;
        case AQUA:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY, -1);
#else
            fprintf(stdout, "%s", "\033[96m");
#endif
            break;
        case RED:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_RED | FOREGROUND_INTENSITY, -1);
#else
            fprintf(stdout, "%s", "\033[91m");
#endif
            break;
        case PINK:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY, -1);
#else
            fprintf(stdout, "%s", "\033[95m");
#endif
            break;
        case YELLOW:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY, -1);
#else
            fprintf(stdout, "%s", "\033[93m");
#endif
            break;
        case WHITE:
#if defined(_WIN32)
            win_set_attributes(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY, -1);
#else
            fprintf(stdout, "%s", "\033[97m");
#endif
            break;
        }
    }
}

void setbgcolor_c(enum Color color) {
    if(is_terminal_c(stdout)) {
        switch(color) {
        case BLACK:
#if defined(_WIN32)
            win_set_attributes(-1, 0);
#else
            fprintf(stdout, "%s", "\033[40m");
#endif
            break;
        case NAVY:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_BLUE);
#else
            fprintf(stdout, "%s", "\033[44m");
#endif
            break;
        case GREEN:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_GREEN);
#else
            fprintf(stdout, "%s", "\033[42m");
#endif
            break;
        case TEAL:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_BLUE | BACKGROUND_GREEN);
#else
            fprintf(stdout, "%s", "\033[46m");
#endif
            break;
        case MAROON:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_RED);
#else
            fprintf(stdout, "%s", "\033[41m");
#endif
            break;
        case PURPLE:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_BLUE | BACKGROUND_RED);
#else
            fprintf(stdout, "%s", "\033[45m");
#endif
            break;
        case OLIVE:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_GREEN | BACKGROUND_RED);
#else
            fprintf(stdout, "%s", "\033[43m");
#endif
            break;
        case SILVER:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE);
#else
            fprintf(stdout, "%s", "\033[47m");
#endif
            break;
        case GREY:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_INTENSITY);
#else
            fprintf(stdout, "%s", "\033[100m");
#endif
            break;
        case BLUE:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_BLUE | BACKGROUND_INTENSITY);
#else
            fprintf(stdout, "%s", "\033[104m");
#endif
            break;
        case LIME:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_GREEN | BACKGROUND_INTENSITY);
#else
            fprintf(stdout, "%s", "\033[102m");
#endif
            break;
        case AQUA:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_INTENSITY);
#else
            fprintf(stdout, "%s", "\033[106m");
#endif
            break;
        case RED:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_RED | BACKGROUND_INTENSITY);
#else
            fprintf(stdout, "%s", "\033[101m");
#endif
            break;
        case PINK:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_BLUE | BACKGROUND_RED | BACKGROUND_INTENSITY);
#else
            fprintf(stdout, "%s", "\033[105m");
#endif
            break;
        case YELLOW:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY);
#else
            fprintf(stdout, "%s", "\033[103m");
#endif
            break;
        case WHITE:
#if defined(_WIN32)
            win_set_attributes(-1, BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY);
#else
            fprintf(stdout, "%s", "\033[107m");
#endif
            break;
        }
    }
}

void setcurpos_c(int x, int y) {
    if(is_terminal_c(stdout)) {
#if defined(_WIN32)
        win_set_cursor_position(x, y);
#else
        fprintf(stdout, "\033[%d;%dH", y+1, x+1);
#endif
    }
}
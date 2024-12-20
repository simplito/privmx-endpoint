#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_COLORS_H
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_COLORS_H

#ifdef __cplusplus
extern "C" {
#endif

enum Color {
    BLACK,
    NAVY,
    GREEN,
    TEAL,
    MAROON,
    PURPLE,
    OLIVE,
    SILVER,
    GREY,
    BLUE,
    LIME,
    AQUA,
    RED,
    PINK,
    YELLOW,
    WHITE
};

/* clear console content */
const char* get_clear_c();
void clear_c();
/* reset foreground and background color */
const char* get_reset_c();
void reset_c();
/* set foreground color */
const char* get_color_c(enum Color color);
void set_color_c(enum Color color);
/* set background color */
const char* get_bgcolor_c(enum Color color);
void set_bgcolor_c(enum Color color);
/* set cursor position */
void set_curpos_c(int x, int y);

#ifdef __cplusplus
}
#endif

#endif /* _PRIVMXLIB_ENDPOINT_PRIVMXCLI_COLORS_H */
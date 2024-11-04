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
void clear_c();
/* reset foreground and background color */
void reset_c();
/* set foreground color */
void setcolor_c(enum Color color);
/* set background color */
void setbgcolor_c(enum Color color);
/* set cursor position */
void setcurpos_c(int x, int y);

#ifdef __cplusplus
}
#endif

#endif /* _PRIVMXLIB_ENDPOINT_PRIVMXCLI_COLORS_H */
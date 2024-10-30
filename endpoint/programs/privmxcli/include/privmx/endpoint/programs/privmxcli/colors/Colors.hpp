#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_COLORS_HPP
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_COLORS_HPP


#include "privmx/endpoint/programs/privmxcli/colors/Colors.h"
#include <iostream>

namespace privmx {
namespace endpoint {
namespace privmxcli {
namespace colors {



class ConsoleColor {
public:
    static std::ostream& clear(std::ostream& stream);
    static std::ostream& reset(std::ostream& stream);
    static std::ostream& black(std::ostream& stream);
    static std::ostream& navy(std::ostream& stream);
    static std::ostream& green(std::ostream& stream);
    static std::ostream& teal(std::ostream& stream);
    static std::ostream& maroon(std::ostream& stream);
    static std::ostream& purple(std::ostream& stream);
    static std::ostream& olive(std::ostream& stream);
    static std::ostream& silver(std::ostream& stream);
    static std::ostream& grey(std::ostream& stream);
    static std::ostream& blue(std::ostream& stream);
    static std::ostream& lime(std::ostream& stream);
    static std::ostream& aqua(std::ostream& stream);
    static std::ostream& red(std::ostream& stream);
    static std::ostream& pink(std::ostream& stream);
    static std::ostream& yellow(std::ostream& stream);
    static std::ostream& white(std::ostream& stream);
    static std::ostream& on_black(std::ostream& stream);
    static std::ostream& on_navy(std::ostream& stream);
    static std::ostream& on_green(std::ostream& stream);
    static std::ostream& on_teal(std::ostream& stream);
    static std::ostream& on_maroon(std::ostream& stream);
    static std::ostream& on_purple(std::ostream& stream);
    static std::ostream& on_olive(std::ostream& stream);
    static std::ostream& on_silver(std::ostream& stream);
    static std::ostream& on_grey(std::ostream& stream);
    static std::ostream& on_blue(std::ostream& stream);
    static std::ostream& on_lime(std::ostream& stream);
    static std::ostream& on_aqua(std::ostream& stream);
    static std::ostream& on_red(std::ostream& stream);
    static std::ostream& on_pink(std::ostream& stream);
    static std::ostream& on_yellow(std::ostream& stream);
    static std::ostream& on_white(std::ostream& stream);

    // wide char streams

    static std::wostream& clear(std::wostream& stream);
    static std::wostream& reset(std::wostream& stream);
    static std::wostream& black(std::wostream& stream);
    static std::wostream& navy(std::wostream& stream);
    static std::wostream& green(std::wostream& stream);
    static std::wostream& teal(std::wostream& stream);
    static std::wostream& maroon(std::wostream& stream);
    static std::wostream& purple(std::wostream& stream);
    static std::wostream& olive(std::wostream& stream);
    static std::wostream& silver(std::wostream& stream);
    static std::wostream& grey(std::wostream& stream);
    static std::wostream& blue(std::wostream& stream);
    static std::wostream& lime(std::wostream& stream);
    static std::wostream& aqua(std::wostream& stream);
    static std::wostream& red(std::wostream& stream);
    static std::wostream& pink(std::wostream& stream);
    static std::wostream& yellow(std::wostream& stream);
    static std::wostream& white(std::wostream& stream);
    static std::wostream& on_black(std::wostream& stream);
    static std::wostream& on_navy(std::wostream& stream);
    static std::wostream& on_green(std::wostream& stream);
    static std::wostream& on_teal(std::wostream& stream);
    static std::wostream& on_maroon(std::wostream& stream);
    static std::wostream& on_purple(std::wostream& stream);
    static std::wostream& on_olive(std::wostream& stream);
    static std::wostream& on_silver(std::wostream& stream);
    static std::wostream& on_grey(std::wostream& stream);
    static std::wostream& on_blue(std::wostream& stream);
    static std::wostream& on_lime(std::wostream& stream);
    static std::wostream& on_aqua(std::wostream& stream);
    static std::wostream& on_red(std::wostream& stream);
    static std::wostream& on_pink(std::wostream& stream);
    static std::wostream& on_yellow(std::wostream& stream);
    static std::wostream& on_white(std::wostream& stream);
};

} // colors

class ConsoleStatusColor {
public:
    static std::ostream& normal(std::ostream& stream);
    static std::ostream& info(std::ostream& stream);
    static std::ostream& ok(std::ostream& stream);
    static std::ostream& help(std::ostream& stream);
    
    static std::ostream& warning(std::ostream& stream);
    static std::ostream& error(std::ostream& stream);
    static std::ostream& error_critical(std::ostream& stream);
};

} // privmxcli
} // endpoint
} // privmx


#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_COLORS_HPP
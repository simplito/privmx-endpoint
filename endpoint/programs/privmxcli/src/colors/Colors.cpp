#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"

using namespace privmx::endpoint::privmxcli::colors;

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::clear(std::ostream& stream) {
    stream.flush();
    clear_c();
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::reset(std::ostream& stream) {
    stream.flush();
    reset_c();
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::black(std::ostream& stream) {
    stream.flush();
    setcolor_c(BLACK);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::navy(std::ostream& stream) {
    stream.flush();
    setcolor_c(NAVY);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::green(std::ostream& stream) {
    stream.flush();
    setcolor_c(GREEN);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::teal(std::ostream& stream) {
    stream.flush();
    setcolor_c(TEAL);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::maroon(std::ostream& stream) {
    stream.flush();
    setcolor_c(MAROON);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::purple(std::ostream& stream) {
    stream.flush();
    setcolor_c(PURPLE);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::olive(std::ostream& stream) {
    stream.flush();
    setcolor_c(OLIVE);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::silver(std::ostream& stream) {
    stream.flush();
    setcolor_c(SILVER);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::grey(std::ostream& stream) {
    stream.flush();
    setcolor_c(GREY);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::blue(std::ostream& stream) {
    stream.flush();
    setcolor_c(BLUE);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::lime(std::ostream& stream) {
    stream.flush();
    setcolor_c(LIME);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::aqua(std::ostream& stream) {
    stream.flush();
    setcolor_c(AQUA);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::red(std::ostream& stream) {
    stream.flush();
    setcolor_c(RED);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::pink(std::ostream& stream) {
    stream.flush();
    setcolor_c(PINK);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::yellow(std::ostream& stream) {
    stream.flush();
    setcolor_c(YELLOW);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::white(std::ostream& stream) {
    stream.flush();
    setcolor_c(WHITE);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_black(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(BLACK);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_navy(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(NAVY);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_green(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(GREEN);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_teal(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(TEAL);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_maroon(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(MAROON);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_purple(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(PURPLE);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_olive(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(OLIVE);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_silver(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(SILVER);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_grey(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(GREY);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_blue(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(BLUE);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_lime(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(LIME);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_aqua(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(AQUA);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_red(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(RED);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_pink(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(PINK);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_yellow(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(YELLOW);
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_white(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(WHITE);
    return stream;
}

// wide char streams

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::clear(std::wostream& stream) {
    stream.flush();
    clear_c();
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::reset(std::wostream& stream) {
    stream.flush();
    reset_c();
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::black(std::wostream& stream) {
    stream.flush();
    setcolor_c(BLACK);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::navy(std::wostream& stream) {
    stream.flush();
    setcolor_c(NAVY);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::green(std::wostream& stream) {
    stream.flush();
    setcolor_c(GREEN);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::teal(std::wostream& stream) {
    stream.flush();
    setcolor_c(TEAL);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::maroon(std::wostream& stream) {
    stream.flush();
    setcolor_c(MAROON);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::purple(std::wostream& stream) {
    stream.flush();
    setcolor_c(PURPLE);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::olive(std::wostream& stream) {
    stream.flush();
    setcolor_c(OLIVE);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::silver(std::wostream& stream) {
    stream.flush();
    setcolor_c(SILVER);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::grey(std::wostream& stream) {
    stream.flush();
    setcolor_c(GREY);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::blue(std::wostream& stream) {
    stream.flush();
    setcolor_c(BLUE);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::lime(std::wostream& stream) {
    stream.flush();
    setcolor_c(LIME);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::aqua(std::wostream& stream) {
    stream.flush();
    setcolor_c(AQUA);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::red(std::wostream& stream) {
    stream.flush();
    setcolor_c(RED);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::pink(std::wostream& stream) {
    stream.flush();
    setcolor_c(PINK);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::yellow(std::wostream& stream) {
    stream.flush();
    setcolor_c(YELLOW);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::white(std::wostream& stream) {
    stream.flush();
    setcolor_c(WHITE);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_black(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(BLACK);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_navy(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(NAVY);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_green(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(GREEN);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_teal(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(TEAL);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_maroon(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(MAROON);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_purple(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(PURPLE);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_olive(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(OLIVE);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_silver(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(SILVER);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_grey(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(GREY);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_blue(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(BLUE);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_lime(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(LIME);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_aqua(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(AQUA);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_red(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(RED);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_pink(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(PINK);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_yellow(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(YELLOW);
    return stream;
}

std::wostream& privmx::endpoint::privmxcli::colors::ConsoleColor::on_white(std::wostream& stream) {
    stream.flush();
    setbgcolor_c(WHITE);
    return stream;
}


std::ostream& privmx::endpoint::privmxcli::ConsoleStatusColor::normal(std::ostream& stream) {
    stream.flush();
    reset_c();
    return stream;
}
std::ostream& privmx::endpoint::privmxcli::ConsoleStatusColor::info(std::ostream& stream) {
    stream.flush();
    setcolor_c(OLIVE);
    return stream;
}
std::ostream& privmx::endpoint::privmxcli::ConsoleStatusColor::ok(std::ostream& stream) {
    stream.flush();
    setcolor_c(GREEN);
    return stream;
}
std::ostream& privmx::endpoint::privmxcli::ConsoleStatusColor::help(std::ostream& stream) {
    stream.flush();
    setcolor_c(AQUA);
    return stream;
}
std::ostream& privmx::endpoint::privmxcli::ConsoleStatusColor::warning(std::ostream& stream) {
    stream.flush();
    setcolor_c(PURPLE);
    return stream;
}
std::ostream& privmx::endpoint::privmxcli::ConsoleStatusColor::error(std::ostream& stream) {
    stream.flush();
    setcolor_c(RED);
    return stream;
}
std::ostream& privmx::endpoint::privmxcli::ConsoleStatusColor::error_critical(std::ostream& stream) {
    stream.flush();
    setbgcolor_c(RED);
    setcolor_c(PURPLE);
    return stream;
}

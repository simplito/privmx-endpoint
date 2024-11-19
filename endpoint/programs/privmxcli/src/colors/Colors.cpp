/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"

using namespace privmx::endpoint::privmxcli;

std::ostream& colors::ConsoleColor::clear(std::ostream& stream) {
    stream.flush();
    stream << get_clear_c();
    return stream;
}

std::ostream& colors::ConsoleColor::reset(std::ostream& stream) {
    stream.flush();
    stream << get_reset_c();
    return stream;
}

std::ostream& colors::ConsoleColor::black(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(BLACK);
    return stream;
}

std::ostream& colors::ConsoleColor::navy(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(NAVY);
    return stream;
}

std::ostream& colors::ConsoleColor::green(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(GREEN);
    return stream;
}

std::ostream& colors::ConsoleColor::teal(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(TEAL);
    return stream;
}

std::ostream& colors::ConsoleColor::maroon(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(MAROON);
    return stream;
}

std::ostream& colors::ConsoleColor::purple(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(PURPLE);
    return stream;
}

std::ostream& colors::ConsoleColor::olive(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(OLIVE);
    return stream;
}

std::ostream& colors::ConsoleColor::silver(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(SILVER);
    return stream;
}

std::ostream& colors::ConsoleColor::grey(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(GREY);
    return stream;
}

std::ostream& colors::ConsoleColor::blue(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(BLUE);
    return stream;
}

std::ostream& colors::ConsoleColor::lime(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(LIME);
    return stream;
}

std::ostream& colors::ConsoleColor::aqua(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(AQUA);
    return stream;
}

std::ostream& colors::ConsoleColor::red(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(RED);
    return stream;
}

std::ostream& colors::ConsoleColor::pink(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(PINK);
    return stream;
}

std::ostream& colors::ConsoleColor::yellow(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(YELLOW);
    return stream;
}

std::ostream& colors::ConsoleColor::white(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(WHITE);
    return stream;
}

std::ostream& colors::ConsoleColor::on_black(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(BLACK);
    return stream;
}

std::ostream& colors::ConsoleColor::on_navy(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(NAVY);
    return stream;
}

std::ostream& colors::ConsoleColor::on_green(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(GREEN);
    return stream;
}

std::ostream& colors::ConsoleColor::on_teal(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(TEAL);
    return stream;
}

std::ostream& colors::ConsoleColor::on_maroon(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(MAROON);
    return stream;
}

std::ostream& colors::ConsoleColor::on_purple(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(PURPLE);
    return stream;
}

std::ostream& colors::ConsoleColor::on_olive(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(OLIVE);
    return stream;
}

std::ostream& colors::ConsoleColor::on_silver(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(SILVER);
    return stream;
}

std::ostream& colors::ConsoleColor::on_grey(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(GREY);
    return stream;
}

std::ostream& colors::ConsoleColor::on_blue(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(BLUE);
    return stream;
}

std::ostream& colors::ConsoleColor::on_lime(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(LIME);
    return stream;
}

std::ostream& colors::ConsoleColor::on_aqua(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(AQUA);
    return stream;
}

std::ostream& colors::ConsoleColor::on_red(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(RED);
    return stream;
}

std::ostream& colors::ConsoleColor::on_pink(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(PINK);
    return stream;
}

std::ostream& colors::ConsoleColor::on_yellow(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(YELLOW);
    return stream;
}

std::ostream& colors::ConsoleColor::on_white(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(WHITE);
    return stream;
}

// wide char streams

std::wostream& colors::ConsoleColor::clear(std::wostream& stream) {
    stream.flush();
    stream << get_clear_c();
    return stream;
}

std::wostream& colors::ConsoleColor::reset(std::wostream& stream) {
    stream.flush();
    stream << get_reset_c();
    return stream;
}

std::wostream& colors::ConsoleColor::black(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(BLACK);
    return stream;
}

std::wostream& colors::ConsoleColor::navy(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(NAVY);
    return stream;
}

std::wostream& colors::ConsoleColor::green(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(GREEN);
    return stream;
}

std::wostream& colors::ConsoleColor::teal(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(TEAL);
    return stream;
}

std::wostream& colors::ConsoleColor::maroon(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(MAROON);
    return stream;
}

std::wostream& colors::ConsoleColor::purple(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(PURPLE);
    return stream;
}

std::wostream& colors::ConsoleColor::olive(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(OLIVE);
    return stream;
}

std::wostream& colors::ConsoleColor::silver(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(SILVER);
    return stream;
}

std::wostream& colors::ConsoleColor::grey(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(GREY);
    return stream;
}

std::wostream& colors::ConsoleColor::blue(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(BLUE);
    return stream;
}

std::wostream& colors::ConsoleColor::lime(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(LIME);
    return stream;
}

std::wostream& colors::ConsoleColor::aqua(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(AQUA);
    return stream;
}

std::wostream& colors::ConsoleColor::red(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(RED);
    return stream;
}

std::wostream& colors::ConsoleColor::pink(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(PINK);
    return stream;
}

std::wostream& colors::ConsoleColor::yellow(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(YELLOW);
    return stream;
}

std::wostream& colors::ConsoleColor::white(std::wostream& stream) {
    stream.flush();
    stream << get_color_c(WHITE);
    return stream;
}

std::wostream& colors::ConsoleColor::on_black(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(BLACK);
    return stream;
}

std::wostream& colors::ConsoleColor::on_navy(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(NAVY);
    return stream;
}

std::wostream& colors::ConsoleColor::on_green(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(GREEN);
    return stream;
}

std::wostream& colors::ConsoleColor::on_teal(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(TEAL);
    return stream;
}

std::wostream& colors::ConsoleColor::on_maroon(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(MAROON);
    return stream;
}

std::wostream& colors::ConsoleColor::on_purple(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(PURPLE);
    return stream;
}

std::wostream& colors::ConsoleColor::on_olive(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(OLIVE);
    return stream;
}

std::wostream& colors::ConsoleColor::on_silver(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(SILVER);
    return stream;
}

std::wostream& colors::ConsoleColor::on_grey(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(GREY);
    return stream;
}

std::wostream& colors::ConsoleColor::on_blue(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(BLUE);
    return stream;
}

std::wostream& colors::ConsoleColor::on_lime(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(LIME);
    return stream;
}

std::wostream& colors::ConsoleColor::on_aqua(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(AQUA);
    return stream;
}

std::wostream& colors::ConsoleColor::on_red(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(RED);
    return stream;
}

std::wostream& colors::ConsoleColor::on_pink(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(PINK);
    return stream;
}

std::wostream& colors::ConsoleColor::on_yellow(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(YELLOW);
    return stream;
}

std::wostream& colors::ConsoleColor::on_white(std::wostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(WHITE);
    return stream;
}


std::ostream& ConsoleStatusColor::normal(std::ostream& stream) {
    stream.flush();
    stream << get_reset_c();
    return stream;
}
std::ostream& ConsoleStatusColor::info(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(OLIVE);
    return stream;
}
std::ostream& ConsoleStatusColor::ok(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(GREEN);
    return stream;
}
std::ostream& ConsoleStatusColor::help(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(AQUA);
    return stream;
}
std::ostream& ConsoleStatusColor::warning(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(PURPLE);
    return stream;
}
std::ostream& ConsoleStatusColor::error(std::ostream& stream) {
    stream.flush();
    stream << get_color_c(RED);
    return stream;
}
std::ostream& ConsoleStatusColor::error_critical(std::ostream& stream) {
    stream.flush();
    stream << get_bgcolor_c(RED);
    stream << get_color_c(PURPLE);
    return stream;
}

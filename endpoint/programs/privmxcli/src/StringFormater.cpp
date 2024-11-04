/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/programs/privmxcli/StringFormater.hpp"

std::ostream& privmx::endpoint::privmxcli::StringFormater::toCPP(std::ostream& stream, const std::string &s) {
    stream.flush();
    stream << "\"";
    for (auto c : s) {
        switch (c) {
            // case '\'':
            //     stream << "\\'";
            //     break;
            case '\"':
                stream << "\\\"";
                break;
            case '\\':
                stream << "\\\\";
                break;
            case '\?':
                stream << "\\?";
                break;
            case '\a':
                stream << "\\a";
                break;
            case '\b':
                stream << "\\b";
                break;
            case '\f':
                stream << "\\f";
                break;
            case '\n':
                stream << "\\n";
                break;
            case '\r':
                stream << "\\r";
                break;
            case '\t':
                stream << "\\t";
                break;
            case '\v':
                stream << "\\v";
                break;
            default:
                stream << c;
        }
    }
    stream << "\"";
    return stream;
}

std::ostream& privmx::endpoint::privmxcli::StringFormater::toPython(std::ostream& stream, const std::string &s) {
    stream.flush();
    stream << "\'";
    for (auto c : s) {
        switch (c) {
            case '\'':
                stream << "\\'";
                break;
            // case '\"':
            //     stream << "\\\"";
            //     break;
            case '\\':
                stream << "\\\\";
                break;
            case '\?':
                stream << "\\?";
                break;
            case '\a':
                stream << "\\a";
                break;
            case '\b':
                stream << "\\b";
                break;
            case '\f':
                stream << "\\f";
                break;
            case '\n':
                stream << "\\n";
                break;
            case '\r':
                stream << "\\r";
                break;
            case '\t':
                stream << "\\t";
                break;
            case '\v':
                stream << "\\v";
                break;
            default:
                stream << c;
        }
    }
    stream << "\'";
    return stream;
}
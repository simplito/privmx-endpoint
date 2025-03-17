/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <algorithm>
#include <cctype>
#include <string>
#include <sstream>
#include <regex>
#include <Poco/Base32Encoder.h>
#include <Poco/Base32Decoder.h>
#include <Poco/Base64Encoder.h>
#include <Poco/Base64Decoder.h>
#include <Poco/Dynamic/Var.h>
#include <Poco/HexBinaryDecoder.h>
#include <Poco/HexBinaryEncoder.h>
#include <Poco/JSON/Parser.h>
#include <Poco/StreamCopier.h>
#include <Poco/Timestamp.h>

#include <privmx/utils/Utils.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/PrivmxExtExceptions.hpp>

using namespace privmx;
using namespace utils;
using namespace std;
using namespace Poco;
using namespace Poco::JSON;
using Poco::Dynamic::Var;

template<typename Decoder>
inline string decodeInline(const string& encoded_data) {
    istringstream encoded_data_stream(encoded_data);
    ostringstream decoded_data_stream;
    Decoder decoder(encoded_data_stream);
    Poco::StreamCopier::copyStreamUnbuffered(decoder, decoded_data_stream);
    return decoded_data_stream.str();
}

template<typename Encoder>
inline string encodeInline(const string& data_to_encode, int line_length = 0) {
    ostringstream encoded_data_stream;
    Encoder encoder(encoded_data_stream);
    encoder.rdbuf()->setLineLength(line_length);
    encoder.write(data_to_encode.data(), data_to_encode.length());
    encoder.close();
    return encoded_data_stream.str();
}

string Hex::from(const string& data) {
    return encodeInline<HexBinaryEncoder>(data);
}

string Hex::toString(const string& hex_data) {
    if (hex_data.size() & 1) {
        return decodeInline<HexBinaryDecoder>(string("0").append(hex_data));
    }
    return decodeInline<HexBinaryDecoder>(hex_data);
}

bool Hex::is(const string& data) {
    std::regex hexRegex("^[0-9a-fA-F]+$");
    return std::regex_match(data, hexRegex);
}

string Base32::decode(const string& base32_data) {
    return decodeInline<Base32Decoder>(base32_data);
}

string Base32::encode(const string& data) {
    ostringstream encoded_data_stream;
    Base32Encoder encoder(encoded_data_stream);
    encoder.write(data.data(), data.length());
    encoder.close();
    return encoded_data_stream.str();
}

bool Base32::is(const string& data) {
    std::regex base32Regex("^(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?$");
    return std::regex_match(data, base32Regex);
}

string Base64::from(const string& data, int line_length) {
    return encodeInline<Base64Encoder>(data, line_length);
}

string Base64::toString(const string& base64_data) {
    return decodeInline<Base64Decoder>(base64_data);
}

bool Base64::is(const string& data) {
    std::regex base64Regex("^(?=(.{4})*$)[A-Za-z0-9+/]*={0,2}$");
    return std::regex_match(data, base64Regex);
}

Int64 TimestampServiceImpl::getNowTimestamp() {
    return Poco::Timestamp().raw()/1000;
}

TimestampService::Ptr Utils::timestamp_service = new TimestampServiceImpl();

string Utils::fillTo32(const string& data) {
    if(data.length() >= 32) {
        return data;
    }
    return string(32 - data.length(), 0) + data;
}

string Utils::removeEscape(const string& data) {
    string result = data;
    for (string::iterator it = result.begin(); it != result.end(); ++it) {
        if (*it == '\\' && *(it+1) == '/') {
            it = result.erase(it);
        }
    }
    return result;
}

string Utils::formatToBase32(const string& data) {
    string r = data;
    r.erase(remove_if(r.begin(), r.end(), ::isspace), r.end());
    for_each(r.begin(), r.end(), [&](char &c){ c = toupper(c); });
    return r;
}

Int64 Utils::getNowTimestamp() {
    return timestamp_service->getNowTimestamp();
}

string Utils::getNowTimestampStr() {
    return to_string(getNowTimestamp());
}

string Utils::stringifyVar(const Poco::Dynamic::Var& var, bool pretty) {
    if (var.type() == typeid(Poco::JSON::Object::Ptr)) {
        return stringify(var.extract<Poco::JSON::Object::Ptr>(), pretty);
    } else if (var.type() == typeid(Poco::JSON::Array::Ptr)) {
        return stringify(var.extract<Poco::JSON::Array::Ptr>(), pretty);
    }
    try {
        return var.toString();
    } catch (...) {
        throw CannotStringifyVar();
    }
}

string Utils::stringify(const Array::Ptr& arr, bool pretty) {
    ostringstream stream;
    arr->stringify(stream, pretty ? 4 : 0);
    return Utils::removeEscape(stream.str());
}

string Utils::stringify(const Object::Ptr& obj, bool pretty) {
    ostringstream stream;
    obj->stringify(stream, pretty ? 4 : 0);
    return Utils::removeEscape(stream.str());
}

Poco::Dynamic::Var Utils::parseJson(const string& json) {
    Parser parser;
    return parser.parse(json);
}

Object::Ptr Utils::parseJsonObject(const string& json) {
    Parser parser;
    return parser.parse(json).extract<Object::Ptr>();
}

Array::Ptr Utils::jsonArrayDeepCopy(const Array::Ptr& arr) {
    Array::Ptr result = new Array();
    for (auto& item : *arr) {
        Var value;
        if (item.type() == typeid(Object::Ptr)) {
            value = jsonObjectDeepCopy(item.extract<Object::Ptr>());
        } else if (item.type() == typeid(Array::Ptr)) {
            value = jsonArrayDeepCopy(item.extract<Array::Ptr>());
        } else {
            value = item;
        }
        result->add(value);
    }
    return result;
}

Object::Ptr Utils::jsonObjectDeepCopy(const Object::Ptr& obj) {
    if (!obj) return Object::Ptr();
    Object::Ptr result = new Object();
    for (auto& item : *obj) {
        Var value;
        if (item.second.type() == typeid(Object::Ptr)) {
            value = jsonObjectDeepCopy(item.second.extract<Object::Ptr>());
        } else if (item.second.type() == typeid(Array::Ptr)) {
            value = jsonArrayDeepCopy(item.second.extract<Array::Ptr>());
        } else {
            value = item.second;
        }
        result->set(item.first, value);
    }
    return result;
}

string Utils::jsonArrayJoin(const Array::Ptr& arr) {
    string result;
    for (auto& item : *arr) {
        result += item.extract<string>();
    }
    return result;
}

std::string Utils::trim(const std::string& data) {
    return Poco::trim(data);
}

std::vector<std::string> Utils::parseIniFileLine(const std::string& str, char character) {
    auto result = std::vector<std::string>{};
    auto ss = std::stringstream{str};
    std::string _namespace {""};

    for (std::string line; std::getline(ss, line, character);) {
        auto trimmed {trim(line)};
        if (trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }
        if (trimmed[0] == '[' && trimmed[trimmed.size() -1 ] == ']') {
            _namespace = trimmed.substr(1, trimmed.size() - 2) + ".";
        }
        result.push_back(_namespace + trim(line));
    }

    return result;
}

void Utils::ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

void Utils::rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

std::vector<std::string> Utils::split(std::string data, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t pos = 0;
    std::string token;
    while ((pos = data.find(delimiter)) != std::string::npos) {
        token = data.substr(0, pos);
        tokens.push_back(token);
        data.erase(0, pos + delimiter.length());
    }
    tokens.push_back(data);

    return tokens;
}
/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Utils.hpp"
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint::core;

Buffer Hex::encode(const Buffer& data) {
    return core::Buffer::from(privmx::utils::Hex::from(data.stdString()));
}
Buffer Hex::decode(const Buffer& hex_data) {
    return core::Buffer::from(privmx::utils::Hex::toString(hex_data.stdString()));
}
bool Hex::is(const Buffer& data) {
    return privmx::utils::Hex::is(data.stdString());
}

Buffer Base32::encode(const Buffer& data) {
    return core::Buffer::from(privmx::utils::Base32::encode(data.stdString()));
}
Buffer Base32::decode(const Buffer& base32_data) {
    return core::Buffer::from(privmx::utils::Base32::decode(base32_data.stdString()));
}
bool Base32::is(const Buffer& data) {
    return privmx::utils::Base32::is(data.stdString());
}

Buffer Base64::encode(const Buffer& data) {
    return core::Buffer::from(privmx::utils::Base64::from(data.stdString()));
}
Buffer Base64::decode(const Buffer& base64_data) {
    return core::Buffer::from(privmx::utils::Base64::toString(base64_data.stdString()));
}
bool Base64::is(const Buffer& data) {
    return privmx::utils::Base64::is(data.stdString());
}

std::string Utils::fillTo32(const std::string& data) {
    return privmx::utils::Utils::fillTo32(data);
}
std::string Utils::removeEscape(const std::string& data) {
    return privmx::utils::Utils::removeEscape(data);
}
std::string Utils::formatToBase32(const std::string& data) {
    return privmx::utils::Utils::formatToBase32(data);
}
std::string Utils::trim(const std::string& data) {
    return privmx::utils::Utils::trim(data);
}
std::vector<std::string> Utils::split(std::string data, const std::string& delimiter) {
    return privmx::utils::Utils::split(data, delimiter);
}
std::vector<std::string> Utils::splitStringByCharacter(const std::string& data, char character) {
    return privmx::utils::Utils::splitStringByCharacter(data, character);
}
void Utils::ltrim(std::string& data) {
    return privmx::utils::Utils::ltrim(data);
}
void Utils::rtrim(std::string& data) {
    return privmx::utils::Utils::rtrim(data);
}
/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILE_KEYID_FORMAT_VALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILE_KEYID_FORMAT_VALIDATOR_HPP_

#include <privmx/endpoint/core/KeyIdFormatValidator.hpp>
#include <string>


namespace privmx {
namespace endpoint {
namespace store {

class FileKeyIdFormatValidator : public core::KeyIdFormatValidator {
public:
    void assertKeyIdFormat(const std::string& keyId) override;
    bool isKeyIdFormatValid(const std::string& keyId) override;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILE_KEYID_FORMAT_VALIDATOR_HPP_
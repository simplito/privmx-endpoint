/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_NO_OP_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_NO_OP_HPP_

#include <string>
#include <optional>
#include <Pson/BinaryString.hpp>
#include <privmx/endpoint/store/cache/CacheInterface.hpp>

namespace privmx {
namespace endpoint {
namespace store {

class CacheNoOp : public CacheInterface
{
public:
    std::optional<Pson::BinaryString> get([[maybe_unused]] const std::string& key) override { return std::nullopt; }
    void put([[maybe_unused]] const std::string& key, [[maybe_unused]] Pson::BinaryString data) override {}
    void del([[maybe_unused]] const std::string& key) override {}
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_NO_OP_HPP_

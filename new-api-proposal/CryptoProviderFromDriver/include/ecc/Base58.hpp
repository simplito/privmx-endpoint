/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_BASE58_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_BASE58_HPP_

/* Temporary classes to facilitate rewriting 
    from an old implementation to a new one   */

#include <string>

#include "CoreTypes.hpp"
#include "CryptoProviderFromDriver.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

class Base58
{
public:
    static std::string encode(const std::string& s);
    static std::string decode(const std::string& s);
    static std::string encodeWithChecksum(const std::string& s);
    static std::string decodeWithChecksum(const std::string& s);
    static bool is(const std::string& s);

    static Bytes encodeB(BytesView s);
    static Bytes decodeB(BytesView s);
    static Bytes encodeWithChecksumB(std::shared_ptr<IDigest> p, BytesView data);
    static Bytes decodeWithChecksumB(std::shared_ptr<IDigest> p, BytesView encodedData);
    static bool isB(BytesView s);
private:
    static std::string gmp2bitcoin(std::string s);
    static std::string bitcoin2gmp(std::string s);

    // static std::string gmp2bitcoinB(std::string s);
    // static std::string bitcoin2gmpB(std::string s);
};

// inline bool Base58::isB(BytesView s) { return is(Utils::b2s(s)); }

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_BASE58_HPP_
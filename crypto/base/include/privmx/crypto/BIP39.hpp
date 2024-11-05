/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_BIP39_HPP_
#define _PRIVMXLIB_CRYPTO_BIP39_HPP_

#include <string>
#include <tuple>

#include <privmx/crypto/ecc/ExtKey.hpp>

namespace privmx {
namespace crypto {

struct BIP39_t {
    std::string mnemonic;
    ExtKey ext_key;
    std::string entropy;
};

class BIP39
{
public:
    static BIP39_t generate(std::size_t strength, const std::string& password = std::string());
    static BIP39_t fromMnemonic(const std::string& mnemonic, const std::string& password = std::string());
    static BIP39_t fromEntropy(const std::string& entropy, const std::string& password = std::string());
private:

};

class Bip39Impl
{
public:
    static ExtKey getExtKey(const std::string& mnemonic, const std::string& password = std::string());
    static std::string entropyToMnemonic(const std::string& entropy);
    static std::string mnemonicToEntropy(const std::string& mnemonic);
    static std::string mnemonicToSeed(const std::string& mnemonic, const std::string& password = std::string());

private:
    static const char WORDLIST[2048][9];

    static std::string salt(const std::string& password);
    static std::tuple<std::string, std::size_t> deriveChecksumBits(const std::string& entropy);
    static int indexOfWord(const std::string& word);
};

} // crypto
} // privmx

#endif // _PRIVMXLIB_CRYPTO_BIP39_HPP_

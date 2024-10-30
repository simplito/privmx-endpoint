#include <privmx/crypto/ecc/ECDHE.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;

ECDHE::ECDHE(const PrivateKey& private_key, const PublicKey& public_key) {
    string secret = private_key.derive(public_key);
    _secret = Utils::fillTo32(secret);
}

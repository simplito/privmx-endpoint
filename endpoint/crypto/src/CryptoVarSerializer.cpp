/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/crypto/CryptoVarSerializer.hpp"
#include "privmx/endpoint/crypto/ExtKeyVarSerializer.hpp"

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

template<>
Poco::Dynamic::Var VarSerializer::serialize<crypto::BIP39_t>(const crypto::BIP39_t& val) {
    Poco::JSON::Object::Ptr obj = new Poco::JSON::Object();
    if (_options.addType) {
        obj->set("__type", "crypto$BIP39_t");
    }
    obj->set("mnemonic", serialize(val.mnemonic));
    obj->set("entropy", serialize(val.entropy));
    return obj;
}


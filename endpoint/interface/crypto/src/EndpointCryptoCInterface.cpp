/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <functional>
#include <string>
#include <unordered_map>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Pson/BinaryString.hpp>

#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/interface/crypto/crypto.h"
#include "privmx/endpoint/interface/core/CApiExecutor.hpp"
#include "privmx/endpoint/interface/core/InterfaceException.hpp"

#include "privmx/endpoint/core/varinterface/BackendRequesterVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp"
#include "privmx/endpoint/crypto/varinterface/CryptoApiVarInterface.hpp"
#include "privmx/endpoint/crypto/varinterface/ExtKeyVarInterface.hpp"
#include "privmx/endpoint/core/Config.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newCryptoApi(CryptoApi** outPtr) {
    crypto::CryptoApiVarInterface* ptr = new crypto::CryptoApiVarInterface(core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (CryptoApi*)ptr;
    return 1;
}

int privmx_endpoint_freeCryptoApi(CryptoApi* ptr) {
    delete (crypto::CryptoApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execCryptoApi(CryptoApi* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        crypto::CryptoApiVarInterface* _ptr = (crypto::CryptoApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((crypto::CryptoApiVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newExtKey(ExtKey** outPtr) {
    crypto::ExtKeyVarInterface* ptr = new crypto::ExtKeyVarInterface(core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (ExtKey*)ptr;
    return 1;
}

int privmx_endpoint_freeExtKey(ExtKey* ptr) {
    delete (crypto::ExtKeyVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execExtKey(ExtKey* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        crypto::ExtKeyVarInterface* _ptr = (crypto::ExtKeyVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((crypto::ExtKeyVarInterface::METHOD)method, argsVal);
    });
}

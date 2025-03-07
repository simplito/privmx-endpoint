/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_

#include <optional>
#include <string>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include "privmx/endpoint/core/Buffer.hpp"

namespace privmx {
namespace endpoint {
namespace core {



struct EncKey {
    std::string id;
    std::string key;
};



struct DataIntegrityObject {
    std::string creatorUserId;
    std::string creatorPubKey;
    std::string contextId;
    std::string containerId;
    int64_t timestamp;
    int64_t nonce;
};

struct DecryptedVersionedData {
    int64_t dataStructureVersion;
    int64_t statusCode;
};

struct DecryptedEncKey : public EncKey, public DecryptedVersionedData {};

struct ExpandedDataIntegrityObject : public DataIntegrityObject {
    int64_t objectFormat;
    std::unordered_map<std::string, std::string> mapOfDataSha256;
    // key : sha256 of DataJSON
};


struct EncKeyV2ToEncrypt : public EncKey {
    DataIntegrityObject dio;
    int64_t containerControlNumber;
};

struct DecryptedEncKeyV2 : public DecryptedEncKey {
    ExpandedDataIntegrityObject dio;
    int64_t containerControlNumber;
};

struct EncKeyV2IntegrityValidationData {
    std::string contextId;
    std::string containerId;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_

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

#define TIMESTAMP_ALLOWED_DELTA 5*60*1000 // in miliseconds

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
    int64_t randomId;
};

struct DecryptedVersionedData {
    int64_t dataStructureVersion;
    int64_t statusCode;
};

struct DecryptedEncKey : public EncKey, public DecryptedVersionedData {};

struct ExpandedDataIntegrityObject : public DataIntegrityObject {
    int64_t structureVersion;
    std::unordered_map<std::string, std::string> fieldChecksums;
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
    bool enableVerificationRequest = true;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CORETYPES_HPP_

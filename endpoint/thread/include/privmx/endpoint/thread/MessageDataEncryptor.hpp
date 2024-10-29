#ifndef _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATAENCRYPTOR_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATAENCRYPTOR_HPP_

#include <string>

#include <privmx/crypto/ecc/PrivateKey.hpp>

#include <privmx/endpoint/core/Types.hpp>
#include <privmx/endpoint/core/DataEncryptor.hpp>

#include "privmx/endpoint/thread/ThreadTypes.hpp"
#include "privmx/endpoint/thread/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace thread {

class MessageDataV2Encryptor
{
public:
    std::string signAndEncrypt(const dynamic::MessageDataV2& data, const privmx::crypto::PrivateKey& priv, const core::EncKey& encKey);
    dynamic::MessageDataV2Signed decryptAndGetSign(const std::string& data, const core::EncKey& key);
private:
    core::DataEncryptor<dynamic::MessageDataV2> _dataEncryptor;
};

class MessageDataV3Encryptor
{
public:
    std::string signAndEncrypt(const dynamic::MessageDataV3& data, const privmx::crypto::PrivateKey& priv, const core::EncKey& encKey);
    dynamic::MessageDataV3Signed decryptAndGetSign(const std::string& data, const core::EncKey& key);
private:
    core::DataEncryptor<Pson::BinaryString> _dataEncryptorBinaryString;
    core::DataEncryptor<dynamic::MessageDataV3> _dataEncryptorMessageDataV3;
};


} // thread
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_MESSAGEDATAENCRYPTOR_HPP_

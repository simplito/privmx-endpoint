#ifndef _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPI_HPP_
#define _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPI_HPP_

#include <memory>
#include <optional>
#include <string>

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/crypto/Types.hpp"

namespace privmx {
namespace endpoint {
namespace crypto {

class CryptoApiImpl;

/**
 * 'CryptoApi' is a class representing Endpoint's API for cryptographic operations.
 */
class CryptoApi {
public:
    /**
     * Creates instance of 'CryptoApi'.
     * 
     * @return CryptoApi object
     */
    static CryptoApi create();

    /**
     * //doc-gen:ignore
     */
    CryptoApi() = default;

    /**
     * Creates a signature of data using given key.
     *
     * @param data buffer to sign
     * @param privateKey key used to sign data
     * @return signature of data
     */
    core::Buffer signData(const core::Buffer& data, const std::string& privateKey);

    /**
     * Validate a signature of data using given key.
     *
     * @param data buffer
     * @param signature signature of data to verify
     * @param publicKey public ECC key in BASE58DER format used to validate data
     * @return data validation result
     */
    bool verifySignature(const core::Buffer& data, const core::Buffer& signature, const std::string& publicKey);

    /**
     * Generates a new private ECC key.
     *
     * @param randomSeed optional string used as the base to generate the new key
     * @return generated ECC key in WIF format
     */
    std::string generatePrivateKey(const std::optional<std::string>& randomSeed);

    /**
     * Generates a new private ECC key from a password using pbkdf2.
     *
     * @param password the password used to generate the new key
     * @param salt random string (additional input for the hashing function)

     * @return generated ECC key in WIF format
     */
    [[deprecated("Use derivePrivateKey2(const std::string& password, const std::string& salt).")]]
    std::string derivePrivateKey(const std::string& password, const std::string& salt);

    /**
     * Generates a new private ECC key from a password using pbkdf2. 
     * This version of the derive function has a rounds count increased to 200k. This makes using this function a safer choice, but it makes the received key different than in the original version.
     *
     * @param password the password used to generate the new key
     * @param salt random string (additional input for the hashing function)
     * 
     * @return generated ECC key in WIF format
     */
    std::string derivePrivateKey2(const std::string& password, const std::string& salt);

    /**
     * Generates a new public ECC key as a pair for an existing private key.
     * @param privatekey private ECC key in WIF format
     * @return generated ECC key in BASE58DER format
     */
    std::string derivePublicKey(const std::string& privateKey);

    /**
     * Generates a new symmetric key.
     * @return generated key
     */
    core::Buffer generateKeySymmetric();

    /**
     * Encrypts buffer with a given key using AES.
     *
     * @param data buffer to encrypt
     * @param symmetricKey key used to encrypt data
     * @return encrypted data buffer
     */
    core::Buffer encryptDataSymmetric(const core::Buffer& data, const core::Buffer& symmetricKey);

    /**
     * Decrypts buffer with a given key using AES.
     *
     * @param data buffer to decrypt
     * @param symmetricKey key used to decrypt data
     * @return plain (decrypted) data buffer
     */
    core::Buffer decryptDataSymmetric(const core::Buffer& data, const core::Buffer& symmetricKey);

    /**
     * Converts given private key in PEM format to its WIF format.
     *
     * @param pemKey private key to convert
     * @return private key in WIF format
     */
    std::string convertPEMKeytoWIFKey(const std::string& pemKey);

    BIP39_t generate(std::size_t strength, const std::string& password = std::string());

    BIP39_t fromMnemonic(const std::string& mnemonic, const std::string& password = std::string());

    BIP39_t fromEntropy(const std::string& entropy, const std::string& password = std::string());

    std::string entropyToMnemonic(const std::string& entropy);

    std::string mnemonicToEntropy(const std::string& mnemonic);

    std::string mnemonicToSeed(const std::string& mnemonic, const std::string& password = std::string());

private:
    CryptoApi(const std::shared_ptr<CryptoApiImpl>& impl);
    std::shared_ptr<CryptoApiImpl> _impl;
};

}  // namespace crypto
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CRYPTO_CRYPTOAPI_HPP_

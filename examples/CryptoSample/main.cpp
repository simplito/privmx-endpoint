#include <optional>
#include <iostream>
#include <privmx/endpoint/crypto/CryptoApi.hpp>

using namespace privmx::endpoint::crypto;
int main() {
    auto cryptoApi {CryptoApi::create()};
	auto priv = cryptoApi.generatePrivateKey(std::nullopt);
	auto pub = cryptoApi.derivePublicKey(priv);
	std::cout << "Generated private key: " << priv << std::endl
		      << "Generated public key: " << pub << std::endl;
	return 0;
}

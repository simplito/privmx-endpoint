/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <gtest/gtest.h>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreException.hpp>

#include "TestHelpers.hpp"

namespace core = privmx::endpoint::core;
using privmx::crypto::PrivateKey;

TEST(ConnectionState, AdoptPreviousIdentityNeedsAConnection) {
    // Never connected: no Bridge to name the slot after, no current key to compare against.
    ConnectionOf connection(std::make_shared<core::ConnectionImpl>());
    EXPECT_THROW(connection.adoptPreviousIdentity(PrivateKey::generateRandom().toWIF()), core::NotConnectedException);
}

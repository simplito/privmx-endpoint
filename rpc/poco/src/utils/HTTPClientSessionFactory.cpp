/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/Net/HTTPSClientSession.h>

#include <privmx/crypto/OpenSSLUtils.hpp>
#include <privmx/rpc/poco/utils/HTTPClientSessionFactory.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::rpc::pocoimpl;
using namespace Poco;
using namespace Poco::Net;

SharedPtr<HTTPClientSession> HTTPClientSessionFactory::create(const URI& uri) {
    if (uri.getScheme() == "https") {
        if (OpenSSLUtils::CaLocation.empty()) {
            return new HTTPSClientSession(uri.getHost(), uri.getPort());
        } else {
            Context::Ptr context = new Context(Context::TLS_CLIENT_USE, OpenSSLUtils::CaLocation, Context::VERIFY_RELAXED, 9, false);
            return new HTTPSClientSession(uri.getHost(), uri.getPort(), context);
        }
    }
    return new HTTPClientSession(uri.getHost(), uri.getPort());
}

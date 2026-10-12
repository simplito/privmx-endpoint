/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/ConvertedExceptions.hpp"
#include "privmx/rpc/RpcException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

namespace {

bool isUserDoesNotExistAlert(const Exception& e) {
    return e.getCode() == privmx::rpc::ServerAlertException().getCode() &&
           e.getDescription() == "User doesn't exist";
}

} // namespace

void ExceptionConverter::rethrowAsCoreException(const Exception& e) {
    if (isUserDoesNotExistAlert(e)) {
        throw server::UserDoesNotExistException(e.getDescription());
    }
    e.rethrow();
}

Exception ExceptionConverter::convert(const Exception& e) {
    if (isUserDoesNotExistAlert(e)) {
        return server::UserDoesNotExistException(e.getDescription());
    }
    return e;
}

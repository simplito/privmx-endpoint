/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_TIMESTAMPVALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_TIMESTAMPVALIDATOR_HPP_

#include <algorithm>


namespace privmx {
namespace endpoint {
namespace core {

class TimestampValidator {
public:
    static bool validate(int64_t clinetTimestamp, int64_t serverTimestamp);
private:
    static constexpr int64_t TIMESTAMP_ALLOWED_DELTA = 5*60*1000; // in miliseconds
};
} // core
} // endpoint
} // privmx
#endif // _PRIVMXLIB_ENDPOINT_CORE_TIMESTAMPVALIDATOR_HPP_
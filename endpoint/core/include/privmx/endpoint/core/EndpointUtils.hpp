/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_

#include <algorithm>
#include <map>
#include <privmx/utils/TypedObject.hpp>
#include <set>
#include <string>
#include <vector>

#include "privmx/endpoint/core/Types.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class EndpointUtils {
public:
    static std::vector<UserWithPubKey> uniqueListUserWithPubKey(const std::vector<UserWithPubKey>& list1,
                                                                const std::vector<UserWithPubKey>& list2);

    /**
     * Returns vector of elements which do exist on the baseList and not on the subList
     */
    static std::vector<std::string> getDifference(const std::vector<std::string>& baseList,
                                                  const std::vector<std::string>& subList);

    static std::vector<std::string> uniqueList(const std::vector<std::string>& list1,
                                               const std::vector<std::string>& list2);

    template<typename T = std::string>
    static std::vector<T> listToVector(utils::List<T> list) {
        std::vector<T> ret{};
        for (auto x : list) {
            ret.push_back(x);
        }
        return ret;
    }

    static std::vector<std::string> usersWithPubKeyToIds(std::vector<core::UserWithPubKey>& users);

    static std::string generateId();

    static std::string generateDIORandomId();
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_UTILS_HPP_

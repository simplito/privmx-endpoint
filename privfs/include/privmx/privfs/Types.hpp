/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_PRIVFS_RAWUSERINFO_HPP_
#define _PRIVMXLIB_PRIVFS_RAWUSERINFO_HPP_

#include <string>
#include <optional>
#include <Poco/SharedPtr.h>

#include <privmx/pki/Types.hpp>
#include <privmx/utils/TypedObject.hpp>
#include <privmx/utils/TypesMacros.hpp>

namespace privmx {
namespace privfs {

// struct UserInfoProfile
// {
//     using Ptr = Poco::SharedPtr<UserInfoProfile>;
//     std::optional<std::string> name;
//     std::optional<std::string> description;
//     std::optional<std::string> image;
//     // TODO: sinks
// };

struct KeystoreWithInsertionParams
{
    using Ptr = Poco::SharedPtr<KeystoreWithInsertionParams>;
    pki::keystore::IKeyStore2::Ptr keystore;
    pki::PkiDataParams::Ptr params;
};

// class RawUserInfo : public utils::TypedObject
// {
// public: 
//     CORE_TYPE_CONSTRUCTOR(RawUserInfo)
//     void initialize() override {
//         initializeObject({"name", "description"});
//     }
//     STRING_FIELD(name)
//     STRING_FIELD(description)
//     LIST_VAR_FIELD(sinks)
// };

} // privfs
} // privmx

#endif // _PRIVMXLIB_PRIVFS_RAWUSERINFO_HPP_

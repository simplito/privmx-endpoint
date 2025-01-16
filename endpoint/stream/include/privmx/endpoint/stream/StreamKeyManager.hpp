/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAM_KEY_MANAGER_API_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAM_KEY_MANAGER_API_HPP_

#include <privmx/endpoint/core/KeyProvider.hpp>

#include <string>
#include <memory>
#include <Poco/Dynamic/Var.h>
#include <pmx_frame_cryptor.h>

namespace privmx {
namespace endpoint {
namespace stream {

class StreamKeyManager {
public:
    StreamKeyManager(std::shared_ptr<privmx::webrtc::KeyProvider> _webRtcKeyProvider);
    void requestKey(const std::vector<core::UserWithPubKey>& users);
    // 
    void respondToRequestRequest(/*request form user sendKey*/);
    // 
    void updateKey(const std::vector<core::UserWithPubKey>& users);
    //
    void respondToUpdateRequest(/*request form user updateKey*/);
    //

    
private:
    std::shared_ptr<privmx::webrtc::KeyProvider> _webRtcKeyProvider;
    std::shared_ptr<core::KeyProvider> _keyProvider;

};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAM_KEY_MANAGER_API_HPP_

/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_FRAMECRYPTIONSTATEOBSERVER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_FRAMECRYPTIONSTATEOBSERVER_HPP_

#include <functional>

#include <pmx_frame_cryptor.h>

namespace privmx {
namespace endpoint {
namespace stream {

// Reports only the one frame cryption state which new keys can mend. A decryption which failed with the
// key in hand, or an encryption which failed, are not helped by fetching the keys again.
class FrameCryptionStateObserver : public privmx::webrtc::FrameCryptorObserver {
public:
    using MissingKeyHandler = std::function<void()>;

    explicit FrameCryptionStateObserver(MissingKeyHandler onMissingKey);
    void onFrameCryptionStateChanged(privmx::webrtc::FrameCryptionState state) override;

private:
    MissingKeyHandler _onMissingKey;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_FRAMECRYPTIONSTATEOBSERVER_HPP_

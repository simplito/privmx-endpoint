/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_TYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_TYPES_HPP_

#include "privmx/endpoint/stream/Types.hpp"
#include "privmx/endpoint/stream/webrtc/OnTrackInterface.hpp"
#include <functional>

namespace privmx {
namespace endpoint {
namespace stream {

/**
 * Types of the local devices that feed a Publisher Stream.
 */
enum DeviceType {
    /**
     * microphone or another audio input
     */
    Audio = 0,

    /**
     * camera
     */
    Video = 1,

    /**
     * whole screen
     */
    Desktop_Screen = 2,

    /**
     * single application window
     */
    Desktop_Window = 3,

    /**
     * data track, which carries the binary messages sent with `sendData`
     */
    Plain = 4
};

/**
 * Kinds of the desktop sources listed by `getDesktopDevices`.
 */
enum DesktopType {
    /**
     * whole screen
     */
    Screen = 0,

    /**
     * single application window
     */
    Window = 1
};

/**
 * Describes a local device that feeds a Publisher Stream.
 *
 * `addTrack` matches the device by its `name` and its `id`, so pass the struct you get from `getAudioDevices`,
 * `getVideoDevices`, or `getDesktopDevices` unchanged.
 */
struct MediaDevice {
    /**
     * name of the device
     */
    std::string name;

    /**
     * ID of the device
     */
    std::string id;

    /**
     * type of the device
     */
    DeviceType type;
};

/**
 * Describes a local audio input device.
 */
struct AudioDevice : public MediaDevice {};

/**
 * Describes a local camera.
 */
struct VideoDevice : public MediaDevice {};

/**
 * Describes a local desktop capture source.
 */
struct DesktopDevice : public MediaDevice {
    /**
     * preview of the screen or the window which this device captures
     */
    std::vector<unsigned char> thumbnail;
};

/**
 * Holds the preferred capture settings of a track.
 *
 * The device applies the closest settings it supports, so the resulting track sometimes differs from the request.
 */
struct MediaTrackConstrains {
    /**
     * preferred capture width in pixels, which applies to the video devices only
     */
    size_t idealWidth = 1280;

    /**
     * preferred capture height in pixels, which applies to the video devices only
     */
    size_t idealHeight = 720;

    /**
     * preferred number of frames per second, which applies to the video and the desktop devices
     */
    size_t idealFps = 15;
};

/**
 * Controls a track added to a Publisher Stream.
 */
struct MediaTrack {
    /**
     * enables and disables the track. A disabled track stays in the Stream and stops sending its content.
     * The data tracks ignore this call.
     */
    std::function<void(bool)> setEnabled;
};

} // namespace stream
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_STREAMAPI_WEBRTC_TYPES_HPP_

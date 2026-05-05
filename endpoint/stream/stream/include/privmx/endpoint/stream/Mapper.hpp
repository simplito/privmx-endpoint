/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STREAM_MAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_STREAM_MAPPER_HPP_

#include "privmx/endpoint/stream/ServerTypes.hpp"
#include "privmx/endpoint/stream/Types.hpp"

namespace privmx {
namespace endpoint {
namespace stream {

class Mapper {
public:
    static StreamTrackInfo mapToStreamTrackInfo(const server::StreamTrackInfo_c_struct& s);
    static StreamInfo mapToStreamInfo(const server::StreamInfo_c_struct& s);
    static StreamTrackModificationPair mapToStreamTrackModificationPair(const server::StreamTrackModificationPair_c_struct& s);
    static StreamTrackModification mapToStreamTrackModification(const server::StreamTrackModification_c_struct& s);
    static NewStreams mapToNewStreams(const server::NewStreams_c_struct& s);
    static PublishedStreamData mapToPublishedStreamData(const server::PublishedStreamData_c_struct& s);
    static PublishedStreamData mapToPublishedStreamData(const server::StreamPublishedEventData_c_struct& s);
    static StreamUpdatedEventData mapToStreamUpdatedEventData(const server::StreamUpdatedEventData_c_struct& s);
    static UpdatedStreamData mapToUpdatedStreamData(const server::UpdatedStreamData_c_struct& s);
    static StreamsUpdatedData mapToStreamsUpdatedData(const server::StreamsUpdatedData_c_struct& s);
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_MAPPER_HPP_

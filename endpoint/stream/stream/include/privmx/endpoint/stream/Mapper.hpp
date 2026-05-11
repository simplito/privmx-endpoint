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
    static StreamTrackInfo mapToStreamTrackInfo(const server::StreamTrackInfo& s);
    static StreamInfo mapToStreamInfo(const server::StreamInfo& s);
    static StreamTrackModificationPair mapToStreamTrackModificationPair(const server::StreamTrackModificationPair& s);
    static StreamTrackModification mapToStreamTrackModification(const server::StreamTrackModification& s);
    static NewStreams mapToNewStreams(const server::NewStreams& s);
    static PublishedStreamData mapToPublishedStreamData(const server::PublishedStreamData& s);
    static PublishedStreamData mapToPublishedStreamData(const server::StreamPublishedEventData& s);
    static StreamUpdatedEventData mapToStreamUpdatedEventData(const server::StreamUpdatedEventData& s);
    static UpdatedStreamData mapToUpdatedStreamData(const server::UpdatedStreamData& s);
    static StreamsUpdatedData mapToStreamsUpdatedData(const server::StreamsUpdatedData& s);
};

} // stream
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STREAM_MAPPER_HPP_

/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_THREAD_THREADVALIDATOR_HPP_
#define _PRIVMXLIB_ENDPOINT_THREAD_THREADVALIDATOR_HPP_

#include <string>
#include <privmx/endpoint/core/Validator.hpp>
#include "privmx/endpoint/thread/Types.hpp"
#include "privmx/endpoint/thread/Events.hpp"

namespace privmx {
namespace endpoint {
namespace core {

template<>
class StructValidator<thread::Thread>
{
public:
    static void validate(const thread::Thread& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "Thread";}
};

template<>
class StructValidator<PagingList<thread::Thread>>
{
public:
    static void validate(const PagingList<thread::Thread>& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "PagingList<Thread>";}
};

template<>
class StructValidator<thread::ServerMessageInfo>
{
public:
    static void validate(const thread::ServerMessageInfo& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ServerMessageInfo";}
};

template<>
class StructValidator<thread::Message> 
{
public:
    static void validate(const thread::Message& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "Message";}
};

template<>
class StructValidator<PagingList<thread::Message>> 
{
public:
    static void validate(const PagingList<thread::Message>& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "PagingList<Message>";}
};
template<>
class StructValidator<thread::ThreadCreatedEvent>
{
public:
    static void validate(const thread::ThreadCreatedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadCreatedEvent";}
};

template<>
class StructValidator<thread::ThreadUpdatedEvent>
{
public:
    static void validate(const thread::ThreadUpdatedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadUpdatedEvent";}
};

template<>
class StructValidator<thread::ThreadDeletedEventData>
{
public:
    static void validate(const thread::ThreadDeletedEventData& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadDeletedEventData";}
};

template<>
class StructValidator<thread::ThreadDeletedEvent>
{
public:
    static void validate(const thread::ThreadDeletedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadDeletedEvent";}
};

template<>
class StructValidator<thread::ThreadStatsEventData>
{
public:
    static void validate(const thread::ThreadStatsEventData& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadStatsEventData";}
};

template<>
class StructValidator<thread::ThreadStatsChangedEvent>
{
public:
    static void validate(const thread::ThreadStatsChangedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadStatsChangedEvent";}
};

template<>
class StructValidator<thread::ThreadNewMessageEvent>
{
public:
    static void validate(const thread::ThreadNewMessageEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadNewMessageEvent";}
};

template<>
class StructValidator<thread::ThreadDeletedMessageEventData>
{
public:
    static void validate(const thread::ThreadDeletedMessageEventData& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadDeletedMessageEventData";}
};

template<>
class StructValidator<thread::ThreadMessageDeletedEvent>
{
public:
    static void validate(const thread::ThreadMessageDeletedEvent& value, const std::string& stack_trace = "");
    static std::string getReadableType() {return "ThreadMessageDeletedEvent";}
};

} // core
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_THREAD_THREADVALIDATOR_HPP_

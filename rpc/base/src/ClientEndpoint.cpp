/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/rpc/ClientEndpoint.hpp>
#include <privmx/rpc/RpcException.hpp>
#include <privmx/endpoint/core/ConvertedExceptions.hpp>

using namespace privmx;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco::Dynamic;
using namespace Poco::JSON;

namespace server = privmx::endpoint::server;

namespace {

template<typename E>
[[noreturn]] void throwServerError(const string& msg, const string& data) {
    E e(data.empty() ? msg : msg + "\n" + data);
    e.setData(data);
    throw e;
}

// the Bridge reports errors as a single int; the high half picks the family, the low half the error
// within it. Codes outside the ranges below are surfaced as a generic EndpointServerException.
[[noreturn]] void throwForServerCode(unsigned int code, const string& msg, const string& data) {
    unsigned int family = (code & 0xFFFF0000) >> 16;
    unsigned int error = (code & 0x0000FFFF);

// one case per row of the Bridge's error table, so a code is never retyped here
#define PRIVMX_THROW_SERVER_ERROR(NAME, MSG, CODE) case CODE: throwServerError<server::NAME>(msg, data);

    if (family == 0xFFFF) {
        switch (error) {
        SERVER_REQUEST_EXCEPTIONS(PRIVMX_THROW_SERVER_ERROR)
        default: throwServerError<server::EndpointServerRequestException>(msg, data);
        }
    }

    if (family == 0x0000) {
        switch (error) {
        SERVER_EXCEPTIONS(PRIVMX_THROW_SERVER_ERROR)
        }
    }

#undef PRIVMX_THROW_SERVER_ERROR

    server::EndpointServerException e(msg + " | " + data, code);
    e.setData(data);
    throw e;
}

} // namespace

ClientEndpoint::ClientEndpoint(TicketsManager& tickets_manager, const ConnectionOptionsFull& options) : tickets_manager(tickets_manager), connection(request_buff, tickets_manager, options), _request_lock(tickets_manager.request_mutex, defer_lock) {
    connection.application_handler = [&](const Var &data){ invoke(data); };
    connection.on_ticket_response = [&]{
        if (_request_lock) {
            _request_lock.unlock();
        }
    };
}

future<Var> ClientEndpoint::call(const std::string& method, const Var& params, bool force_plain) {
    if (!force_plain && !_ticket_handshake) {
        _request_lock.lock();
        try {
            connection.reset();
            connection.ticketHandshake();
            _ticket_handshake = true;
            if (tickets_manager.shouldAskForNewTickets(TICKETS_MIN_COUNT)) {
                connection.ticketRequest(TICKETS_MAX_COUNT);
            } else {
                _request_lock.unlock();
            }
        } catch (const PrivmxException& e) {
            _request_lock.unlock();
            e.rethrow();
        } catch (...) {
            _request_lock.unlock();
            throw TicketHandshakeErrorException();
        }
    }
    Object::Ptr request_json = new Object();
    request_json->set("jsonrpc", "2.0");
    request_json->set("id", _id);
    request_json->set("method", method);
    request_json->set("params", params);
    connection.send(_pson_encoder.encode(request_json));
    _promises.emplace(make_pair(_id, promise<Var>()));
    return _promises[_id++].get_future();
}

void ClientEndpoint::flush() {
    request_buff.str("");
    _ticket_handshake = false;
}

void ClientEndpoint::invoke(const Var& application_data) {
    Object::Ptr data_object = application_data.extract<Object::Ptr>();
    if (data_object->has("error") && !data_object->getObject("error").isNull()) {
        Object::Ptr err = data_object->getObject("error");
        auto msg = err->getValue<string>("msg");
        auto code = (unsigned int)err->getObject("data")->getObject("error")->getValue<int>("code");
        if(err->getObject("data")->getObject("error")->has("data") && !err->getObject("data")->getObject("error")->get("data").isEmpty()) {
            auto error_data = err->getObject("data")->getObject("error")->get("data");
            if(error_data.type() == typeid(Poco::JSON::Object::Ptr) || error_data.type() == typeid(Poco::JSON::Array::Ptr)) {
                throwForServerCode(code, msg, utils::Utils::stringifyVar(error_data));
            } else if (error_data.isString()) {
                throwForServerCode(code, msg, error_data.convert<std::string>());
            } else {
                throwForServerCode(code, msg, "unkown data type");
            }
        }
        throwForServerCode(code, msg, "");
    }
    int id = data_object->getValue<int>("id");
    auto promise = _promises.find(id);
    promise->second.set_value(data_object->get("result"));
    _promises.erase(promise);
}

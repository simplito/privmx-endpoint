#include <privmx/rpc/ClientEndpoint.hpp>
#include <privmx/rpc/RpcException.hpp>

using namespace privmx;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco::Dynamic;
using namespace Poco::JSON;

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
        if(err->getObject("data")->getObject("error")->has("data") && !err->getObject("data")->getObject("error")->get("data").isEmpty()) {
            auto error_data = err->getObject("data")->getObject("error")->get("data");
            if(error_data.type() == typeid(Poco::JSON::Object::Ptr) || error_data.type() == typeid(Poco::JSON::Array::Ptr)) {
                throw PrivmxException(err->getValue<string>("msg"), PrivmxException::RPC, err->getObject("data")->getObject("error")->getValue<int>("code"), utils::Utils::stringifyVar(error_data)); 
            } else if (error_data.isString()) {
                throw PrivmxException(err->getValue<string>("msg"), PrivmxException::RPC, err->getObject("data")->getObject("error")->getValue<int>("code"), error_data.convert<std::string>()); 
            } else {
                throw PrivmxException(err->getValue<string>("msg"), PrivmxException::RPC, err->getObject("data")->getObject("error")->getValue<int>("code"), "unkown data type");
            }
        }
        throw PrivmxException(err->getValue<string>("msg"), PrivmxException::RPC, err->getObject("data")->getObject("error")->getValue<int>("code"));
    }
    int id = data_object->getValue<int>("id");
    auto promise = _promises.find(id);
    promise->second.set_value(data_object->get("result"));
    _promises.erase(promise);
}

/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <functional>
#include <string>
#include <unordered_map>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Pson/BinaryString.hpp>

#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/event/cinterface/event.h"
#include <privmx/endpoint/core/cinterface/CApiExecutor.hpp>
#include <privmx/endpoint/core/cinterface/InterfaceException.hpp>
#include <privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp>
#include "privmx/endpoint/event/varinterface/EventApiVarInterface.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newEventApi(Connection* connectionPtr, EventApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    event::EventApiVarInterface* ptr = new event::EventApiVarInterface(_connectionPtr->getApi(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (EventApi*)ptr;
    return 1;
}

int privmx_endpoint_freeEventApi(EventApi* ptr) {
    delete (event::EventApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execEventApi(EventApi* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        event::EventApiVarInterface* _ptr = (event::EventApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((event::EventApiVarInterface::METHOD)method, argsVal);
    });
}
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

#include "privmx/endpoint/interface/endpoint.h"
#include "privmx/endpoint/interface/CApiExecutor.hpp"
#include "privmx/endpoint/interface/InterfaceException.hpp"

#include "privmx/endpoint/core/varinterface/BackendRequesterVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/EventQueueVarInterface.hpp"
#include "privmx/endpoint/thread/varinterface/ThreadApiVarInterface.hpp"
#include "privmx/endpoint/store/varinterface/StoreApiVarInterface.hpp"
#include "privmx/endpoint/inbox/varinterface/InboxApiVarInterface.hpp"
#include "privmx/endpoint/crypto/varinterface/CryptoApiVarInterface.hpp"
#include "privmx/endpoint/core/Config.hpp"

using namespace privmx::endpoint;

int privmx_endpoint_newEventQueue(EventQueue** outPtr) {
    core::EventQueueVarInterface* ptr = new core::EventQueueVarInterface(core::EventQueue::getInstance(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (EventQueue*)ptr;
    return 1;
}

int privmx_endpoint_freeEventQueue(EventQueue* ptr) {
    delete (core::EventQueueVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execEventQueue(EventQueue* ptr, int method, const pson_value* args, pson_value** res) {
    return privmx::utils::CApiExecutor::execFunc(res, [&]{
        core::EventQueueVarInterface* _ptr = (core::EventQueueVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((core::EventQueueVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newConnection(Connection** outPtr) {
    core::ConnectionVarInterface* ptr = new core::ConnectionVarInterface(core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (Connection*)ptr;
    return 1;
}

int privmx_endpoint_freeConnection(Connection* ptr) {
    delete (core::ConnectionVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execConnection(Connection* ptr, int method, const pson_value* args, pson_value** res) {
    return privmx::utils::CApiExecutor::execFunc(res, [&]{
        core::ConnectionVarInterface* _ptr = (core::ConnectionVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((core::ConnectionVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newBackendRequester(BackendRequester** outPtr) {
    core::BackendRequesterVarInterface* ptr = new core::BackendRequesterVarInterface(core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (BackendRequester*)ptr;
    return 1;
}

int privmx_endpoint_freeBackendRequester(BackendRequester* ptr) {
    delete (core::BackendRequesterVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execBackendRequester(BackendRequester* ptr, int method, const pson_value* args, pson_value** res) {
    return privmx::utils::CApiExecutor::execFunc(res, [&]{
        core::BackendRequesterVarInterface* _ptr = (core::BackendRequesterVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((core::BackendRequesterVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newThreadApi(Connection* connectionPtr, ThreadApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    thread::ThreadApiVarInterface* ptr = new thread::ThreadApiVarInterface(_connectionPtr->getApi(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (ThreadApi*)ptr;
    return 1;
}

int privmx_endpoint_freeThreadApi(ThreadApi* ptr) {
    delete (thread::ThreadApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execThreadApi(ThreadApi* ptr, int method, const pson_value* args, pson_value** res) {
    return privmx::utils::CApiExecutor::execFunc(res, [&]{
        thread::ThreadApiVarInterface* _ptr = (thread::ThreadApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((thread::ThreadApiVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newStoreApi(Connection* connectionPtr, StoreApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    store::StoreApiVarInterface* ptr = new store::StoreApiVarInterface(_connectionPtr->getApi(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (StoreApi*)ptr;
    return 1;
}

int privmx_endpoint_freeStoreApi(StoreApi* ptr) {
    delete (store::StoreApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execStoreApi(StoreApi* ptr, int method, const pson_value* args, pson_value** res) {
    return privmx::utils::CApiExecutor::execFunc(res, [&]{
        store::StoreApiVarInterface* _ptr = (store::StoreApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((store::StoreApiVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newInboxApi(Connection* connectionPtr, ThreadApi* threadApiPtr, StoreApi* storeApiPtr, InboxApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    thread::ThreadApiVarInterface* _threadApiPtr = (thread::ThreadApiVarInterface*)threadApiPtr;
    store::StoreApiVarInterface* _storeApiPtr = (store::StoreApiVarInterface*)storeApiPtr;
    inbox::InboxApiVarInterface* ptr = new inbox::InboxApiVarInterface(_connectionPtr->getApi(), _threadApiPtr->getApi(), _storeApiPtr->getApi(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (InboxApi*)ptr;
    return 1;
}

int privmx_endpoint_freeInboxApi(InboxApi* ptr) {
    delete (inbox::InboxApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execInboxApi(InboxApi* ptr, int method, const pson_value* args, pson_value** res) {
    return privmx::utils::CApiExecutor::execFunc(res, [&]{
        inbox::InboxApiVarInterface* _ptr = (inbox::InboxApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((inbox::InboxApiVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newCryptoApi(CryptoApi** outPtr) {
    crypto::CryptoApiVarInterface* ptr = new crypto::CryptoApiVarInterface(core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (CryptoApi*)ptr;
    return 1;
}

int privmx_endpoint_freeCryptoApi(CryptoApi* ptr) {
    delete (crypto::CryptoApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execCryptoApi(CryptoApi* ptr, int method, const pson_value* args, pson_value** res) {
    return privmx::utils::CApiExecutor::execFunc(res, [&]{
        crypto::CryptoApiVarInterface* _ptr = (crypto::CryptoApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((crypto::CryptoApiVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_setCertsPath(const char* certsPath) {
    try {
        core::Config::setCertsPath(certsPath);
        return 1;
    } catch(...) {}
    return 0;
}

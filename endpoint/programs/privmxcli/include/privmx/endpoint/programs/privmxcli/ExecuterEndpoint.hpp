/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_ENDPOINT_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_ENDPOINT_HPP_

#include <chrono>
#include <thread>
#include <readline/readline.h>
#include <functional>
#include <string>
#include <unordered_map>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>

#include "privmx/endpoint/programs/privmxcli/GlobalVariables.hpp"
#include "privmx/endpoint/programs/privmxcli/LoadingAnimation.hpp"
#include "privmx/endpoint/programs/privmxcli/ConsoleWriter.hpp"
#include "privmx/endpoint/core/Config.hpp"

#include "privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/EventQueueVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/BackendRequesterVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/UtilsVarInterface.hpp"
#include "privmx/endpoint/crypto/varinterface/CryptoApiVarInterface.hpp"
#include "privmx/endpoint/crypto/varinterface/ExtKeyVarInterface.hpp"
#include "privmx/endpoint/event/varinterface/EventApiVarInterface.hpp"
#include "privmx/endpoint/thread/varinterface/ThreadApiVarInterface.hpp"
#include "privmx/endpoint/store/varinterface/StoreApiVarInterface.hpp"
#include "privmx/endpoint/inbox/varinterface/InboxApiVarInterface.hpp"
#include "privmx/endpoint/kvdb/varinterface/KvdbApiVarInterface.hpp"
#include "privmx/endpoint/group/varinterface/GroupApiVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

namespace privmx {
namespace endpoint {
namespace privmxcli {


struct ApiVar {
    ApiVar(
        core::VarSerializer _serializer,
        std::shared_ptr<privmx::endpoint::core::EventQueueVarInterface> _event,
        std::shared_ptr<privmx::endpoint::core::ConnectionVarInterface> _connection,
        std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> _backendRequester,
        std::shared_ptr<privmx::endpoint::core::UtilsVarInterface> _utils,
        std::shared_ptr<privmx::endpoint::crypto::CryptoApiVarInterface> _crypto,
        std::shared_ptr<privmx::endpoint::crypto::ExtKeyVarInterface> _extKey,
        std::shared_ptr<privmx::endpoint::thread::ThreadApiVarInterface> _thread,
        std::shared_ptr<privmx::endpoint::store::StoreApiVarInterface> _store,
        std::shared_ptr<privmx::endpoint::inbox::InboxApiVarInterface> _inbox,
        std::shared_ptr<privmx::endpoint::kvdb::KvdbApiVarInterface> _kvdb,
        std::shared_ptr<privmx::endpoint::group::GroupApiVarInterface> _group,
        std::shared_ptr<privmx::endpoint::event::EventApiVarInterface> _eventApi
    ) : serializer(_serializer), event(_event), connection(_connection), backendRequester(_backendRequester), utils(_utils), crypto(_crypto), extKey(_extKey), thread(_thread), store(_store), inbox(_inbox), kvdb(_kvdb), group(_group), eventApi(_eventApi) {}
    core::VarSerializer serializer;
    std::shared_ptr<privmx::endpoint::core::EventQueueVarInterface> event;
    std::shared_ptr<privmx::endpoint::core::ConnectionVarInterface> connection;
    std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> backendRequester;
    std::shared_ptr<privmx::endpoint::core::UtilsVarInterface> utils;
    std::shared_ptr<privmx::endpoint::crypto::CryptoApiVarInterface> crypto;
    std::shared_ptr<privmx::endpoint::crypto::ExtKeyVarInterface> extKey;
    std::shared_ptr<privmx::endpoint::thread::ThreadApiVarInterface> thread;
    std::shared_ptr<privmx::endpoint::store::StoreApiVarInterface> store;
    std::shared_ptr<privmx::endpoint::inbox::InboxApiVarInterface> inbox;
    std::shared_ptr<privmx::endpoint::kvdb::KvdbApiVarInterface> kvdb;
    std::shared_ptr<privmx::endpoint::group::GroupApiVarInterface> group;
    std::shared_ptr<privmx::endpoint::event::EventApiVarInterface> eventApi;
};

class ExecuterEndpoint {
public:
    ExecuterEndpoint(std::thread::id main_thread_id, std::shared_ptr<CliConfig> config, std::shared_ptr<ConsoleWriter> console_writer);
    bool execute(const func_enum& fun_code, const Tokens &st);
    bool execute_help(const func_enum& fun_code, const std::string& function_name);
    std::string  get_all_function_help_printable_string();
private:
    Poco::Dynamic::Var getS_var(const std::string &key);

    std::thread::id _main_thread_id;
    std::shared_ptr<CliConfig> _config;
    std::shared_ptr<ConsoleWriter> _console_writer;
    std::shared_ptr<ApiVar> _endpoint;

    std::chrono::_V2::system_clock::time_point _timer_start = std::chrono::system_clock::now();


    const std::unordered_map<func_enum, std::function<Poco::Dynamic::Var(std::shared_ptr<ApiVar> , const Poco::JSON::Array::Ptr&)>> functions_endpoint_execute = {
        {config_setCertsPath, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = privmx::endpoint::core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            Poco::Dynamic::Var certsPath = argsArr->get(0);
            if (!certsPath.isString()) {
                throw privmx::endpoint::core::InvalidArgumentTypeException("certsPath | Expected string, value has type " + (std::string)(certsPath.type().name()));
            }
            privmx::endpoint::core::Config::setCertsPath(certsPath.convert<std::string>());
            return Poco::Dynamic::Var();
        }},
        {core_waitEvent, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->event->waitEvent(args);
        }},
        {core_getEvent, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->event->getEvent(args);
        }},
        {core_emitBreakEvent, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->event->emitBreakEvent(args);
        }},
        {core_connect, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            api->connection->connect(args);
            // Built first: every container API is handed the same GroupApi so they share one group key cache.
            std::shared_ptr<group::GroupApiVarInterface> group = std::make_shared<group::GroupApiVarInterface>(api->connection->getApi(), api->serializer);
            group->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->group = group;
            std::shared_ptr<thread::ThreadApiVarInterface> thread = std::make_shared<thread::ThreadApiVarInterface>(api->connection->getApi(), api->serializer, api->group->getApi());
            thread->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->thread = thread;
            std::shared_ptr<store::StoreApiVarInterface> store = std::make_shared<store::StoreApiVarInterface>(api->connection->getApi(), api->serializer, api->group->getApi());
            store->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->store = store;
            std::shared_ptr<inbox::InboxApiVarInterface> inbox = std::make_shared<inbox::InboxApiVarInterface>(api->connection->getApi(), api->thread->getApi(), api->store->getApi(), api->serializer, api->group->getApi());
            inbox->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->inbox = inbox;
            std::shared_ptr<kvdb::KvdbApiVarInterface> kvdb = std::make_shared<kvdb::KvdbApiVarInterface>(api->connection->getApi(), api->serializer, api->group->getApi());
            kvdb->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->kvdb = kvdb;
            std::shared_ptr<event::EventApiVarInterface> eventApi = std::make_shared<event::EventApiVarInterface>(api->connection->getApi(), api->serializer);
            eventApi->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->eventApi = eventApi;
            return Poco::Dynamic::Var();
        }},
        {core_connectPublic, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            api->connection->connectPublic(args);
            // Built first: every container API is handed the same GroupApi so they share one group key cache.
            std::shared_ptr<group::GroupApiVarInterface> group = std::make_shared<group::GroupApiVarInterface>(api->connection->getApi(), api->serializer);
            group->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->group = group;
            std::shared_ptr<thread::ThreadApiVarInterface> thread = std::make_shared<thread::ThreadApiVarInterface>(api->connection->getApi(), api->serializer, api->group->getApi());
            thread->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->thread = thread;
            std::shared_ptr<store::StoreApiVarInterface> store = std::make_shared<store::StoreApiVarInterface>(api->connection->getApi(), api->serializer, api->group->getApi());
            store->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->store = store;
            std::shared_ptr<inbox::InboxApiVarInterface> inbox = std::make_shared<inbox::InboxApiVarInterface>(api->connection->getApi(), api->thread->getApi(), api->store->getApi(), api->serializer, api->group->getApi());
            inbox->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->inbox = inbox;
            std::shared_ptr<kvdb::KvdbApiVarInterface> kvdb = std::make_shared<kvdb::KvdbApiVarInterface>(api->connection->getApi(), api->serializer, api->group->getApi());
            kvdb->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->kvdb = kvdb;
            std::shared_ptr<event::EventApiVarInterface> eventApi = std::make_shared<event::EventApiVarInterface>(api->connection->getApi(), api->serializer);
            eventApi->create(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
            api->eventApi = eventApi;
            return Poco::Dynamic::Var();
        }},
        {core_disconnect, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->connection->disconnect(args);
        }},
        {core_getConnectionId, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->connection->getConnectionId(args);
        }},
        {core_listContexts, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->connection->listContexts(args);
        }},
        {core_listContextUsers, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->connection->listContextUsers(args);
        }},
        {core_backendRequest, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->backendRequester->backendRequest(args);
        }},
        {core_subscribeFor, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->connection->subscribeFor(args);
        }},
        {core_unsubscribeFrom, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->connection->unsubscribeFrom(args);
        }},
        {core_buildSubscriptionQuery, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->connection->buildSubscriptionQuery(args);
        }},
        {utils_encodeHex, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->encodeHex(args);
        }},
        {utils_decodeHex, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->decodeHex(args);
        }},
        {utils_isHex, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->isHex(args);
        }},
        {utils_encodeBase32, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->encodeBase32(args);
        }},
        {utils_decodeBase32, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->decodeBase32(args);
        }},
        {utils_isBase32, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->isBase32(args);
        }},
        {utils_encodeBase64, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->encodeBase64(args);
        }},
        {utils_decodeBase64, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->decodeBase64(args);
        }},
        {utils_isBase64, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->isBase64(args);
        }},
        {utils_trim, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->trim(args);
        }},
        {utils_split, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->split(args);
        }},
        {utils_ltrim, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->ltrim(args);
        }},
        {utils_rtrim, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->utils->rtrim(args);
        }},
        {crypto_signData, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->signData(args);
        }},
        {crypto_verifySignature, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->verifySignature(args);
        }},
        {crypto_generatePrivateKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->generatePrivateKey(args);
        }},
        {crypto_derivePrivateKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->derivePrivateKey(args);
        }},
        {crypto_derivePublicKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->derivePublicKey(args);
        }},
        {crypto_generateKeySymmetric, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->generateKeySymmetric(args);
        }},
        {crypto_encryptDataSymmetric, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->encryptDataSymmetric(args);
        }},
        {crypto_decryptDataSymmetric, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->decryptDataSymmetric(args);
        }},
        {crypto_convertPEMKeytoWIFKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->convertPEMKeytoWIFKey(args);
        }},
        {crypto_fromMnemonic, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->fromMnemonic(args);
        }},
        {crypto_fromEntropy, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->fromEntropy(args);
        }},
        {crypto_entropyToMnemonic, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->entropyToMnemonic(args);
        }},
        {crypto_mnemonicToEntropy, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->mnemonicToEntropy(args);
        }},
        {crypto_mnemonicToSeed, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->crypto->mnemonicToSeed(args);
        }},
        // ExtKey: factory methods return an int64 handle to an ExtKey instance;
        // instance methods take that handle as the first argument.
        {extkey_fromSeed, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->extKey->fromSeed(args);
        }},
        {extkey_fromBase58, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->extKey->fromBase58(args);
        }},
        {extkey_generateRandom, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->extKey->generateRandom(args);
        }},
        {extkey_derive, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            Poco::JSON::Array::Ptr subArgs = new Poco::JSON::Array();
            subArgs->add(argsArr->get(1));
            return extKey->derive(subArgs);
        }},
        {extkey_deriveHardened, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 2);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            Poco::JSON::Array::Ptr subArgs = new Poco::JSON::Array();
            subArgs->add(argsArr->get(1));
            return extKey->deriveHardened(subArgs);
        }},
        {extkey_getPrivatePartAsBase58, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            return extKey->getPrivatePartAsBase58(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        }},
        {extkey_getPublicPartAsBase58, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            return extKey->getPublicPartAsBase58(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        }},
        {extkey_getPrivateKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            return extKey->getPrivateKey(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        }},
        {extkey_getPublicKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            return extKey->getPublicKey(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        }},
        {extkey_getPrivateEncKey, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            return extKey->getPrivateEncKey(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        }},
        {extkey_getPublicKeyAsBase58Address, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            return extKey->getPublicKeyAsBase58Address(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        }},
        {extkey_getChainCode, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            return extKey->getChainCode(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        }},
        {extkey_verifyCompactSignatureWithHash, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 3);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            Poco::JSON::Array::Ptr subArgs = new Poco::JSON::Array();
            subArgs->add(argsArr->get(1));
            subArgs->add(argsArr->get(2));
            return extKey->verifyCompactSignatureWithHash(subArgs);
        }},
        {extkey_isPrivate, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            auto argsArr = core::VarInterfaceUtil::validateAndExtractArray(args, 1);
            auto extKey = reinterpret_cast<crypto::ExtKeyVarInterface*>((intptr_t)argsArr->get(0).convert<int64_t>());
            return extKey->isPrivate(Poco::JSON::Array::Ptr(new Poco::JSON::Array()));
        }},
        {event_emitEvent, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->eventApi->emitEvent(args);
        }},
        {event_subscribeFor, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->eventApi->subscribeFor(args);
        }},
        {event_unsubscribeFrom, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->eventApi->unsubscribeFrom(args);
        }},
        {event_buildSubscriptionQuery, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->eventApi->buildSubscriptionQuery(args);
        }},
        {thread_createThread, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->createThread(args);
        }},
        {thread_updateThread, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->updateThread(args);
        }},
        {thread_rotateThreadKeys, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->rotateThreadKeys(args);
        }},
        {thread_getThread, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->getThread(args);
        }},
        {thread_listThreads, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->listThreads(args);
        }},
        {thread_deleteThread, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->deleteThread(args);
        }},
        {thread_sendMessage, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->sendMessage(args);
        }},
        {thread_updateMessage, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->updateMessage(args);
        }},
        {thread_getMessage, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->getMessage(args);
        }},
        {thread_listMessages, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->listMessages(args);
        }},
        {thread_deleteMessage, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->deleteMessage(args);
        }},
        {thread_subscribeFor, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->subscribeFor(args);
        }},
        {thread_unsubscribeFrom, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->unsubscribeFrom(args);
        }},
        {thread_buildSubscriptionQuery, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->thread->buildSubscriptionQuery(args);
        }},
        {store_createStore, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->createStore(args);
        }},
        {store_updateStore, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->updateStore(args);
        }},
        {store_rotateStoreKeys, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->rotateStoreKeys(args);
        }},
        {store_getStore, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->getStore(args);
        }},
        {store_listStores, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->listStores(args);
        }},
        {store_deleteStore, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->deleteStore(args);
        }},
        {store_createFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->createFile(args);
        }},
        {store_updateFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->updateFile(args);
        }},
        {store_updateFileMeta, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->updateFileMeta(args);
        }},
        {store_getFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->getFile(args);
        }},
        {store_listFiles, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->listFiles(args);
        }},
        {store_deleteFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->deleteFile(args);
        }},
        {store_openFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->openFile(args);
        }},
        {store_readFromFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->readFromFile(args);
        }},
        {store_writeToFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->writeToFile(args);
        }},
        {store_seekInFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->seekInFile(args);
        }},
        {store_closeFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->closeFile(args);
        }},
        {store_syncFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->syncFile(args);
        }},
        {store_subscribeFor, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->subscribeFor(args);
        }},
        {store_unsubscribeFrom, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->unsubscribeFrom(args);
        }},
        {store_buildSubscriptionQuery, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->store->buildSubscriptionQuery(args);
        }},
        {inbox_createInbox, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->createInbox(args);
        }},
        {inbox_updateInbox, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->updateInbox(args);
        }},
        {inbox_rotateInboxKeys, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->rotateInboxKeys(args);
        }},
        {inbox_getInbox, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->getInbox(args);
        }},
        {inbox_listInboxes, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->listInboxes(args);
        }},
        {inbox_deleteInbox, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->deleteInbox(args);
        }},
        {inbox_getInboxPublicView, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->getInboxPublicView(args);
        }},
        {inbox_getInboxPublicView, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->deleteInbox(args);
        }},
        {inbox_prepareEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->prepareEntry(args);
        }},
        {inbox_sendEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->sendEntry(args);
        }},
        {inbox_readEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->readEntry(args);
        }},
        {inbox_listEntries, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->listEntries(args);
        }},
        {inbox_deleteEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->deleteEntry(args);
        }},
        {inbox_createFileHandle, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->createFileHandle(args);
        }},
        {inbox_writeToFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->writeToFile(args);
        }},
        {inbox_openFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->openFile(args);
        }},
        {inbox_readFromFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->readFromFile(args);
        }},
        {inbox_seekInFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->seekInFile(args);
        }},
        {inbox_closeFile, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->closeFile(args);
        }},
        {inbox_subscribeFor, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->subscribeFor(args);
        }},
        {inbox_unsubscribeFrom, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->unsubscribeFrom(args);
        }},
        {inbox_buildSubscriptionQuery, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->inbox->buildSubscriptionQuery(args);
        }},
        {kvdb_createKvdb, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->createKvdb(args);
        }},
        {kvdb_updateKvdb, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->updateKvdb(args);
        }},
        {kvdb_rotateKvdbKeys, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->rotateKvdbKeys(args);
        }},
        {kvdb_deleteKvdb, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->deleteKvdb(args);
        }},
        {kvdb_getKvdb, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->getKvdb(args);
        }},
        {kvdb_listKvdbs, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->listKvdbs(args);
        }},
        {kvdb_getEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->getEntry(args);
        }},
        {kvdb_listEntriesKeys, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->listEntriesKeys(args);
        }},
        {kvdb_listEntries, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->listEntries(args);
        }},
        {kvdb_setEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->setEntry(args);
        }},
        {kvdb_deleteEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->deleteEntry(args);
        }},
        {kvdb_deleteEntries, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->deleteEntries(args);
        }},
        {kvdb_hasEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->hasEntry(args);
        }},
        {kvdb_subscribeFor, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->subscribeFor(args);
        }},
        {kvdb_unsubscribeFrom, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->unsubscribeFrom(args);
        }},
        {kvdb_buildSubscriptionQuery, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->buildSubscriptionQuery(args);
        }},
        {kvdb_buildSubscriptionQueryForSelectedEntry, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->kvdb->buildSubscriptionQueryForSelectedEntry(args);
        }},
        {group_createGroupWithKeyTree, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->createGroupWithKeyTree(args);
        }},
        {group_addGroupMember, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->addGroupMember(args);
        }},
        {group_removeGroupMember, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->removeGroupMember(args);
        }},
        {group_updateGroup, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->updateGroup(args);
        }},
        {group_deleteGroup, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->deleteGroup(args);
        }},
        {group_getGroup, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->getGroup(args);
        }},
        {group_listGroups, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->listGroups(args);
        }},
        {group_subscribeFor, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->subscribeFor(args);
        }},
        {group_unsubscribeFrom, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->unsubscribeFrom(args);
        }},
        {group_buildSubscriptionQuery, [](std::shared_ptr<ApiVar> api, const Poco::JSON::Array::Ptr& args) -> Poco::Dynamic::Var{
            return api->group->buildSubscriptionQuery(args);
        }},
    };

    const std::unordered_map<func_enum, std::string> functions_endpoint_help_description = {
        {config_setCertsPath, 
            "setCertsPath JSON_ARRAY\n"
            "\tjson format - [certsPath]\n"
            "\t\tcertsPath [STRING] - filesystem's path to certs file"
        },
        {core_waitEvent, 
            "waitEvent JSON_ARRAY\n"
            "\tjson format - []\n"
            "\talways run in new thread (works only in -i mode)"
        },
        {core_getEvent, 
            "getEvent JSON_ARRAY\n"
            "\tjson format - []"
        },
        {core_emitBreakEvent, 
            "emitBreakEvent JSON_ARRAY\n"
            "\tjson format - []"
        },
        {core_connect, 
            "connect JSON_ARRAY\n"
            "\tjson format - [userPrivKey, solutionId, platformUrl]\n"
            "\t\tuserPrivKey [STRING] - user's private key in WIF format\n"
            "\t\tsolutionId [STRING] - ID of the Solution\n"
            "\t\tplatformUrl [STRING] - Platform's Endpoint URL"
        },
        {core_connectPublic, 
            "connectPublic JSON_ARRAY\n"
            "\tjson format - [solutionId, platformUrl]\n"
            "\t\tsolutionId [STRING] - ID of the Solution\n"
            "\t\tplatformUrl [STRING] - Platform's Endpoint URL"
        },
        {core_disconnect, 
            "platformDisconnect JSON_ARRAY\n"
            "\tjson format - []"
        },
        {core_getConnectionId, 
            "platformDisconnect JSON_ARRAY\n"
            "\tjson format - []"
        },
        {core_listContexts, 
            "listContexts JSON_ARRAY\n"
            "\tjson format - [pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tpagingQuery [OBJECT] - list query parameters\n"
            "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
            "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
            "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
            "\t\t\tlastId [STRING] - ID of the element from which query results should start"
        },
        {core_backendRequest, 
            "backendRequest JSON_ARRAY\n"
            "\tjson format - [serverUrl, accessToken, method, paramsAsJson]\n"
            "\t\tserverUrl [STRING] - PrivMX Bridge server URL\n"
            "\t\taccessToken [STRING] - token for authorization (see PrivMX Bridge API for more details)\n"
            "\t\tmethod [STRING] - API method to call\n"
            "\t\tparamsAsJson [STRING] - API method's parameters in JSON format\n"
            "\tjson format - [serverUrl, method, paramsAsJson]\n"
            "\t\tserverUrl [STRING] - PrivMX Bridge server URL\n"
            "\t\tmethod [STRING] - API method to call\n"
            "\t\tparamsAsJson [STRING] - API method's parameters in JSON format\n"
            "\tjson format - [serverUrl, apiKeyId, apiKeySecret, mode, method, paramsAsJson]\n"
            "\t\tserverUrl [STRING] - PrivMX Bridge server URL\n"
            "\t\tapiKeyId [STRING] - API KEY ID (see PrivMX Bridge API for more details)\n"
            "\t\tapiKeySecret [STRING] - API KEY SECRET (see PrivMX Bridge API for more details)\n"
            "\t\tmode [NUMBER] - allows you to set whether the request should be signed (mode = 1) or plain (mode = 0)\n"
            "\t\tmethod [STRING] - API method to call\n"
            "\t\tparamsAsJson [STRING] - API method's parameters in JSON format"
        },
        {crypto_signData, 
            "signData JSON_ARRAY\n"
            "\tjson format - [data, privateKey]\n"
            "\t\tdata [BUFFER] - buffer to sign\n"
            "\t\tprivateKey  [STRING] - key used to sign data in WIF format"
        },
        {crypto_verifySignature, 
            "verifySignature JSON_ARRAY\n"
            "\tjson format - [data, signature, publicKey]\n"
            "\t\tdata [BUFFER] - buffer\n"
            "\t\tsignature [BUFFER] - signature of data to verify\n"
            "\t\tpublicKey [STRING] - public ECC key in BASE58DER format used to validate data"
        },
        {crypto_generatePrivateKey, 
            "generatePrivateKey JSON_ARRAY\n"
            "\tjson format - [randomSeed?]\n"
            "\t\trandomSeed [STRING] - string used as the base to generate the new key"
        },
        {crypto_derivePrivateKey, 
            "derivePrivateKey JSON_ARRAY\n"
            "\tjson format - [password, salt]\n"
            "\t\tpassword [STRING] - the password used to generate the new key\n"
            "\t\tsalt [STRING] - random string (additional input for the hashing function)"
        },
        {crypto_derivePublicKey, 
            "derivePublicKey JSON_ARRAY\n"
            "\tjson format - [privatekey]\n"
            "\t\tprivatekey [STRING] - private ECC key in WIF format"
        },
        {crypto_generateKeySymmetric, 
            "generateKeySymmetric JSON_ARRAY\n"
            "\tjson format - []"
        },
        {crypto_encryptDataSymmetric, 
            "encryptDataSymmetric JSON_ARRAY\n"
            "\tjson format - [data, symmetricKey]\n"
            "\t\tdata [BUFFER] - buffer to encrypt\n"
            "\t\tsymmetricKey [STRING] - key used to encrypt data"
        },
        {crypto_decryptDataSymmetric,
            "decryptDataSymmetric JSON_ARRAY\n"
            "\tjson format - [data, symmetricKey]\n"
            "\t\tdata [BUFFER] - buffer to decrypt\n"
            "\t\tsymmetricKey [STRING] - key used to decrypt data"
        },
        {crypto_convertPEMKeytoWIFKey, 
            "convertPEMKeytoWIFKey JSON_ARRAY\n"
            "\tjson format - [pemKey]\n"
            "\t\tpemKey [STRING] - private key to convert"
        },
        {thread_createThread,
            "createThread JSON_ARRAY\n"
            "\tjson format - [contextId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, policies?, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tcontextId [STRING] - ID of the Context to create the Thread in\n"
            "\t\tusers [ARRAY] - vector of UserWithPubKey structs which indicates who will have access to the created Thread\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [STRING] - vector of UserWithPubKey structs which indicates who will have access (and management rights) to the created Thread\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tpolicies [OBJECT] - (optional) Thread's policies (ContainerPolicy)\n"
            "\t\tgroups [ARRAY] - groups granted access to the Thread; pass [] for none\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER); \"\" to read it from the Bridge\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at; 0 to read it from the Bridge"
        },
        {thread_updateThread,
            "updateThread JSON_ARRAY\n"
            "\tjson format - [threadId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, version, force, forceGenerateNewKey, policies?, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tthreadId [STRING] - ID of the Thread to update\n"
            "\t\tusers [ARRAY] - vector of UserWithPubKey which indicates who will have access to the updated Thread\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] - vector of UserWithPubKey which indicates who will have access (and management rights) to the updated Thread\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tversion [NUMBER] - current version of the updated Thread\n"
            "\t\tforce [BOOL] - force update (without checking version)\n"
            "\t\tforceGenerateNewKey [BOOL] - force to regenerate a key for the Thread\n"
            "\t\tpolicies [OBJECT] - (optional) Thread's policies (ContainerPolicy)\n"
            "\t\tgroups [ARRAY] - groups granted access to the Thread; authoritative, so [] revokes every group grant\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER); \"\" to read it from the Bridge\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at; 0 to read it from the Bridge"
            },
        {thread_rotateThreadKeys,
            "rotateThreadKeys JSON_ARRAY\n"
            "\tjson format - [threadId, users:[{userId, pubKey}], managers:[{userId, pubKey}], version, force, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tthreadId [STRING] - ID of the Thread to re-key\n"
            "\t\tusers [ARRAY] - current Thread users with their public keys\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] - current Thread managers with their public keys\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tversion [NUMBER] - current Thread version (optimistic lock guard)\n"
            "\t\tforce [BOOL] - skip the version check\n"
            "\t\tgroups [ARRAY] - epoch public keys the caller has verified itself; pass [] to read them all from the Bridge. A re-key changes no grants, so groups the Thread does not grant are ignored\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER)\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at"
        },
        {thread_getThread, 
            "getThread JSON_ARRAY\n"
            "\tjson format - [threadId]\n"
            "\t\tthreadId [STRING] - ID of Thread to get"
        },
        {thread_listThreads, 
            "listThreads JSON_ARRAY\n"
            "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tcontextId [STRING] - ID of the Context to get the Threads from\n"
            "\t\tpagingQuery [OBJECT] - list query parameters\n"
            "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
            "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
            "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
            "\t\t\tlastId [STRING] - ID of the element from which query results should start"
        },
        {thread_deleteThread, 
            "deleteThread JSON_ARRAY\n"
            "\tjson format - [threadId]\n"
            "\t\tthreadId [STRING] - ID of the Thread to delete"
        },
        {thread_sendMessage, 
            "sendMessage JSON_ARRAY\n"
            "\tjson format - [threadId, publicMeta, privateMeta, data]\n"
            "\t\tthreadId [STRING] - ID of the Thread to send message to\n"
            "\t\tpublicMeta [BUFFER] - public message metadata\n"
            "\t\tprivateMeta [BUFFER] - private message metadata\n"
            "\t\tprivateMeta [BUFFER] - content of the message"
        },
        {thread_updateMessage, 
            "updateMessage JSON_ARRAY\n"
            "\tjson format - [messageId, publicMeta, privateMeta, data]\n"
            "\t\tmessageId [STRING] - ID of the message to update\n"
            "\t\tpublicMeta [BUFFER] - public message metadata\n"
            "\t\tprivateMeta [BUFFER] - private message metadata\n"
            "\t\tprivateMeta [BUFFER] - content of the message"
        },
        {thread_getMessage, 
            "getMessage JSON_ARRAY\n"
            "\tjson format - [messageId]\n"
            "\t\tmessageId [STRING] - ID of the message to get"
        },
        {thread_listMessages, 
            "listMessages JSON_ARRAY\n"
            "\tjson format - [threadId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tthreadId [STRING] - ID of the Thread to list messages from\n"
            "\t\tpagingQuery [OBJECT] - list query parameters\n"
            "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
            "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
            "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
            "\t\t\tlastId [STRING] - ID of the element from which query results should start"
        },
        {thread_deleteMessage, 
            "deleteMessage JSON_ARRAY\n"
            "\tjson format - [messageId]\n"
            "\t\tmessageId [STRING] - ID of the message to delete"
        },
        {store_createStore, 
            "createStore JSON_ARRAY\n"
            "\tjson format - [contextId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, policies?, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tcontextId [STRING] - ID of the Context to create the Store in\n"
            "\t\tusers [ARRAY] - vector of UserWithPubKey structs which indicates who will have access to the created Store\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [STRING] - vector of UserWithPubKey structs which indicates who will have access (and management rights) to the created Store\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tpolicies [OBJECT] - (optional) Store's policies (ContainerPolicy)\n"
            "\t\tgroups [ARRAY] - groups granted access to the Store; pass [] for none\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER); \"\" to read it from the Bridge\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at; 0 to read it from the Bridge"
        },
        {store_updateStore,
            "updateStore JSON_ARRAY\n"
            "\tjson format - [storeId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, version, force, forceGenerateNewKey, policies?, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tstoreId [STRING] - ID of the Store to update\n"
            "\t\tusers [ARRAY] - vector of UserWithPubKey structs which indicates who will have access to the updated Store\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [STRING] - vector of UserWithPubKey structs which indicates who will have access (and management rights) to the updated Store\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tversion [NUMBER] - current version of the updated Store\n"
            "\t\tforce [BOOL] - force update (without checking version)\n"
            "\t\tforceGenerateNewKey [BOOL] - force to regenerate a key for the Store\n"
            "\t\tpolicies [OBJECT] - (optional) Store's policies (ContainerPolicy)\n"
            "\t\tgroups [ARRAY] - groups granted access to the Store; authoritative, so [] revokes every group grant\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER); \"\" to read it from the Bridge\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at; 0 to read it from the Bridge"
        },
        {store_rotateStoreKeys,
            "rotateStoreKeys JSON_ARRAY\n"
            "\tjson format - [storeId, users:[{userId, pubKey}], managers:[{userId, pubKey}], version, force, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tstoreId [STRING] - ID of the Store to re-key\n"
            "\t\tusers [ARRAY] - current Store users with their public keys\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] - current Store managers with their public keys\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tversion [NUMBER] - current Store version (optimistic lock guard)\n"
            "\t\tforce [BOOL] - skip the version check\n"
            "\t\tgroups [ARRAY] - epoch public keys the caller has verified itself; pass [] to read them all from the Bridge. A re-key changes no grants, so groups the Store does not grant are ignored\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER)\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at"
        },
        {store_getStore,
            "getStore JSON_ARRAY\n"
            "\tjson format - [storeId]\n"
            "\t\tstoreId [STRING] - ID of the Store to get"
        },
        {store_listStores, 
            "listStores JSON_ARRAY\n"
            "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tcontextId [STRING] - ID of the Context to get the Stores from\n"
            "\t\tpagingQuery [OBJECT] - list query parameters\n"
            "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
            "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
            "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
            "\t\t\tlastId [STRING] - ID of the element from which query results should start"
        },
        {store_deleteStore, 
            "deleteStore JSON_ARRAY\n"
            "\tjson format - [storeId]\n"
            "\t\tstoreId [STRING] - ID of the Store to delete"
        },
        {store_createFile, 
            "createFile JSON_ARRAY\n"
            "\tjson format - [storeId, publicMeta, privateMeta, size]\n"
            "\t\tstoreId [STRING] - ID of the Store to create the file in\n"
            "\t\tpublicMeta [BUFFER] - public file metadata\n"
            "\t\tprivateMeta [BUFFER] - private file metadata\n"
            "\t\tsize [NUMBER] - size of the file"
        },
        {store_updateFile, 
            "updateFile JSON_ARRAY\n"
            "\tjson format - [fileId, publicMeta, privateMeta, size]\n"
            "\t\tfileId [STRING] - ID of the file to update\n"
            "\t\tpublicMeta [BUFFER] - public file metadata\n"
            "\t\tprivateMeta [BUFFER] - private file metadata\n"
            "\t\tsize [NUMBER] - size of the file"
        },
        {store_updateFileMeta, 
            "updateFileMeta JSON_ARRAY\n"
            "\tjson format - [fileId, publicMeta, privateMeta]\n"
            "\t\tfileId [STRING] - ID of the file to update\n"
            "\t\tpublicMeta [BUFFER] - public file metadata\n"
            "\t\tprivateMeta [BUFFER] - private file metadata"
        },
        {store_getFile, 
            "getFile JSON_ARRAY\n"
            "\tjson format - [fileId]\n"
            "\t\tfileId [STRING] - ID of the file to get"
        },
        {store_listFiles, 
            "listFiles JSON_ARRAY\n"
            "\tjson format - [storeId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tstoreId [STRING] - ID of the Store to get files from\n"
            "\t\tpagingQuery [OBJECT] - list query parameters\n"
            "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
            "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
            "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
            "\t\t\tlastId [STRING] - ID of the element from which query results should start"
        },
        {store_deleteFile, 
            "deleteFile JSON_ARRAY\n"
            "\tjson format - [fileId]\n"
            "\t\tfileId [STRING] - ID of the file to delete"
        },
        {store_openFile, 
            "openFile JSON_ARRAY\n"
            "\tjson format - [fileId]\n"
            "\t\tfileId [STRING] - ID of the file to read"
        },
        {store_readFromFile, 
            "readFromFile JSON_ARRAY\n"
            "\tjson format - [fileHandle, length]\n"
            "\t\tfileHandle [NUMBER] - handle to read file data\n"
            "\t\tlength [NUMBER] - size of data to read"
        },
        {store_writeToFile, 
            "writeToFile JSON_ARRAY\n"
            "\tjson format - [fileHandle, dataChunk]\n"
            "\t\tfileHandle [NUMBER] - handle to write file data\n"
            "\t\tdataChunk [BUFFER] - file data chunk"
        },
        {store_seekInFile, 
            "seekInFile JSON_ARRAY\n"
            "\tjson format - [fileHandle, position]\n"
            "\t\tfileHandle [NUMBER] - handle to read file data\n"
            "\t\tposition [NUMBER] - new cursor position"
        },
        {store_closeFile, 
            "closeFile JSON_ARRAY\n"
            "\tjson format - [fileHandle]\n"
            "\t\tfileHandle [NUMBER] - handle to read/write file data"
        },
        {inbox_createInbox, 
            "createInbox JSON_ARRAY\n"
            "\tjson format - [contextId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, filesConfig?:{minCount, maxCount, maxFileSize, maxWholeUploadSize}, policies?, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tcontextId [STRING] - ID of the Context of the new Inbox\n"
            "\t\tusers [ARRAY] -  vector of UserWithPubKey which indicates who will have access to the created Inbox\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] -  vector of UserWithPubKey which indicates who will have access (and management rights) to the created Inbox\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tfilesConfig [OBJECT] - (optional) to override default file configuration\n"
            "\t\t\tminCount [NUMBER] - minimum number of files required when sending inbox entry\n"
            "\t\t\tmaxCount [NUMBER] - maximum number of files allowed when sending inbox entry\n"
            "\t\t\tmaxFileSize [NUMBER] - maximum file size allowed when sending inbox entry\n"
            "\t\t\tmaxWholeUploadSize [NUMBER] - maximum size of all files in total allowed when sending inbox entry\n"
            "\t\tpolicies [OBJECT] - (optional) Inbox's policies (ContainerPolicyWithoutItem)\n"
            "\t\tgroups [ARRAY] - groups granted access to the Inbox and to its inner Thread and Store; pass [] for none\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER); \"\" to read it from the Bridge\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at; 0 to read it from the Bridge"
        },
        {inbox_updateInbox,
            "updateInbox JSON_ARRAY\n"
            "\tjson format - [inboxId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, filesConfig?:{minCount, maxCount, maxFileSize, maxWholeUploadSize}, version, force, forceGenerateNewKey, policies?, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tinboxId [STRING] - ID of the Inbox to update\n"
            "\t\tusers [ARRAY] -  vector of UserWithPubKey which indicates who will have access to the updated Inbox\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] -  vector of UserWithPubKey which indicates who will have access (and management rights) to the updated Inbox\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tfilesConfig [OBJECT] - (optional) to override default file configuration\n"
            "\t\t\tminCount [NUMBER] - minimum number of files required when sending inbox entry\n"
            "\t\t\tmaxCount [NUMBER] - maximum number of files allowed when sending inbox entry\n"
            "\t\t\tmaxFileSize [NUMBER] - maximum file size allowed when sending inbox entry\n"
            "\t\t\tmaxWholeUploadSize [NUMBER] - maximum size of all files in total allowed when sending inbox entry\n"
            "\t\tversion [NUMBER] - current version of the updated Inbox\n"
            "\t\tforce [BOOL] - force update (without checking version)\n"
            "\t\tforceGenerateNewKey [BOOL] - force to regenerate a key for the Inbox\n"
            "\t\tpolicies [OBJECT] - (optional) Inbox's policies (ContainerPolicyWithoutItem)\n"
            "\t\tgroups [ARRAY] - groups granted access to the Inbox and to its inner Thread and Store; authoritative, so [] revokes every group grant on all three\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER); \"\" to read it from the Bridge\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at; 0 to read it from the Bridge"
        },
        {inbox_rotateInboxKeys,
            "rotateInboxKeys JSON_ARRAY\n"
            "\tjson format - [inboxId, users:[{userId, pubKey}], managers:[{userId, pubKey}], version, force, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tinboxId [STRING] - ID of the Inbox to re-key; its inner Thread and Store are re-keyed too\n"
            "\t\tusers [ARRAY] - current Inbox users with their public keys\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] - current Inbox managers with their public keys\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tversion [NUMBER] - current Inbox version (optimistic lock guard); the inner Thread and Store are re-keyed at whatever version they currently hold\n"
            "\t\tforce [BOOL] - skip the version check\n"
            "\t\tgroups [ARRAY] - epoch public keys the caller has verified itself; pass [] to read them all from the Bridge. A re-key changes no grants, so groups the Inbox does not grant are ignored\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER)\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at"
        },
        {inbox_getInbox,
            "getInbox JSON_ARRAY\n"
            "\tjson format - [inboxId]\n"
            "\t\tinboxId [STRING] - ID of the Inbox to get"
        },
        {inbox_listInboxes, 
            "listInboxes JSON_ARRAY\n"
            "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tcontextId [STRING] - ID of the Context to get the Inboxes from\n"
            "\t\tpagingQuery [OBJECT] - list query parameters\n"
            "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
            "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
            "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
            "\t\t\tlastId [STRING] - ID of the element from which query results should start"
        },
        {inbox_deleteInbox, 
            "deleteInbox JSON_ARRAY\n"
            "\tjson format - [inboxId]\n"
            "\t\tinboxId [STRING] - ID of the Inbox to delete"
        },
        {inbox_getInboxPublicView, 
            "getInboxPublicView JSON_ARRAY\n"
            "\tjson format - [inboxId]\n"
            "\t\tinboxId [STRING] - ID of the Inbox to get"
        },
        {inbox_prepareEntry, 
            "prepareEntry JSON_ARRAY\n"
            "\tjson format - [inboxId, data, inboxFileHandles:[fileHandle], userPrivKey?]\n"
            "\t\tinboxId [STRING] - ID of the Inbox to which the request applies\n"
            "\t\tdata [BUFFER] - entry data to send\n"
            "\t\tinboxFileHandles [ARRAY] - list of file handles that will be sent with the request\n"
            "\t\t\tfileHandle [NUMBER] - write handle to the file\n"
            "\t\tuserPrivKey [STRING] - sender's private key which can be used later to encrypt data for that sender"
        },
        {inbox_sendEntry, 
            "sendEntry JSON_ARRAY\n"
            "\tjson format - [inboxHandle]\n"
            "\t\tinboxHandle [NUMBER] - ID of the Inbox to which the request applies"
        },
        {inbox_readEntry, 
            "readEntry JSON_ARRAY\n"
            "\tjson format - [entryId]\n"
            "\t\tentryId [STRING] - ID of an entry to read from the Inbox"
        },
        {inbox_listEntries, 
            "listEntries JSON_ARRAY\n"
            "\tjson format - [inboxId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tinboxId [STRING] - ID of the Inbox\n"
            "\t\tpagingQuery [OBJECT] - list query parameters\n"
            "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
            "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
            "\t\t\tsortOrder [NUMBER] - order of elements in result (\"asc\" for ascending, \"desc\" for descending)\n"
            "\t\t\tlastId [STRING] - ID of the element from which query results should start"
        },
        {inbox_deleteEntry, 
            "deleteEntry JSON_ARRAY\n"
            "\tjson format - [entryId]\n"
            "\t\tentryId [STRING] - ID of an entry to delete"
        },
        {inbox_createFileHandle, 
            "createFileHandle JSON_ARRAY\n"
            "\tjson format - [publicMeta, privateMeta, fileSize]\n"
            "\t\tpublicMeta [BUFFER] - file's public metadata\n"
            "\t\tprivateMeta [BUFFER] - file's private metadata\n"
            "\t\tfileSize [NUMBER] - size of the file to send"
        },
        {inbox_writeToFile, 
            "writeToFile JSON_ARRAY\n"
            "\tjson format - [inboxHandle, fileHandle, dataChunk]\n"
            "\t\tinboxHandle [NUMBER] - ID of the Inbox to which the request applies\n"
            "\t\tfileHandle [NUMBER] - handle to the file where the uploaded chunk belongs\n"
            "\t\tdataChunk [BUFFER] - dataChunk - file chunk to send"
        },
        {inbox_openFile,
            "openFile JSON_ARRAY\n"
            "\tjson format - [fileId]\n"
            "\t\tfileId [STRING] - ID of the file to read"
        },
        {inbox_readFromFile, 
            "readFromFile JSON_ARRAY\n"
            "\tjson format - [fileHandle, length]\n"
            "\t\tfileHandle [NUMBER] - handle to the file\n"
            "\t\tlength [NUMBER] - size of data to read"
        },
        {inbox_seekInFile, 
            "seekInFile JSON_ARRAY\n"
            "\tjson format - [fileHandle, position]\n"
            "\t\tfileHandle [NUMBER] - handle to the file\n"
            "\t\tposition [NUMBER] - sets new cursor position"
        },
        {inbox_closeFile,
            "closeFile JSON_ARRAY\n"
            "\tjson format - [fileHandle]\n"
            "\t\tfileHandle [NUMBER] - handle to the file"
        },
        {core_listContextUsers,
            "listContextUsers JSON_ARRAY\n"
            "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tcontextId [STRING] - ID of the Context\n"
            "\t\tpagingQuery [OBJECT] - list query parameters"
        },
        {core_subscribeFor,
            "subscribeFor JSON_ARRAY\n"
            "\tjson format - [subscriptionQueries:[query]]\n"
            "\t\tsubscriptionQueries [ARRAY] - list of subscription query strings (see buildSubscriptionQuery)\n"
            "\t\t\tquery [STRING] - single subscription query\n"
            "\treturns a list of subscriptionIds in matching order to subscriptionQueries"
        },
        {core_unsubscribeFrom,
            "unsubscribeFrom JSON_ARRAY\n"
            "\tjson format - [subscriptionIds:[subscriptionId]]\n"
            "\t\tsubscriptionIds [ARRAY] - list of subscriptionIds to unsubscribe from\n"
            "\t\t\tsubscriptionId [STRING] - single subscriptionId"
        },
        {core_buildSubscriptionQuery,
            "buildSubscriptionQuery JSON_ARRAY\n"
            "\tjson format - [eventType, selectorType, selectorId]\n"
            "\t\teventType [NUMBER] - type of event to listen for (core::EventType enum value)\n"
            "\t\tselectorType [NUMBER] - scope on which to listen for events (core::EventSelectorType enum value)\n"
            "\t\tselectorId [STRING] - ID of the selector"
        },
        {utils_encodeHex,
            "encodeHex JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [BUFFER] - buffer to encode"
        },
        {utils_decodeHex,
            "decodeHex JSON_ARRAY\n"
            "\tjson format - [hex_data]\n"
            "\t\thex_data [STRING] - Hex string to decode"
        },
        {utils_isHex,
            "isHex JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [STRING] - string to check"
        },
        {utils_encodeBase32,
            "encodeBase32 JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [BUFFER] - buffer to encode"
        },
        {utils_decodeBase32,
            "decodeBase32 JSON_ARRAY\n"
            "\tjson format - [base32_data]\n"
            "\t\tbase32_data [STRING] - Base32 string to decode"
        },
        {utils_isBase32,
            "isBase32 JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [STRING] - string to check"
        },
        {utils_encodeBase64,
            "encodeBase64 JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [BUFFER] - buffer to encode"
        },
        {utils_decodeBase64,
            "decodeBase64 JSON_ARRAY\n"
            "\tjson format - [base64_data]\n"
            "\t\tbase64_data [STRING] - Base64 string to decode"
        },
        {utils_isBase64,
            "isBase64 JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [STRING] - string to check"
        },
        {utils_trim,
            "trim JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [STRING] - string to trim of leading and trailing whitespace"
        },
        {utils_split,
            "split JSON_ARRAY\n"
            "\tjson format - [data, delimiter]\n"
            "\t\tdata [STRING] - string to split\n"
            "\t\tdelimiter [STRING] - delimiter to split on (removed from output)"
        },
        {utils_ltrim,
            "ltrim JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [STRING] - string to trim of leading whitespace"
        },
        {utils_rtrim,
            "rtrim JSON_ARRAY\n"
            "\tjson format - [data]\n"
            "\t\tdata [STRING] - string to trim of trailing whitespace"
        },
        {crypto_fromMnemonic,
            "fromMnemonic JSON_ARRAY\n"
            "\tjson format - [mnemonic, password]\n"
            "\t\tmnemonic [STRING] - the BIP-39 mnemonic used to generate the key\n"
            "\t\tpassword [STRING] - the password used to generate the key\n"
            "\treturns a BIP39 object (privateKey, publicKey, mnemonic, entropy) plus an extKey handle"
        },
        {crypto_fromEntropy,
            "fromEntropy JSON_ARRAY\n"
            "\tjson format - [entropy, password]\n"
            "\t\tentropy [BUFFER] - the BIP-39 entropy used to generate the key\n"
            "\t\tpassword [STRING] - the password used to generate the key\n"
            "\treturns a BIP39 object (privateKey, publicKey, mnemonic, entropy) plus an extKey handle"
        },
        {crypto_entropyToMnemonic,
            "entropyToMnemonic JSON_ARRAY\n"
            "\tjson format - [entropy]\n"
            "\t\tentropy [BUFFER] - the BIP-39 entropy to convert"
        },
        {crypto_mnemonicToEntropy,
            "mnemonicToEntropy JSON_ARRAY\n"
            "\tjson format - [mnemonic]\n"
            "\t\tmnemonic [STRING] - the BIP-39 mnemonic to convert"
        },
        {crypto_mnemonicToSeed,
            "mnemonicToSeed JSON_ARRAY\n"
            "\tjson format - [mnemonic, password]\n"
            "\t\tmnemonic [STRING] - the BIP-39 mnemonic\n"
            "\t\tpassword [STRING] - the password used to generate the seed"
        },
        {extkey_fromSeed,
            "fromSeed JSON_ARRAY\n"
            "\tjson format - [seed]\n"
            "\t\tseed [BUFFER] - the seed used to generate the ExtKey\n"
            "\treturns an extKey handle (NUMBER) used as the first argument of the other extkey.* methods"
        },
        {extkey_fromBase58,
            "fromBase58 JSON_ARRAY\n"
            "\tjson format - [base58]\n"
            "\t\tbase58 [STRING] - the ExtKey in Base58 format\n"
            "\treturns an extKey handle (NUMBER)"
        },
        {extkey_generateRandom,
            "generateRandom JSON_ARRAY\n"
            "\tjson format - []\n"
            "\treturns an extKey handle (NUMBER)"
        },
        {extkey_derive,
            "derive JSON_ARRAY\n"
            "\tjson format - [extKey, index]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance (from fromSeed/fromBase58/generateRandom/derive/deriveHardened or crypto.fromMnemonic/fromEntropy)\n"
            "\t\tindex [NUMBER] - BIP32 child index\n"
            "\treturns a new extKey handle (NUMBER)"
        },
        {extkey_deriveHardened,
            "deriveHardened JSON_ARRAY\n"
            "\tjson format - [extKey, index]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance\n"
            "\t\tindex [NUMBER] - BIP32 hardened child index\n"
            "\treturns a new extKey handle (NUMBER)"
        },
        {extkey_getPrivatePartAsBase58,
            "getPrivatePartAsBase58 JSON_ARRAY\n"
            "\tjson format - [extKey]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance"
        },
        {extkey_getPublicPartAsBase58,
            "getPublicPartAsBase58 JSON_ARRAY\n"
            "\tjson format - [extKey]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance"
        },
        {extkey_getPrivateKey,
            "getPrivateKey JSON_ARRAY\n"
            "\tjson format - [extKey]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance\n"
            "\treturns the ECC private key in WIF format"
        },
        {extkey_getPublicKey,
            "getPublicKey JSON_ARRAY\n"
            "\tjson format - [extKey]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance\n"
            "\treturns the ECC public key in BASE58DER format"
        },
        {extkey_getPrivateEncKey,
            "getPrivateEncKey JSON_ARRAY\n"
            "\tjson format - [extKey]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance\n"
            "\treturns the raw ECC private key (BUFFER)"
        },
        {extkey_getPublicKeyAsBase58Address,
            "getPublicKeyAsBase58Address JSON_ARRAY\n"
            "\tjson format - [extKey]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance"
        },
        {extkey_getChainCode,
            "getChainCode JSON_ARRAY\n"
            "\tjson format - [extKey]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance\n"
            "\treturns the raw chain code (BUFFER)"
        },
        {extkey_verifyCompactSignatureWithHash,
            "verifyCompactSignatureWithHash JSON_ARRAY\n"
            "\tjson format - [extKey, message, signature]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance\n"
            "\t\tmessage [BUFFER] - data used for validation\n"
            "\t\tsignature [BUFFER] - signature of the data to verify"
        },
        {extkey_isPrivate,
            "isPrivate JSON_ARRAY\n"
            "\tjson format - [extKey]\n"
            "\t\textKey [NUMBER] - handle to an ExtKey instance"
        },
        {event_emitEvent,
            "emitEvent JSON_ARRAY\n"
            "\tjson format - [contextId, users:[{userId, pubKey}], channelName, eventData]\n"
            "\t\tcontextId [STRING] - ID of the Context the event is emitted on\n"
            "\t\tusers [ARRAY] - recipients of the event\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tchannelName [STRING] - name of the channel\n"
            "\t\teventData [BUFFER] - event payload data"
        },
        {event_subscribeFor,
            "subscribeFor JSON_ARRAY\n"
            "\tjson format - [subscriptionQueries:[query]]\n"
            "\t\tsubscriptionQueries [ARRAY] - list of subscription query strings (see buildSubscriptionQuery)\n"
            "\t\t\tquery [STRING] - single subscription query\n"
            "\treturns a list of subscriptionIds in matching order to subscriptionQueries"
        },
        {event_unsubscribeFrom,
            "unsubscribeFrom JSON_ARRAY\n"
            "\tjson format - [subscriptionIds:[subscriptionId]]\n"
            "\t\tsubscriptionIds [ARRAY] - list of subscriptionIds to unsubscribe from\n"
            "\t\t\tsubscriptionId [STRING] - single subscriptionId"
        },
        {event_buildSubscriptionQuery,
            "buildSubscriptionQuery JSON_ARRAY\n"
            "\tjson format - [channelName, selectorType, selectorId]\n"
            "\t\tchannelName [STRING] - name of the channel\n"
            "\t\tselectorType [NUMBER] - scope on which to listen for events (event::EventSelectorType enum value)\n"
            "\t\tselectorId [STRING] - ID of the selector"
        },
        {thread_subscribeFor,
            "subscribeFor JSON_ARRAY\n"
            "\tjson format - [subscriptionQueries:[query]]\n"
            "\t\tsubscriptionQueries [ARRAY] - list of subscription query strings (see buildSubscriptionQuery)\n"
            "\t\t\tquery [STRING] - single subscription query\n"
            "\treturns a list of subscriptionIds in matching order to subscriptionQueries"
        },
        {thread_unsubscribeFrom,
            "unsubscribeFrom JSON_ARRAY\n"
            "\tjson format - [subscriptionIds:[subscriptionId]]\n"
            "\t\tsubscriptionIds [ARRAY] - list of subscriptionIds to unsubscribe from\n"
            "\t\t\tsubscriptionId [STRING] - single subscriptionId"
        },
        {thread_buildSubscriptionQuery,
            "buildSubscriptionQuery JSON_ARRAY\n"
            "\tjson format - [eventType, selectorType, selectorId]\n"
            "\t\teventType [NUMBER] - type of event to listen for (thread::EventType enum value)\n"
            "\t\tselectorType [NUMBER] - scope on which to listen for events (thread::EventSelectorType enum value)\n"
            "\t\tselectorId [STRING] - ID of the selector"
        },
        {store_syncFile,
            "syncFile JSON_ARRAY\n"
            "\tjson format - [fileHandle]\n"
            "\t\tfileHandle [NUMBER] - handle of the open file to synchronize"
        },
        {store_subscribeFor,
            "subscribeFor JSON_ARRAY\n"
            "\tjson format - [subscriptionQueries:[query]]\n"
            "\t\tsubscriptionQueries [ARRAY] - list of subscription query strings (see buildSubscriptionQuery)\n"
            "\t\t\tquery [STRING] - single subscription query\n"
            "\treturns a list of subscriptionIds in matching order to subscriptionQueries"
        },
        {store_unsubscribeFrom,
            "unsubscribeFrom JSON_ARRAY\n"
            "\tjson format - [subscriptionIds:[subscriptionId]]\n"
            "\t\tsubscriptionIds [ARRAY] - list of subscriptionIds to unsubscribe from\n"
            "\t\t\tsubscriptionId [STRING] - single subscriptionId"
        },
        {store_buildSubscriptionQuery,
            "buildSubscriptionQuery JSON_ARRAY\n"
            "\tjson format - [eventType, selectorType, selectorId]\n"
            "\t\teventType [NUMBER] - type of event to listen for (store::EventType enum value)\n"
            "\t\tselectorType [NUMBER] - scope on which to listen for events (store::EventSelectorType enum value)\n"
            "\t\tselectorId [STRING] - ID of the selector"
        },
        {inbox_subscribeFor,
            "subscribeFor JSON_ARRAY\n"
            "\tjson format - [subscriptionQueries:[query]]\n"
            "\t\tsubscriptionQueries [ARRAY] - list of subscription query strings (see buildSubscriptionQuery)\n"
            "\t\t\tquery [STRING] - single subscription query\n"
            "\treturns a list of subscriptionIds in matching order to subscriptionQueries"
        },
        {inbox_unsubscribeFrom,
            "unsubscribeFrom JSON_ARRAY\n"
            "\tjson format - [subscriptionIds:[subscriptionId]]\n"
            "\t\tsubscriptionIds [ARRAY] - list of subscriptionIds to unsubscribe from\n"
            "\t\t\tsubscriptionId [STRING] - single subscriptionId"
        },
        {inbox_buildSubscriptionQuery,
            "buildSubscriptionQuery JSON_ARRAY\n"
            "\tjson format - [eventType, selectorType, selectorId]\n"
            "\t\teventType [NUMBER] - type of event to listen for (inbox::EventType enum value)\n"
            "\t\tselectorType [NUMBER] - scope on which to listen for events (inbox::EventSelectorType enum value)\n"
            "\t\tselectorId [STRING] - ID of the selector"
        },
        {kvdb_createKvdb,
            "createKvdb JSON_ARRAY\n"
            "\tjson format - [contextId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, policies?, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tcontextId [STRING] - ID of the Context to create the KVDB in\n"
            "\t\tusers [ARRAY] - vector of UserWithPubKey which indicates who will have access to the created KVDB\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] - vector of UserWithPubKey which indicates who will have access (and management rights) to the created KVDB\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tpolicies [OBJECT] - (optional) KVDB's policies (ContainerPolicy)\n"
            "\t\tgroups [ARRAY] - groups granted access to the KVDB; pass [] for none\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER); \"\" to read it from the Bridge\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at; 0 to read it from the Bridge"
        },
        {kvdb_updateKvdb,
            "updateKvdb JSON_ARRAY\n"
            "\tjson format - [kvdbId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, version, force, forceGenerateNewKey, policies?, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to update\n"
            "\t\tusers [ARRAY] - vector of UserWithPubKey which indicates who will have access to the updated KVDB\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] - vector of UserWithPubKey which indicates who will have access (and management rights) to the updated KVDB\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tversion [NUMBER] - current version of the updated KVDB\n"
            "\t\tforce [BOOL] - force update (without checking version)\n"
            "\t\tforceGenerateNewKey [BOOL] - force to regenerate a key for the KVDB\n"
            "\t\tpolicies [OBJECT] - (optional) KVDB's policies (ContainerPolicy)\n"
            "\t\tgroups [ARRAY] - groups granted access to the KVDB; authoritative, so [] revokes every group grant\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER); \"\" to read it from the Bridge\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at; 0 to read it from the Bridge"
        },
        {kvdb_rotateKvdbKeys,
            "rotateKvdbKeys JSON_ARRAY\n"
            "\tjson format - [kvdbId, users:[{userId, pubKey}], managers:[{userId, pubKey}], version, force, groups:[{groupId, role, groupPubKey, groupEpoch}]]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to re-key\n"
            "\t\tusers [ARRAY] - current KVDB users with their public keys\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] - current KVDB managers with their public keys\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tversion [NUMBER] - current KVDB version (optimistic lock guard)\n"
            "\t\tforce [BOOL] - skip the version check\n"
            "\t\tgroups [ARRAY] - epoch public keys the caller has verified itself; pass [] to read them all from the Bridge. A re-key changes no grants, so groups the KVDB does not grant are ignored\n"
            "\t\t\tgroupId [STRING] - ID of the group\n"
            "\t\t\trole [STRING] - role held by the group (\"user\" or \"manager\")\n"
            "\t\t\tgroupPubKey [STRING] - verified group epoch public key (base58-DER)\n"
            "\t\t\tgroupEpoch [NUMBER] - epoch groupPubKey was verified at"
        },
        {kvdb_deleteKvdb,
            "deleteKvdb JSON_ARRAY\n"
            "\tjson format - [kvdbId]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to delete"
        },
        {kvdb_getKvdb,
            "getKvdb JSON_ARRAY\n"
            "\tjson format - [kvdbId]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to get"
        },
        {kvdb_listKvdbs,
            "listKvdbs JSON_ARRAY\n"
            "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tcontextId [STRING] - ID of the Context to get the KVDBs from\n"
            "\t\tpagingQuery [OBJECT] - list query parameters"
        },
        {kvdb_getEntry,
            "getEntry JSON_ARRAY\n"
            "\tjson format - [kvdbId, key]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to get the entry from\n"
            "\t\tkey [STRING] - key of the KVDB entry to get"
        },
        {kvdb_listEntriesKeys,
            "listEntriesKeys JSON_ARRAY\n"
            "\tjson format - [kvdbId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to list entry keys from\n"
            "\t\tpagingQuery [OBJECT] - list query parameters"
        },
        {kvdb_listEntries,
            "listEntries JSON_ARRAY\n"
            "\tjson format - [kvdbId, pagingQuery:{skip, limit, sortOrder, lastId?}]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to list entries from\n"
            "\t\tpagingQuery [OBJECT] - list query parameters"
        },
        {kvdb_setEntry,
            "setEntry JSON_ARRAY\n"
            "\tjson format - [kvdbId, key, publicMeta, privateMeta, data, version?]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to set the entry in\n"
            "\t\tkey [STRING] - KVDB entry key\n"
            "\t\tpublicMeta [BUFFER] - public KVDB entry metadata\n"
            "\t\tprivateMeta [BUFFER] - private KVDB entry metadata\n"
            "\t\tdata [BUFFER] - content of the KVDB entry\n"
            "\t\tversion [NUMBER] - (optional) current entry version; 0 to create a new entry"
        },
        {kvdb_deleteEntry,
            "deleteEntry JSON_ARRAY\n"
            "\tjson format - [kvdbId, key]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to delete the entry from\n"
            "\t\tkey [STRING] - key of the KVDB entry to delete"
        },
        {kvdb_deleteEntries,
            "deleteEntries JSON_ARRAY\n"
            "\tjson format - [kvdbId, keys:[key]]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to delete from\n"
            "\t\tkeys [ARRAY] - list of keys of the KVDB entries to delete\n"
            "\t\t\tkey [STRING] - single KVDB entry key\n"
            "\treturns a map with the deletion status for every key"
        },
        {kvdb_hasEntry,
            "hasEntry JSON_ARRAY\n"
            "\tjson format - [kvdbId, key]\n"
            "\t\tkvdbId [STRING] - ID of the KVDB to check\n"
            "\t\tkey [STRING] - key of the KVDB entry to check"
        },
        {kvdb_subscribeFor,
            "subscribeFor JSON_ARRAY\n"
            "\tjson format - [subscriptionQueries:[query]]\n"
            "\t\tsubscriptionQueries [ARRAY] - list of subscription query strings (see buildSubscriptionQuery)\n"
            "\t\t\tquery [STRING] - single subscription query\n"
            "\treturns a list of subscriptionIds in matching order to subscriptionQueries"
        },
        {kvdb_unsubscribeFrom,
            "unsubscribeFrom JSON_ARRAY\n"
            "\tjson format - [subscriptionIds:[subscriptionId]]\n"
            "\t\tsubscriptionIds [ARRAY] - list of subscriptionIds to unsubscribe from\n"
            "\t\t\tsubscriptionId [STRING] - single subscriptionId"
        },
        {kvdb_buildSubscriptionQuery,
            "buildSubscriptionQuery JSON_ARRAY\n"
            "\tjson format - [eventType, selectorType, selectorId]\n"
            "\t\teventType [NUMBER] - type of event to listen for (kvdb::EventType enum value)\n"
            "\t\tselectorType [NUMBER] - scope on which to listen for events (kvdb::EventSelectorType enum value)\n"
            "\t\tselectorId [STRING] - ID of the selector"
        },
        {kvdb_buildSubscriptionQueryForSelectedEntry,
            "buildSubscriptionQueryForSelectedEntry JSON_ARRAY\n"
            "\tjson format - [eventType, kvdbId, kvdbEntryKey]\n"
            "\t\teventType [NUMBER] - type of event to listen for (kvdb::EventType enum value)\n"
            "\t\tkvdbId [STRING] - ID of the KVDB\n"
            "\t\tkvdbEntryKey [STRING] - key of the KVDB entry"
        },
        {group_createGroupWithKeyTree,
            "createGroupWithKeyTree JSON_ARRAY\n"
            "\tjson format - [contextId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, policies?]\n"
            "\t\tcontextId [STRING] - ID of the Context to create the Group in\n"
            "\t\tusers [ARRAY] - vector of UserWithPubKey which indicates who will have access to the created Group\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tmanagers [ARRAY] - vector of UserWithPubKey which indicates who will have access (and management rights) to the created Group\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tpolicies [OBJECT] - (optional) Group's policies (ContainerPolicy)"
        },
        {group_addGroupMember,
            "addGroupMember JSON_ARRAY\n"
            "\tjson format - [groupId, newMember:{userId, pubKey}, asManager, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta]\n"
            "\t\tgroupId [STRING] - ID of the Group\n"
            "\t\tnewMember [OBJECT] - the member to add, with their public key (UserWithPubKey)\n"
            "\t\t\tuserId [STRING] - ID of the user\n"
            "\t\t\tpubKey [STRING] - user's public key\n"
            "\t\tasManager [BOOL] - whether the new member joins as a manager\n"
            "\t\tusers [ARRAY] - full member list *after* the addition\n"
            "\t\tmanagers [ARRAY] - full manager list *after* the addition\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata to store with this change\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata to store with this change\n"
            "\tdoes not advance the Group's key epoch"
        },
        {group_removeGroupMember,
            "removeGroupMember JSON_ARRAY\n"
            "\tjson format - [groupId, userId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta]\n"
            "\t\tgroupId [STRING] - ID of the Group\n"
            "\t\tuserId [STRING] - ID of the member to remove\n"
            "\t\tusers [ARRAY] - member list that *remains*, without the removed member\n"
            "\t\tmanagers [ARRAY] - manager list that remains\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata to store with this change\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata to store with this change\n"
            "\tadvances the Group's key epoch; containers the Group can read must be re-keyed afterwards"
        },
        {group_updateGroup,
            "updateGroup JSON_ARRAY\n"
            "\tjson format - [groupId, users:[{userId, pubKey}], managers:[{userId, pubKey}], publicMeta, privateMeta, version, force, forceGenerateNewKey, policies?]\n"
            "\t\tgroupId [STRING] - ID of the Group to update\n"
            "\t\tusers [ARRAY] - vector of UserWithPubKey which indicates who will have access to the updated Group\n"
            "\t\tmanagers [ARRAY] - vector of UserWithPubKey which indicates who will have access (and management rights) to the updated Group\n"
            "\t\tpublicMeta [BUFFER] - public (unencrypted) metadata\n"
            "\t\tprivateMeta [BUFFER] - private (encrypted) metadata\n"
            "\t\tversion [NUMBER] - current version of the updated Group\n"
            "\t\tforce [BOOL] - force update (without checking version)\n"
            "\t\tforceGenerateNewKey [BOOL] - force to regenerate a key for the Group\n"
            "\t\tpolicies [OBJECT] - (optional) Group's policies (ContainerPolicy)"
        },
        {group_deleteGroup,
            "deleteGroup JSON_ARRAY\n"
            "\tjson format - [groupId]\n"
            "\t\tgroupId [STRING] - ID of the Group to delete"
        },
        {group_getGroup,
            "getGroup JSON_ARRAY\n"
            "\tjson format - [groupId]\n"
            "\t\tgroupId [STRING] - ID of the Group to get"
        },
        {group_listGroups,
            "listGroups JSON_ARRAY\n"
            "\tjson format - [contextId, pagingQuery:{skip, limit, sortOrder, lastId?, sortBy?, queryAsJson?}]\n"
            "\t\tcontextId [STRING] - ID of the Context to get the Groups from\n"
            "\t\tpagingQuery [OBJECT] - struct with list query parameters\n"
            "\t\t\tskip [NUMBER] - number of elements to skip from result\n"
            "\t\t\tlimit [NUMBER] - limit of elements to return for query\n"
            "\t\t\tsortOrder [STRING] - order of elements in result (\"asc\" or \"desc\")\n"
            "\t\t\tlastId [STRING] - (optional) ID of the element from which query results should start\n"
            "\tthe listing carries no publicMeta/privateMeta - call getGroup for those"
        },
        {group_subscribeFor,
            "subscribeFor JSON_ARRAY\n"
            "\tjson format - [subscriptionQueries:[STRING]]\n"
            "\t\tsubscriptionQueries [ARRAY] - list of queries built with group.buildSubscriptionQuery"
        },
        {group_unsubscribeFrom,
            "unsubscribeFrom JSON_ARRAY\n"
            "\tjson format - [subscriptionIds:[STRING]]\n"
            "\t\tsubscriptionIds [ARRAY] - list of subscriptionId"
        },
        {group_buildSubscriptionQuery,
            "buildSubscriptionQuery JSON_ARRAY\n"
            "\tjson format - [eventType, selectorType, selectorId]\n"
            "\t\teventType [NUMBER] - type of event to listen for (group::EventType: 0 - GROUP_CREATE, 1 - GROUP_UPDATE, 2 - GROUP_DELETE)\n"
            "\t\tselectorType [NUMBER] - scope to listen on (group::EventSelectorType: 0 - CONTEXT_ID, 1 - GROUP_ID)\n"
            "\t\tselectorId [STRING] - ID of the selector"
        }
    };

    const std::unordered_map<func_enum, std::string> functions_endpoint_help_short_description = {
        {config_setCertsPath, "Allows to set path to the SSL certificate file."},
        {core_waitEvent, "Starts a loop waiting for an Event. Runs in new thread"},
        {core_getEvent, "Gets the first event from the events queue."},
        {core_emitBreakEvent, "Puts the break event on the events queue."},
        {core_connect, "Connects to the Platform backend."},
        {core_connectPublic, "Connects to the Platform backend as a guest user."},
        {core_disconnect, "Disconnects from the Platform backend."},
        {core_getConnectionId, "Gets the ID of the current connection."},
        {core_listContexts, "Gets a list of Contexts available for the user."},
        {core_backendRequest, "Sends request to PrivMX Bridge API."},
        {crypto_signData, "Creates a signature of data using given key."},
        {crypto_verifySignature, "Validate a signature of data using given key."},
        {crypto_generatePrivateKey, "Generates a new private ECC key."},
        {crypto_derivePrivateKey, "Generates a new private ECC key from a password using pbkdf2."},
        {crypto_derivePublicKey, "Generates a new public ECC key as a pair for an existing private key."},
        {crypto_generateKeySymmetric, "Generates a new symmetric key."},
        {crypto_encryptDataSymmetric, "Encrypts buffer with a given key using AES."},
        {crypto_decryptDataSymmetric, "Decrypts buffer with a given key using AES."},
        {crypto_convertPEMKeytoWIFKey, "Converts given private key in PEM format to its WIF format."},
        {thread_createThread, "Creates a new Thread in given Context."},
        {thread_updateThread, "Updates an existing Thread."},
        {thread_rotateThreadKeys, "Re-encrypts the Thread key for its current members and grantee groups."},
        {thread_getThread, "Gets a Thread by given Thread ID."},
        {thread_listThreads, "Gets a list of Threads in given Context."},
        {thread_deleteThread, "Deletes a Thread by given Thread ID."},
        {thread_sendMessage, "Sends a message in a Thread."},
        {thread_updateMessage, "Update message in a Thread."},
        {thread_getMessage, "Gets a message by given message ID."},
        {thread_listMessages, "Gets a list of messages from a Thread."},
        {thread_deleteMessage, "Deletes a message by given message ID."},
        {store_createStore, "Creates a new Store in given Context."},
        {store_updateStore, "Updates an existing Store."},
        {store_rotateStoreKeys, "Re-encrypts the Store key for its current members and grantee groups."},
        {store_getStore, "Gets a single Store by given Store ID."},
        {store_listStores, "Gets a list of Stores in given Context."},
        {store_deleteStore, "Deletes a Store by given Store ID."},
        {store_createFile, "Creates a new file in a Store."},
        {store_updateFile, "Update an existing file in a Store."},
        {store_updateFileMeta, "Update metadata of an existing file in a Store."},
        {store_getFile, "Gets a single file by the given file ID."},
        {store_listFiles, "Gets a list of files in given Store."},
        {store_deleteFile, "Deletes a file by given ID."},
        {store_openFile, "Opens a file to read."},
        {store_readFromFile, "Reads file data."},
        {store_writeToFile, "Writes a file data."},
        {store_seekInFile, "Moves read cursor."},
        {store_closeFile, "Closes the file handle."},
        {inbox_createInbox, "Creates a new Inbox."},
        {inbox_updateInbox, "Updates an existing Inbox."},
        {inbox_rotateInboxKeys, "Re-encrypts the Inbox key, and its inner Thread's and Store's, for their current members and grantee groups."},
        {inbox_getInbox, "Gets a single Inbox by given Inbox ID."},
        {inbox_listInboxes, "Gets s list of Inboxes in given Context."},
        {inbox_deleteInbox, "Deletes an Inbox by given Inbox ID."},
        {inbox_getInboxPublicView, "Gets public data of given Inbox."},
        {inbox_prepareEntry, "Prepares a request to send data to an Inbox."},
        {inbox_sendEntry, "Sends data to an Inbox."},
        {inbox_readEntry, "Gets an entry from an Inbox."},
        {inbox_listEntries, "Gets list of entries in given Inbox."},
        {inbox_deleteEntry, "Delete an entry from an Inbox."},
        {inbox_createFileHandle, "Creates a file handle to send a file to an Inbox."},
        {inbox_writeToFile, "Sends file's data chunk to an Inbox."},
        {inbox_openFile, "Opens a file to read."},
        {inbox_readFromFile, "Reads file data."},
        {inbox_seekInFile, "Moves file's read cursor."},
        {inbox_closeFile, "Closes a file by given handle."},
        {core_listContextUsers, "Gets a list of users of given Context."},
        {core_subscribeFor, "Subscribes for the Context events on the given subscription queries."},
        {core_unsubscribeFrom, "Unsubscribes from events for the given subscriptionIds."},
        {core_buildSubscriptionQuery, "Generates a subscription query for Context events."},
        {utils_encodeHex, "Encodes a buffer to a Hex string."},
        {utils_decodeHex, "Decodes a Hex string to a buffer."},
        {utils_isHex, "Checks whether a string is valid Hex."},
        {utils_encodeBase32, "Encodes a buffer to a Base32 string."},
        {utils_decodeBase32, "Decodes a Base32 string to a buffer."},
        {utils_isBase32, "Checks whether a string is valid Base32."},
        {utils_encodeBase64, "Encodes a buffer to a Base64 string."},
        {utils_decodeBase64, "Decodes a Base64 string to a buffer."},
        {utils_isBase64, "Checks whether a string is valid Base64."},
        {utils_trim, "Removes leading and trailing whitespace from a string."},
        {utils_split, "Splits a string by a delimiter into parts."},
        {utils_ltrim, "Removes whitespace from the left of a string."},
        {utils_rtrim, "Removes whitespace from the right of a string."},
        {crypto_fromMnemonic, "Generates an ECC key and an extKey handle from a BIP-39 mnemonic."},
        {crypto_fromEntropy, "Generates an ECC key and an extKey handle from BIP-39 entropy."},
        {crypto_entropyToMnemonic, "Converts BIP-39 entropy to a mnemonic."},
        {crypto_mnemonicToEntropy, "Converts a BIP-39 mnemonic to entropy."},
        {crypto_mnemonicToSeed, "Generates a seed from a BIP-39 mnemonic."},
        {extkey_fromSeed, "Creates an ExtKey from the given seed and returns its handle."},
        {extkey_fromBase58, "Creates an ExtKey from a Base58 string and returns its handle."},
        {extkey_generateRandom, "Generates a new random ExtKey and returns its handle."},
        {extkey_derive, "Derives a child ExtKey using BIP32."},
        {extkey_deriveHardened, "Derives a hardened child ExtKey using BIP32."},
        {extkey_getPrivatePartAsBase58, "Gets the private part of the ExtKey as a Base58 string."},
        {extkey_getPublicPartAsBase58, "Gets the public part of the ExtKey as a Base58 string."},
        {extkey_getPrivateKey, "Extracts the ECC private key (WIF) from the ExtKey."},
        {extkey_getPublicKey, "Extracts the ECC public key (BASE58DER) from the ExtKey."},
        {extkey_getPrivateEncKey, "Extracts the raw ECC private key from the ExtKey."},
        {extkey_getPublicKeyAsBase58Address, "Gets the public key as a Base58 address."},
        {extkey_getChainCode, "Gets the chain code of the ExtKey."},
        {extkey_verifyCompactSignatureWithHash, "Validates a message signature against the ExtKey."},
        {extkey_isPrivate, "Checks whether the ExtKey is private."},
        {event_emitEvent, "Emits a custom event to the given users on a Context channel."},
        {event_subscribeFor, "Subscribes for custom events on the given subscription queries."},
        {event_unsubscribeFrom, "Unsubscribes from events for the given subscriptionIds."},
        {event_buildSubscriptionQuery, "Generates a subscription query for custom events."},
        {thread_subscribeFor, "Subscribes for the Thread events on the given subscription queries."},
        {thread_unsubscribeFrom, "Unsubscribes from events for the given subscriptionIds."},
        {thread_buildSubscriptionQuery, "Generates a subscription query for Thread events."},
        {store_syncFile, "Synchronizes the file identified by the given handle."},
        {store_subscribeFor, "Subscribes for the Store events on the given subscription queries."},
        {store_unsubscribeFrom, "Unsubscribes from events for the given subscriptionIds."},
        {store_buildSubscriptionQuery, "Generates a subscription query for Store events."},
        {inbox_subscribeFor, "Subscribes for the Inbox events on the given subscription queries."},
        {inbox_unsubscribeFrom, "Unsubscribes from events for the given subscriptionIds."},
        {inbox_buildSubscriptionQuery, "Generates a subscription query for Inbox events."},
        {kvdb_createKvdb, "Creates a new KVDB in given Context."},
        {kvdb_updateKvdb, "Updates an existing KVDB."},
        {kvdb_rotateKvdbKeys, "Re-encrypts the KVDB key for its current members and grantee groups."},
        {kvdb_deleteKvdb, "Deletes a KVDB by given KVDB ID."},
        {kvdb_getKvdb, "Gets a KVDB by given KVDB ID."},
        {kvdb_listKvdbs, "Gets a list of KVDBs in given Context."},
        {kvdb_getEntry, "Gets a KVDB entry by given key."},
        {kvdb_listEntriesKeys, "Gets a list of KVDB entry keys from a KVDB."},
        {kvdb_listEntries, "Gets a list of KVDB entries from a KVDB."},
        {kvdb_setEntry, "Sets a KVDB entry in the given KVDB."},
        {kvdb_deleteEntry, "Deletes a KVDB entry by given key."},
        {kvdb_deleteEntries, "Deletes multiple KVDB entries by given keys."},
        {kvdb_hasEntry, "Checks whether a KVDB entry exists."},
        {kvdb_subscribeFor, "Subscribes for the KVDB events on the given subscription queries."},
        {kvdb_unsubscribeFrom, "Unsubscribes from events for the given subscriptionIds."},
        {kvdb_buildSubscriptionQuery, "Generates a subscription query for KVDB events."},
        {kvdb_buildSubscriptionQueryForSelectedEntry, "Generates a subscription query for events of a single KVDB entry."},
        {group_createGroupWithKeyTree, "Creates a new Group whose key distribution is backed by a hidden key tree."},
        {group_addGroupMember, "Adds one member to a tree-backed Group, without advancing its key epoch."},
        {group_removeGroupMember, "Removes one member from a tree-backed Group and advances its key epoch."},
        {group_updateGroup, "Updates an existing Group."},
        {group_deleteGroup, "Deletes a Group by given Group ID."},
        {group_getGroup, "Gets a Group by given Group ID."},
        {group_listGroups, "Gets a list of Groups in given Context."},
        {group_subscribeFor, "Subscribes for the Group events on the given subscription queries."},
        {group_unsubscribeFrom, "Unsubscribes from events for the given subscriptionIds."},
        {group_buildSubscriptionQuery, "Generates a subscription query for Group events."},
    };

    const std::unordered_map<func_enum, std::string> functions_endpoint_action_description = {
        {config_setCertsPath, "Setting CertsPath"},
        {core_waitEvent, "Waiting for event"},
        {core_getEvent, "Getting event"},
        {core_emitBreakEvent, "Emitting break event"},
        {core_connect, "Connecting"},
        {core_connectPublic, "Connecting public"},
        {core_disconnect, "Disconnecting"},
        {core_getConnectionId, "Getting connection id"},
        {core_listContexts, "Getting contexts"},
        {core_backendRequest, "Running backendRequest"},
        {crypto_signData, "Signing data"},
        {crypto_verifySignature, "Verifying signature"},
        {crypto_generatePrivateKey, "Generating private key"},
        {crypto_derivePrivateKey, "Deriving private key"},
        {crypto_derivePublicKey, "Deriving public key"},
        {crypto_generateKeySymmetric, "Generating symmetric key"},
        {crypto_encryptDataSymmetric, "Encrypt data using symmetric key"},
        {crypto_decryptDataSymmetric, "Decrypting data using symmetric key"},
        {crypto_convertPEMKeytoWIFKey, "Convert PEM key to WIF key"},
        {thread_createThread, "Creating thread"},
        {thread_updateThread, "Updating thread"},
        {thread_rotateThreadKeys, "Rotating thread keys"},
        {thread_getThread, "Getting thread"},
        {thread_listThreads, "Getting threads"},
        {thread_deleteThread, "Deleting thread"},
        {store_createStore, "Creating store"},
        {store_updateStore, "Updating store"},
        {store_rotateStoreKeys, "Rotating store keys"},
        {store_getStore, "Getting store"},
        {store_listStores, "Getting stores"},
        {store_deleteStore, "Deleting store"},
        {store_createFile, "Creating store file"},
        {store_updateFile, "Updating store file"},
        {store_updateFileMeta, "Updating store file meta"},
        {store_getFile, "Getting store file"},
        {store_listFiles, "Getting store files"},
        {store_deleteFile, "Deleting store file"},
        {store_openFile, "Opening store file"},
        {store_readFromFile, "Reading from store file"},
        {store_writeToFile, "Writing to store file"},
        {store_seekInFile, "Seeking in store file"},
        {store_closeFile, "Closing store file"},
        {inbox_createInbox, "Creating inbox"},
        {inbox_updateInbox, "Updating inbox"},
        {inbox_rotateInboxKeys, "Rotating inbox keys"},
        {inbox_getInbox, "Getting inbox"},
        {inbox_listInboxes, "Getting inboxes"},
        {inbox_deleteInbox, "Deleting inbox"},
        {inbox_getInboxPublicView, "Getting inbox public view"},
        {inbox_prepareEntry, "Preparing entry"},
        {inbox_sendEntry, "Sending entry"},
        {inbox_readEntry, "Reading entry"},
        {inbox_listEntries, "Getting entries"},
        {inbox_deleteEntry, "Deleting entry"},
        {inbox_createFileHandle, "Creating file handle"},
        {inbox_writeToFile, "Writing to file"},
        {inbox_openFile, "Opening file"},
        {inbox_readFromFile, "Reading form file"},
        {inbox_seekInFile, "Seeking in file"},
        {inbox_closeFile, "Closing file"},
        {core_listContextUsers, "Getting context users"},
        {core_subscribeFor, "Subscribing for core events"},
        {core_unsubscribeFrom, "Unsubscribing from events"},
        {core_buildSubscriptionQuery, "Building subscription query"},
        {utils_encodeHex, "Encoding hex"},
        {utils_decodeHex, "Decoding hex"},
        {utils_isHex, "Checking hex"},
        {utils_encodeBase32, "Encoding base32"},
        {utils_decodeBase32, "Decoding base32"},
        {utils_isBase32, "Checking base32"},
        {utils_encodeBase64, "Encoding base64"},
        {utils_decodeBase64, "Decoding base64"},
        {utils_isBase64, "Checking base64"},
        {utils_trim, "Trimming"},
        {utils_split, "Splitting"},
        {utils_ltrim, "Left-trimming"},
        {utils_rtrim, "Right-trimming"},
        {crypto_fromMnemonic, "Generating key from mnemonic"},
        {crypto_fromEntropy, "Generating key from entropy"},
        {crypto_entropyToMnemonic, "Converting entropy to mnemonic"},
        {crypto_mnemonicToEntropy, "Converting mnemonic to entropy"},
        {crypto_mnemonicToSeed, "Generating seed from mnemonic"},
        {extkey_fromSeed, "Creating ExtKey from seed"},
        {extkey_fromBase58, "Creating ExtKey from base58"},
        {extkey_generateRandom, "Generating random ExtKey"},
        {extkey_derive, "Deriving ExtKey"},
        {extkey_deriveHardened, "Deriving hardened ExtKey"},
        {extkey_getPrivatePartAsBase58, "Getting ExtKey private part"},
        {extkey_getPublicPartAsBase58, "Getting ExtKey public part"},
        {extkey_getPrivateKey, "Getting ExtKey private key"},
        {extkey_getPublicKey, "Getting ExtKey public key"},
        {extkey_getPrivateEncKey, "Getting ExtKey private enc key"},
        {extkey_getPublicKeyAsBase58Address, "Getting ExtKey public address"},
        {extkey_getChainCode, "Getting ExtKey chain code"},
        {extkey_verifyCompactSignatureWithHash, "Verifying ExtKey signature"},
        {extkey_isPrivate, "Checking if ExtKey is private"},
        {event_emitEvent, "Emitting event"},
        {event_subscribeFor, "Subscribing for custom events"},
        {event_unsubscribeFrom, "Unsubscribing from events"},
        {event_buildSubscriptionQuery, "Building subscription query"},
        {thread_subscribeFor, "Subscribing for thread events"},
        {thread_unsubscribeFrom, "Unsubscribing from events"},
        {thread_buildSubscriptionQuery, "Building subscription query"},
        {store_syncFile, "Syncing store file"},
        {store_subscribeFor, "Subscribing for store events"},
        {store_unsubscribeFrom, "Unsubscribing from events"},
        {store_buildSubscriptionQuery, "Building subscription query"},
        {inbox_subscribeFor, "Subscribing for inbox events"},
        {inbox_unsubscribeFrom, "Unsubscribing from events"},
        {inbox_buildSubscriptionQuery, "Building subscription query"},
        {kvdb_createKvdb, "Creating kvdb"},
        {kvdb_updateKvdb, "Updating kvdb"},
        {kvdb_rotateKvdbKeys, "Rotating kvdb keys"},
        {kvdb_deleteKvdb, "Deleting kvdb"},
        {kvdb_getKvdb, "Getting kvdb"},
        {kvdb_listKvdbs, "Getting kvdbs"},
        {kvdb_getEntry, "Getting kvdb entry"},
        {kvdb_listEntriesKeys, "Getting kvdb entry keys"},
        {kvdb_listEntries, "Getting kvdb entries"},
        {kvdb_setEntry, "Setting kvdb entry"},
        {kvdb_deleteEntry, "Deleting kvdb entry"},
        {kvdb_deleteEntries, "Deleting kvdb entries"},
        {kvdb_hasEntry, "Checking kvdb entry"},
        {kvdb_subscribeFor, "Subscribing for kvdb events"},
        {kvdb_unsubscribeFrom, "Unsubscribing from events"},
        {kvdb_buildSubscriptionQuery, "Building subscription query"},
        {kvdb_buildSubscriptionQueryForSelectedEntry, "Building subscription query"},
        {group_createGroupWithKeyTree, "Creating group"},
        {group_addGroupMember, "Adding group member"},
        {group_removeGroupMember, "Removing group member"},
        {group_updateGroup, "Updating group"},
        {group_deleteGroup, "Deleting group"},
        {group_getGroup, "Getting group"},
        {group_listGroups, "Getting group list"},
        {group_subscribeFor, "Subscribing for events"},
        {group_unsubscribeFrom, "Unsubscribing from events"},
        {group_buildSubscriptionQuery, "Building subscription query"},
    };
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_ENDPOINT_HPP_
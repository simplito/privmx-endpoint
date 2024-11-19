/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_BRIDGE_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_BRIDGE_HPP_

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

#include "privmx/endpoint/core/varinterface/BackendRequesterVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/VarInterfaceUtil.hpp"
#include "privmx/endpoint/core/CoreException.hpp"

#include "privmx/utils/Utils.hpp"

namespace privmx {
namespace endpoint {
namespace privmxcli {

class ExecuterBridge {
public:
    ExecuterBridge(std::thread::id main_thread_id, std::shared_ptr<CliConfig> config, std::shared_ptr<ConsoleWriter> console_writer);
    bool execute(const func_enum& fun_code, const Tokens &st);
    bool execute_help(const func_enum& fun_code, const std::string& function_name);
    std::string  get_all_function_help_printable_string();
private:
    Poco::Dynamic::Var getS_var(const std::string &key);
    void set_api_creds(const std::string &api_key_id, const std::string &api_key_secret, const std::string &url);

    std::thread::id _main_thread_id;
    std::shared_ptr<CliConfig> _config;
    std::shared_ptr<ConsoleWriter> _console_writer;
    std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> _bridge;
    
    std::optional<std::string> _api_key_id;
    std::optional<std::string> _api_key_secret;
    std::optional<std::string> _url;

    std::chrono::_V2::system_clock::time_point _timer_start = std::chrono::system_clock::now();


    const std::unordered_map<func_enum, std::function<Poco::Dynamic::Var(std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface>, const std::string& args, const std::string&, const std::string&, const std::string&)>> functions_bridge_execute = {
        {bridge_manager_auth, 
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("manager/auth"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_manager_createApiKey,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("manager/createApiKey"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_manager_getApiKey,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("manager/getApiKey"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_manager_listApiKeys, 
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("manager/listApiKeys"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_manager_updateApiKey,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("manager/updateApiKey"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_manager_deleteApiKey,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("manager/deleteApiKey"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_solution_getSolution,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("solution/getSolution"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_solution_listSolutions,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("solution/listSolutions"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_solution_createSolution,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("solution/createSolution"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_solution_updateSolution,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("solution/updateSolution"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_solution_deleteSolution,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("solution/deleteSolution"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_getContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/getContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_listContexts,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/listContexts"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_listContextsOfSolution,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/listContextsOfSolution"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_createContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/createContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_updateContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/updateContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_deleteContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/deleteContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_addSolutionToContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/addSolutionToContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_removeSolutionFromContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/removeSolutionFromContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_addUserToContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/addUserToContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_removeUserFromContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/removeUserFromContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_removeUserFromContextByPubKey,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/removeUserFromContextByPubKey"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_getUserFromContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/getUserFromContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_getUserFromContextByPubKey,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/getUserFromContextByPubKey"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_listUsersFromContext,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/listUsersFromContext"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
        {bridge_context_setUserAcl,  
            [](std::shared_ptr<privmx::endpoint::core::BackendRequesterVarInterface> api, const std::string& args, const std::string& api_key_id, const std::string& api_key_secret, const std::string& url) -> Poco::Dynamic::Var{
                Poco::JSON::Array::Ptr request_args = new Poco::JSON::Array();
                request_args->add(url);
                request_args->add(api_key_id);
                request_args->add(api_key_secret);
                request_args->add(0);
                request_args->add(std::string("context/setUserAcl"));
                request_args->add(args);
                return api->backendRequest(request_args);
            }
        },
    };

    const std::unordered_map<func_enum, std::string> functions_bridge_help_description = {
        {bridge_setBridgeApiCreds,
            "bridge.setBridgeApiCreds APIKEY_ID, APIKEY_SECRET, URL\n"
        },
        {bridge_manager_auth,
            "bridge.manager.auth JSON_OBJECT\n"
            "\tjson format - {grantType: \"api_key_credentials\", apiKeyId: string, apiKeySecret: string, scope?: string[]}"
            "\t\tapiKeyId [STRING] - Api key id (length in [1,128])"
            "\t\tapiKeySecret [STRING] - Api key secret (length in [1,128])"
            "\t\tscope [ARRAY[STRING]] - (optional) Requested token scope (length in [0,128])"
            "\tjson format - {grantType: \"refresh_token\", refreshToken: string}"
            "\t\trefreshToken [STRING] - Refresh token from earlier invocation (length in [1,2048]))"
            "\tjson format - {grantType: \"api_key_signature\", apiKeyId: string, signature: string, timestamp: number, nonce: string, scope?: string[], data?: string}"
            "\t\tapiKeyId [STRING] - Api key id (length in [1,128])"
            "\t\tsignature [STRING] - EdDSA signature or Hash"
            "\t\ttimestamp [NUMBER] - Request timestamp (in range: [-∞,∞])"
            "\t\tnonce [STRING] - Random value used to generate signature (length in [32,64])"
            "\t\tscope [ARRAY[STRING]] - (optional) Requested token scope (length in [0,128])"
            "\t\tdata [STRING] - (optional) Optional signed data (length in [0,1024])"

            
        },
        {bridge_manager_createApiKey, 
            "bridge.manager.createApiKey JSON_OBJECT\n"
            "\tjson format - {name: string, scope: string[], publicKey?: string}\n"
            "\t\tname [STRING] - New api key name (length in [0,128])"
            "\t\tscope [ARRAY[STRING]] - New api key scope (length in [0,128])"
            "\t\tpublicKey [STRING] - (optional) ED25519 PEM encoded public key"
        },
        {bridge_manager_getApiKey, 
            "bridge.manager.getApiKey JSON_OBJECT\n"
            "\tjson format - {id: string}\n"
            "\t\tid [STRING] - Api key id (length in [1,128])"
        },
        {bridge_manager_listApiKeys,
            "bridge.manager.listApiKeys JSON_OBJECT\n"
            "\tjson format - {}\n"
        },
        {bridge_manager_updateApiKey, 
            "bridge.manager.updateApiKey JSON_OBJECT\n"
            "\tjson format - {id: string, name?: string, scope?: string[], enabled?: boolean}\n"
            "\t\tid [STRING] - Api key id (length in [1,128])"
            "\t\tname [STRING] - (optional) Api key name (length in [0,128])"
            "\t\tscope [ARRAY[STRING]] - (optional) Api key scope (length in [0,128])"
            "\t\tenabled [BOOL] - (optional) Api key status"
        },
        {bridge_manager_deleteApiKey, 
            "bridge.manager.deleteApiKey JSON_OBJECT\n"
            "\tjson format - {id: string}\n"
            "\t\tid [STRING] - Api key id (length in [1,128])"
        },
        {bridge_solution_getSolution, 
            "bridge.solution.getSolution JSON_OBJECT\n"
            "\tjson format - {id: string}\n"
            "\t\tid [STRING] - solution's id (length in [1,128])"
        },
        {bridge_solution_listSolutions,
            "bridge.solution.listSolutions JSON_OBJECT\n"
            "\tjson format - {}\n"
        },
        {bridge_solution_createSolution, 
            "bridge.solution.createSolution JSON_OBJECT\n"
            "\tjson format - {name: string}\n"
            "\t\tname [STRING] - solution's name (length in [0,256])"
        },
        {bridge_solution_updateSolution, 
            "bridge.solution.updateSolution JSON_OBJECT\n"
            "\tjson format - {id: string, name: string}\n"
            "\t\tid [STRING] - solution's id (length in [1,128])"
            "\t\tname [STRING] - solution's name (length in [0,256])"
        },
        {bridge_solution_deleteSolution, 
            "bridge.solution.deleteSolution JSON_OBJECT\n"
            "\tjson format - {id: string}\n"
            "\t\tid [STRING] - solution's id (length in [1,128])"
        },
        {bridge_context_getContext, 
            "bridge.context.getContext JSON_OBJECT\n"
            "\tjson format - {contextId: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
        },
        {bridge_context_listContexts, 
            "bridge.context.listContexts JSON_OBJECT\n"
            "\tjson format - {skip: number, limit: number, sortOrder: desc|asc, lastId?: string}\n"
            "\t\tskip [NUMBER] - (in range: [0,∞])"
            "\t\tlimit [NUMBER] - (in range: [1,100])"
            "\t\tsortOrder [STRING] - desc|asc"
            "\t\tlastId [STRING] - (optional) (length in [1,60])"
        },
        {bridge_context_listContextsOfSolution, 
            "bridge.context.listContextsOfSolution JSON_OBJECT\n"
            "\tjson format - {solutionId: string, skip: number, limit: number, sortOrder: desc|asc, lastId?: string}\n"
            "\t\tsolutionId [STRING] - solution's id (length in [1,128])"
            "\t\tskip [NUMBER] - (in range: [0,∞])"
            "\t\tlimit [NUMBER] - (in range: [1,100])"
            "\t\tsortOrder [STRING] - desc|asc"
            "\t\tlastId [STRING] - (optional) (length in [1,60])"
        },
        {bridge_context_createContext, 
            "bridge.context.createContext JSON_OBJECT\n"
            "\tjson format - {solution: string, name?: string, description?: string, scope?: private|public, policy?: object}\n"
            "\t\tsolution [STRING] - solution's id (length in [1,128])"
            "\t\tname [STRING] - (optional) context's name (length in [0,128])"
            "\t\tdescription [STRING] - (optional) context's description (length in [0,128])"
            "\t\tscope [STRING] - (optional) context's scope, public or private"
            "\t\tpolicy [OBJECT] - (optional) context's policy"
        },
        {bridge_context_updateContext, 
            "bridge.context.updateContext JSON_OBJECT\n"
            "\tjson format - {contextId: string, name?: string, description?: string, scope?: private|public, policy?: object}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tname [STRING] - (optional) context's name (length in [0,128])"
            "\t\tdescription [STRING] - (optional) context's description (length in [0,128])"
            "\t\tscope [STRING] - (optional) context's scope, public or private"
            "\t\tpolicy [OBJECT] - (optional) context's policy"
        },
        {bridge_context_deleteContext, 
            "bridge.context.deleteContext JSON_OBJECT\n"
            "\tjson format - {contextId: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
        },
        {bridge_context_addSolutionToContext, 
            "bridge.context.addSolutionToContext JSON_OBJECT\n"
            "\tjson format - {contextId: string, solutionId: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tsolutionId [STRING] - solution's id (length in [1,128])"
        },
        {bridge_context_removeSolutionFromContext, 
            "bridge.context.removeSolutionFromContext JSON_OBJECT\n"
            "\tjson format - {contextId: string, solutionId: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tsolutionId [STRING] - solution's id (length in [1,128])"
        },
        {bridge_context_addUserToContext, 
            "bridge.context.getUserFromContextByPubKey JSON_OBJECT\n"
            "\tjson format - {contextId: string, userId: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tuserId [STRING] - user's id (length in [1,128])"
        },
        {bridge_context_removeUserFromContext, 
            "bridge.context.removeUserFromContext JSON_OBJECT\n"
            "\tjson format - {contextId: string, userId: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tuserId [STRING] - user's id (length in [1,128])"
        },
        {bridge_context_removeUserFromContextByPubKey,
            "bridge.context.removeUserFromContextByPubKey JSON_OBJECT\n"
            "\tjson format - {contextId: string, userPubKey: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tuserPubKey [STRING] - context user's public key"
        },
        {bridge_context_getUserFromContext, 
            "bridge.context.getUserFromContext JSON_OBJECT\n"
            "\tjson format - {contextId: string, userId: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tuserId [STRING] - user's id (length in [1,128])"
        },
        {bridge_context_getUserFromContextByPubKey, 
            "bridge.context.getUserFromContextByPubKey JSON_OBJECT\n"
            "\tjson format - {contextId: string, pubKey: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tpubKey [STRING] - context user's public key"
        },
        {bridge_context_listUsersFromContext, 
            "bridge.context.listUsersFromContext JSON_OBJECT\n"
            "\tjson format - {contextId: string, skip: number, limit: number, sortOrder: asc|desc, lastId?: string}\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tskip [NUMBER] - (in range: [0,∞])"
            "\t\tlimit [NUMBER] - (in range: [1,100])"
            "\t\tsortOrder [STRING] - desc|asc"
            "\t\tlastId [STRING] - (optional) (length in [1,60])"
        },
        {bridge_context_setUserAcl,
            "bridge.context.setUserAcl JSON_OBJECT\n"
            "\tjson format - {contextId: string, userId: string, acl: string}]\n"
            "\t\tcontextId [STRING] - context's id (length in [1,128])"
            "\t\tuserId [STRING] - user's id (length in [1,128])"
            "\t\tacl [STRING] - user acl (length in [0,4096])"
        },
    };

    const std::unordered_map<func_enum, std::string> functions_bridge_help_short_description = {
        {bridge_setBridgeApiCreds, "Set api bridge credentials"},
        {bridge_manager_auth, "Retrieve an Oauth access token, to be used for authentication of requests."},
        {bridge_manager_createApiKey, "Adds new ApiKey (up to limit of 10). If you pass a public key you cannot use generated api key secret to authorize"},
        {bridge_manager_getApiKey, "returns info about ApiKey"},
        {bridge_manager_listApiKeys, "lists all ApiKeys"},
        {bridge_manager_updateApiKey, "updates given ApiKey"},
        {bridge_manager_deleteApiKey, "Deletes ApiKey"},
        {bridge_solution_getSolution, "Get solution"},
        {bridge_solution_listSolutions, "Get list of the solutions"},
        {bridge_solution_createSolution, "Creates solution"},
        {bridge_solution_updateSolution, "Updates solution"},
        {bridge_solution_deleteSolution, "Deletes solution"},
        {bridge_context_getContext, "Get context by given id"},
        {bridge_context_listContexts, "Get list of all contexts"},
        {bridge_context_listContextsOfSolution, "Get list of all contexts of given solution"},
        {bridge_context_createContext, "Creates new application context with given options"},
        {bridge_context_updateContext, "Updates existing context properties"},
        {bridge_context_deleteContext, "Removes context"},
        {bridge_context_addSolutionToContext, "Creates connection between context and solution"},
        {bridge_context_removeSolutionFromContext, "Removes connection between context and solution"},
        {bridge_context_addUserToContext, "Add user to context with given id"},
        {bridge_context_removeUserFromContext, "Removes user from the context"},
        {bridge_context_removeUserFromContextByPubKey, "Removes user form the context by user's public key"},
        {bridge_context_getUserFromContext, "Get user from context"},
        {bridge_context_getUserFromContextByPubKey, "Get user from context by user's public key"},
        {bridge_context_listUsersFromContext, "Get list of all users in the given context"},
        {bridge_context_setUserAcl, "updates user ACL"},
    };

    const std::unordered_map<func_enum, std::string> functions_bridge_action_description = {
        {bridge_setBridgeApiCreds, "Setting bridge api credential"},
        {bridge_manager_auth, "Authenticating"},
        {bridge_manager_createApiKey, "Creating ApiKey"},
        {bridge_manager_getApiKey, "Geting ApiKey"},
        {bridge_manager_listApiKeys, "Geting list of api keys"},
        {bridge_manager_updateApiKey, "Updating ApiKey"},
        {bridge_manager_deleteApiKey, "Deleteing ApiKey"},
        {bridge_solution_getSolution, "Geting solution"},
        {bridge_solution_listSolutions, "Geting list of solutions"},
        {bridge_solution_createSolution, "Creating solution"},
        {bridge_solution_updateSolution, "Updating solution"},
        {bridge_solution_deleteSolution, "Deleteing solution"},
        {bridge_context_getContext, "Geting context"},
        {bridge_context_listContexts, "Geting list of contexts"},
        {bridge_context_listContextsOfSolution, "Geting list of contexts"},
        {bridge_context_createContext, "Creating context"},
        {bridge_context_updateContext, "Updating context"},
        {bridge_context_deleteContext, "Deleteing context"},
        {bridge_context_addSolutionToContext, "Adding solution to context"},
        {bridge_context_removeSolutionFromContext, "Removing solution from context"},
        {bridge_context_addUserToContext, "Adding user to context"},
        {bridge_context_removeUserFromContext, "Removing user from context"},
        {bridge_context_removeUserFromContextByPubKey, "Removing user from context"},
        {bridge_context_getUserFromContext, "Geting user"},
        {bridge_context_getUserFromContextByPubKey, "Geting user"},
        {bridge_context_listUsersFromContext, "Geting list of users"},
        {bridge_context_setUserAcl, "Updating user ACL"},
    };
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_BRIDGE_HPP_
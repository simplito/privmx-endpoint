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
        {bridge_setBridgeApiCreds, ""},
        {bridge_manager_auth, ""},
        {bridge_manager_createApiKey, ""},
        {bridge_manager_getApiKey, ""},
        {bridge_manager_listApiKeys, ""},
        {bridge_manager_updateApiKey, ""},
        {bridge_manager_deleteApiKey, ""},
        {bridge_solution_getSolution, ""},
        {bridge_solution_listSolutions, ""},
        {bridge_solution_createSolution, ""},
        {bridge_solution_updateSolution, ""},
        {bridge_solution_deleteSolution, ""},
        {bridge_context_getContext, ""},
        {bridge_context_listContexts, ""},
        {bridge_context_listContextsOfSolution, ""},
        {bridge_context_createContext, ""},
        {bridge_context_updateContext, ""},
        {bridge_context_deleteContext, ""},
        {bridge_context_addSolutionToContext, ""},
        {bridge_context_removeSolutionFromContext, ""},
        {bridge_context_addUserToContext, ""},
        {bridge_context_removeUserFromContext, ""},
        {bridge_context_removeUserFromContextByPubKey, ""},
        {bridge_context_getUserFromContext, ""},
        {bridge_context_getUserFromContextByPubKey, ""},
        {bridge_context_listUsersFromContext, ""},
        {bridge_context_setUserAcl, ""},
    };

    const std::unordered_map<func_enum, std::string> functions_bridge_help_short_description = {
        {bridge_setBridgeApiCreds, ""},
        {bridge_manager_auth, ""},
        {bridge_manager_createApiKey, ""},
        {bridge_manager_getApiKey, ""},
        {bridge_manager_listApiKeys, ""},
        {bridge_manager_updateApiKey, ""},
        {bridge_manager_deleteApiKey, ""},
        {bridge_solution_getSolution, ""},
        {bridge_solution_listSolutions, ""},
        {bridge_solution_createSolution, ""},
        {bridge_solution_updateSolution, ""},
        {bridge_solution_deleteSolution, ""},
        {bridge_context_getContext, ""},
        {bridge_context_listContexts, ""},
        {bridge_context_listContextsOfSolution, ""},
        {bridge_context_createContext, ""},
        {bridge_context_updateContext, ""},
        {bridge_context_deleteContext, ""},
        {bridge_context_addSolutionToContext, ""},
        {bridge_context_removeSolutionFromContext, ""},
        {bridge_context_addUserToContext, ""},
        {bridge_context_removeUserFromContext, ""},
        {bridge_context_removeUserFromContextByPubKey, ""},
        {bridge_context_getUserFromContext, ""},
        {bridge_context_getUserFromContextByPubKey, ""},
        {bridge_context_listUsersFromContext, ""},
        {bridge_context_setUserAcl, ""},
    };

    const std::unordered_map<func_enum, std::string> functions_bridge_action_description = {
        {bridge_setBridgeApiCreds, ""},
        {bridge_manager_auth, ""},
        {bridge_manager_createApiKey, ""},
        {bridge_manager_getApiKey, ""},
        {bridge_manager_listApiKeys, "getting list of ApiKeys"},
        {bridge_manager_updateApiKey, ""},
        {bridge_manager_deleteApiKey, ""},
        {bridge_solution_getSolution, ""},
        {bridge_solution_listSolutions, ""},
        {bridge_solution_createSolution, ""},
        {bridge_solution_updateSolution, ""},
        {bridge_solution_deleteSolution, ""},
        {bridge_context_getContext, ""},
        {bridge_context_listContexts, ""},
        {bridge_context_listContextsOfSolution, ""},
        {bridge_context_createContext, ""},
        {bridge_context_updateContext, ""},
        {bridge_context_deleteContext, ""},
        {bridge_context_addSolutionToContext, ""},
        {bridge_context_removeSolutionFromContext, ""},
        {bridge_context_addUserToContext, ""},
        {bridge_context_removeUserFromContext, ""},
        {bridge_context_removeUserFromContextByPubKey, ""},
        {bridge_context_getUserFromContext, ""},
        {bridge_context_getUserFromContextByPubKey, ""},
        {bridge_context_listUsersFromContext, ""},
        {bridge_context_setUserAcl, ""},
    };
};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_EXECUTER_BRIDGE_HPP_
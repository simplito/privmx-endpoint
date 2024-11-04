/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_CAPIEXECUTOR_HPP_
#define _PRIVMXLIB_UTILS_CAPIEXECUTOR_HPP_

#include <functional>
#include <Poco/Exception.h>
#include <Poco/Dynamic/Var.h>
#include <Pson/pson.h>

#include <privmx/utils/PrivmxException.hpp>

#include "privmx/endpoint/interface/ExceptionHandler.hpp"

namespace privmx {
namespace utils {

class CApiExecutor
{
public:
    static int execFunc(pson_value** result, const std::function<Poco::Dynamic::Var(void)>& func) noexcept;
    static int execVoidFunc(pson_value** result, const std::function<void(void)>& func) noexcept;
};

inline int CApiExecutor::execFunc(pson_value** result, const std::function<Poco::Dynamic::Var(void)>& func) noexcept {
    Poco::JSON::Object::Ptr res = new Poco::JSON::Object();
    try {
        Poco::Dynamic::Var var = func();
        res->set("result", Poco::Dynamic::Var(var));
        res->set("error", Poco::Dynamic::Var());
        res->set("status", true);
    } catch (const endpoint::core::Exception& e) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error(e));
        res->set("status", false);
    } catch (const utils::PrivmxException& e) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error(e));
        res->set("status", false);
    } catch (const Poco::Exception& e) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error(e));
        res->set("status", false);
    } catch (const std::exception& e) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error(e));
        res->set("status", false);
    } catch (...) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error());
        res->set("status", false);
    }
    res->set("__type", "Result");
    *result = (pson_value*)(new Poco::Dynamic::Var(res));
    return res->getValue<bool>("status");
}

inline int CApiExecutor::execVoidFunc(pson_value** result, const std::function<void(void)>& func) noexcept {
    Poco::JSON::Object::Ptr res = new Poco::JSON::Object();
    try {
        res->set("result", Poco::Dynamic::Var());
        func();
        res->set("error", Poco::Dynamic::Var());
        res->set("status", true);
    } catch (const utils::PrivmxException& e) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error(e));
        res->set("status", false);
    } catch (const Poco::Exception& e) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error(e));
        res->set("status", false);
    } catch (const std::exception& e) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error(e));
        res->set("status", false);
    } catch (...) {
        res->set("result", Poco::Dynamic::Var());
        res->set("error", utils::ExceptionHandler::make_error());
        res->set("status", false);
    }
    res->set("__type", "Result");
    *result = (pson_value*)(new Poco::Dynamic::Var(res));
    return res->getValue<bool>("status");
}

} // utils
} // privmx

#endif // _PRIVMXLIB_UTILS_CAPIEXECUTOR_HPP_

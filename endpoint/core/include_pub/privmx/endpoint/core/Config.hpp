#ifndef _PRIVMXLIB_ENDPOINT_CORE_CONFIG_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CONFIG_HPP_

#include <string>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * 'Config' provides Endpoint's configuration functions.
 */
class Config {
public:
    
    /**
     * Allows to set path to the SSL certificate file.
     * 
     * @param certsPath path to file
     *
     */
    static void setCertsPath(const std::string& certsPath);
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_CONFIG_HPP_

#ifndef _PRIVMXLIB_ENDPOINT_PRIVMXCLI_LOADING_ANIMATION_HPP_
#define _PRIVMXLIB_ENDPOINT_PRIVMXCLI_LOADING_ANIMATION_HPP_

#include <thread>
#include <memory>
#include <string>
#include <iostream>

namespace privmx {
namespace endpoint {
namespace privmxcli {

class LoadingAnimation
{
public:
    LoadingAnimation();
    ~LoadingAnimation();
    void start();
    void stop();
private:
    
    std::shared_ptr<std::thread> _t = nullptr;
    bool _stop = false;

};

} // privmxcli
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_PRIVMXCLI_LOADING_ANIMATION_HPP_
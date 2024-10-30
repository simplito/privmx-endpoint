#include "privmx/endpoint/programs/privmxcli/LoadingAnimation.hpp"

using namespace std;
using namespace privmx::endpoint::privmxcli;

LoadingAnimation::LoadingAnimation() : _t(nullptr), _stop(true) {}

LoadingAnimation::~LoadingAnimation() {
    _stop = true;
    if(_t != nullptr) _t->join();
}

void LoadingAnimation::start() {
    if(_stop || _t == nullptr) {
        _stop = false;
        _t = std::make_shared<std::thread>(std::thread([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            std::cout << "-" << std::flush;
            while(!_stop) {
                if(!_stop) {
                    std::cout << "\b\\" << std::flush;
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                if(!_stop) {
                    std::cout << "\b|" << std::flush;
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                if(!_stop) {
                    std::cout << "\b/" << std::flush;
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                if(!_stop) {
                    std::cout << "\b-" << std::flush;
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                
            }
            std::cout << "\b ";
            // std::cout << "\x1b[2K";
            // std::cout << "\r";
        }));
    }
}

void LoadingAnimation::stop() {
    _stop = true;
    if(_t != nullptr) _t->join();
    _t = nullptr;
    
}
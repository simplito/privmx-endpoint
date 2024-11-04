#ifndef _PRIVMXLIB_TEST_SNAPSHOOTSERVICE_HPP_
#define _PRIVMXLIB_TEST_SNAPSHOOTSERVICE_HPP_

#include <string>
#include <cstdlib>
#include <thread>
#include <exception>
#include <privmx/utils/Debug.hpp>
#include <privmx/utils/PrivmxException.hpp>

namespace privmx {
namespace test {

class SnapshootService
{
public:
    SnapshootService();
    void up(const std::string& snapshoot = "default", bool force = false);
    std::string getAddress();
    void down(bool force = false);

private:
    std::string exec(std::string cmd);

    std::string _snapshootType = "";
    std::string _address = "";
    std::string _instanceUrl = "";

    std::string _instanceServerURL;

    
    bool _working = false;
    const bool ENABLED = true;
};

SnapshootService::SnapshootService() : _snapshootType(std::string()), _address(std::string()), _instanceUrl(std::string()) {
    if(std::getenv("INSTANCE_SERVER_URL") != NULL) {
        _instanceServerURL = std::getenv("INSTANCE_SERVER_URL");
    } else {
        _instanceServerURL = "localhost:5000";
    }
}

void SnapshootService::up(const std::string& snapshoot, bool force) {
    if (!ENABLED) return;
    if(snapshoot == "default" && (!_working || force)) {
        _snapshootType = snapshoot;
        std::string checkInstanceServerCom = "curl -s http://" + _instanceServerURL + "/getStatus 2>/dev/null >/dev/null";
        if(std::system(checkInstanceServerCom.c_str()) != 0) {
            throw privmx::utils::PrivmxException("instanceServer not responding");
        }
        std::string getInstanceCom = "curl -s http://" + _instanceServerURL + "/getInstance | jq -r .instance.instanceUrl | tr -d '\n'";
        for (int i = 0; i < 20; ++i) {
            _instanceUrl = exec(getInstanceCom.c_str());
            PRIVMX_DEBUG("TEST_E2E", "SnapshootService::up", "Getting instanceUrl, try nr: " + std::to_string(i));
            PRIVMX_DEBUG("TEST_E2E", "SnapshootService::up", "instanceUrl - " + _instanceUrl);
            if(_instanceUrl.empty() || _instanceUrl != "null") {
                break;
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
        if(!_instanceUrl.empty() && _instanceUrl != "null") {
            _working = true;
            _address = _instanceUrl;
            std::string checkServerCom = "curl -m 2 -X POST http://" + _instanceUrl + "/cloud/api 2>/dev/null >/dev/null";
            int i = 0;
            for (; std::system(checkServerCom.c_str()) != 0 && i < 5000; ++i) {
                if (i%100 == 0) {
                    PRIVMX_DEBUG("TEST_E2E", "SnapshootService::up", "CheckServer, try nr: " + std::to_string(i) + " failed");
                }
            };
            if (i == 5000) {
                throw privmx::utils::PrivmxException("server not responding");
            }
        } else {
            throw privmx::utils::PrivmxException("getInstance failed");
        }
    }
}

void SnapshootService::down(bool force) {
    if (!ENABLED) return;
    if(_snapshootType == "default" && (_working || force)) {
        auto tmp = exec(
            std::string("curl -s http://" + _instanceServerURL + "/releaseInstance?url=" + _instanceUrl).c_str()
        );
        if(tmp =="{\"result\":\"OK\"}") {
            _working = false;
            _address = "";
        } else {
            throw privmx::utils::PrivmxException("releaseInstance failed");
        }
    }
}

std::string SnapshootService::getAddress() {
    return _address;
}

std::string SnapshootService::exec(std::string cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

} // test
} // privmx

#endif // _PRIVMXLIB_TEST_SNAPSHOOTSERVICE_HPP_

#ifndef _PRIVMXLIB_TEST_BASETEST_HPP_
#define _PRIVMXLIB_TEST_BASETEST_HPP_

#include "./SnapshootService.hpp"

#include <gtest/gtest.h>
#include <random>
#include <Poco/URI.h>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/utils/PrivmxException.hpp>


namespace privmx {
namespace test {

enum BaseTestMode {
    online,
    offline
};

class BaseTest : public testing::Test {

protected:
    BaseTest(const BaseTestMode& mode = BaseTestMode::online) : _mode(mode) {}
    void SetUp() override {
        try {
            
            if(std::getenv("INI_FILE_PATH") == NULL) {
                std::cout << "INI_FILE_PATH == NULL" << std::endl;
                FAIL();
                return;
            }
            if(_mode == BaseTestMode::online) {
                _snapshoot_service.up("default");
            }
            customSetUp();
        } catch (const privmx::endpoint::core::Exception& e) {
            std::cout << e.getFull() << std::endl;
            FAIL();
        } catch (const privmx::utils::PrivmxException& e) {
            std::cout << e.what() << " | " << e.getData() << std::endl;
            FAIL();
        }
    }
    void TearDown() override {
        if(std::getenv("INI_FILE_PATH") == NULL) {
            return;
        }
        customTearDown();
        if(_mode == BaseTestMode::online) {
        _snapshoot_service.down();
        }
    }
    virtual void customSetUp() = 0;
    virtual void customTearDown() = 0;
    std::string randomReadableString(int max_length);
    std::string getPlatformUrl(std::string url);
private:
    BaseTestMode _mode;
    SnapshootService _snapshoot_service;
};

std::string BaseTest::randomReadableString(int max_length) {
    std::string possible_characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 engine(rd());
    std::uniform_int_distribution<> dist(0, possible_characters.size()-1);
    std::string ret = "";
    for(int i = 0; i < max_length; i++){
        int random_index = dist(engine); //get index between 0 and possible_characters.size()-1
        ret += possible_characters[random_index];
    }
    return ret;
}

std::string BaseTest::getPlatformUrl(std::string url) {
    // std::string path = Poco::URI(url).getPath();
    // std::string address = _snapshoot_service.getAddress();
    // std::string result = "http://" + address + path;
    // return result;
    return "http://" + _snapshoot_service.getAddress();
}

} // test
} // privmx

#endif // _PRIVMXLIB_TEST_BASETEST_HPP_

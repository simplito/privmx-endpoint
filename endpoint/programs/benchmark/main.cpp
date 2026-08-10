#include <iostream>
#include <string>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <functional>
#include <condition_variable>
#include <privmx/endpoint/core/Config.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/store/StoreApi.hpp>
#include <privmx/endpoint/inbox/InboxApi.hpp>
#include <privmx/endpoint/kvdb/KvdbApi.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <Poco/Util/IniFileConfiguration.h>
#include <privmx/utils/Logger.hpp>
#include "privmx/endpoint/programs/benchmark/Types.hpp"
#include "privmx/endpoint/programs/benchmark/GetTestFunction.hpp"
#include "privmx/endpoint/programs/benchmark/PrepereInitData.hpp"


using namespace std::chrono_literals;
using namespace privmx::endpoint;

static std::vector<std::string_view> getParamsList(int argc, char* argv[]) {
    std::vector<std::string_view> args(argv + 1, argv + argc);
    return args;
}

static uint64_t parseUintArg(const std::string& str) {
    int base = 10;
    if (str.size() > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        base = 16;
    }
    return std::stoull(str, nullptr, base);
}

int main(int argc, char** argv) {
    auto params = getParamsList(argc, argv);
    if(params.size() != 4) {        
        std::cout << "expected number of arguments is 4 recived "<< params.size() << std::endl;
        return -1;
    }
    // from ARG
    auto benchmark_mode_it = mode_names.find(std::string(params[0]));
    if(benchmark_mode_it == mode_names.end()) {
        std::cout << "unknown Mode "<< std::string(params[0]) << std::endl;
        return -1;
    }
    const Mode benchmark_mode = (*benchmark_mode_it).second;

    const uint64_t benchmark_duration = std::stoull(std::string(params[1])); 
    auto benchmark_module_it = module_names.find(std::string(params[2]));
    if(benchmark_module_it == module_names.end()) {
        std::cout << "unknown Module "<< std::string(params[2]) << std::endl;
        return -1;
    }
    const Module benchmark_module = (*benchmark_module_it).second;;
    uint64_t benchmark_grup;
    try {
        benchmark_grup = parseUintArg(std::string(params[3]));
    } catch (const std::exception&) {
        std::cout << "invalid group \"" << std::string(params[3]) << "\" (use a decimal like 65541 or hex like 0x10005)" << std::endl;
        return -1;
    }

    //form INI
    auto iniFile = std::getenv("INI_FILE_PATH");
    Poco::Util::IniFileConfiguration::Ptr reader = new Poco::Util::IniFileConfiguration(iniFile);
    const std::string userPrivKey = reader->getString("Login.user_1_privKey");
    const std::string userPubKey = reader->getString("Login.user_1_pubKey");
    const std::string userId = reader->getString("Login.user_1_id");
    const std::string solution = reader->getString("Login.solutionId");
    auto env_platformUrl = std::getenv("PLATFORM_URL");
    const std::string platformUrl = env_platformUrl == NULL ? reader->getString("Login.instanceUrl") : ("http://" + std::string(env_platformUrl) + "/");
    // initialising connection
    std::shared_ptr<core::Connection> connection = std::make_shared<core::Connection>(core::Connection::connect(userPrivKey, solution, platformUrl));
    std::shared_ptr<thread::ThreadApi> threadApi = std::make_shared<thread::ThreadApi>(thread::ThreadApi::create(*connection));
    std::shared_ptr<store::StoreApi> storeApi = std::make_shared<store::StoreApi>(store::StoreApi::create(*connection));
    std::shared_ptr<inbox::InboxApi> inboxApi = std::make_shared<inbox::InboxApi>(inbox::InboxApi::create(*connection, *threadApi, *storeApi));
    std::shared_ptr<kvdb::KvdbApi> kvdbApi = std::make_shared<kvdb::KvdbApi>(kvdb::KvdbApi::create(*connection));
    std::shared_ptr<event::EventApi> eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
    LOG_TRACE("Benchmark - init Connected")
    //contextId
    auto contextsList = connection->listContexts({.skip=0, .limit=1, .sortOrder="asc"});
    if(contextsList.totalAvailable == 0) {
        throw;
    }
    auto contexts = contextsList.readItems;
    const auto context = contextsList.readItems[0];
    const std::string contextId = contexts[0].contextId;
    // get function
    auto exec = GetTestFunction(benchmark_module, benchmark_grup);
    // prepare init data
    auto initLoopData = PrepareInitData(connection, threadApi, storeApi, inboxApi, kvdbApi, eventApi, userId, userPubKey, benchmark_module, benchmark_grup);
    LOG_TRACE("Benchmark - init PrepareInitData")
    // Main

    uint64_t N = 0;
    std::mutex m;
    std::condition_variable cv;
    bool stop = false;
    std::vector<std::chrono::_V2::system_clock::time_point> run_timestamps = {};
    std::thread t([&]() {
        run_timestamps.push_back(std::chrono::system_clock::now());
        while (benchmark_mode == Mode::Timeout ? !stop : N < benchmark_duration) {
            exec(connection, threadApi, storeApi, inboxApi, kvdbApi, eventApi, initLoopData);
            if(!stop) {
                N++;
                run_timestamps.push_back(std::chrono::system_clock::now());
                // std::cout << N << ": time - " << std::chrono::duration<double>{(run_timestamps[run_timestamps.size()-1] - run_timestamps[run_timestamps.size()-2])}.count()*1000 << "ms" << std::endl;
            }
        }
        cv.notify_all();
    }); 
    t.detach();
    if(benchmark_mode == Mode::Timeout) {
        std::unique_lock<std::mutex> lock(m);
        if(cv.wait_for(lock, std::chrono::seconds(benchmark_duration)) == std::cv_status::timeout) {
            stop = true;
        }
        cv.wait(lock);
    } else {
        std::unique_lock<std::mutex> lock(m);
        cv.wait(lock);
    }
    connection->disconnect();
    std::cout << "Total time - " << std::chrono::duration<double>{(run_timestamps[run_timestamps.size()-1] - run_timestamps[0])}.count() << "s" << std::endl;
    std::cout << "Total exec - " << N << std::endl;
    std::cout << "Avarage time - " << std::chrono::duration<double>{(run_timestamps[run_timestamps.size()-1] - run_timestamps[0])}.count() / N * 1000 << "ms" << std::endl;
    std::chrono::duration<double> min = run_timestamps[1] - run_timestamps[0];
    std::chrono::duration<double> max = run_timestamps[1] - run_timestamps[0];
    for(int i = 1; i < run_timestamps.size(); i++) {
        std::chrono::duration<double> tmp = run_timestamps[i] - run_timestamps[i-1];
        if(tmp > max) {
            max = tmp;
        }
        if(tmp < min) {
            min = tmp;
        }
    } 
    std::cout << "Min single exec time - " << min.count() * 1000 << "ms" << std::endl;
    std::cout << "Max single exec time - " << max.count() * 1000 << "ms" << std::endl;
    
    return 0;
}



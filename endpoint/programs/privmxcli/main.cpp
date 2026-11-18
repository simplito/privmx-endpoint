
#include <iostream>

#include <fstream>
#include <unordered_map>
#include <thread>

#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <Poco/Environment.h>
#include <Poco/Path.h>
#include <Poco/String.h>

#include "privmx/crypto/Crypto.hpp"
#include "privmx/utils/Utils.hpp"
#include "privmx/utils/PrivmxException.hpp"

#include "privmx/endpoint/programs/privmxcli/DataProcesor.hpp"
#include "privmx/endpoint/programs/privmxcli/colors/Colors.h"
#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"

using namespace std;
using namespace privmx::endpoint::privmxcli;

char* completion_generator(const char* text, int state) {
    if(!config_auto_completion) return nullptr;
    static std::vector<std::string> matches;
    static size_t match_index = 0;

    if (state == 0) {
        matches.clear();
        match_index = 0;

        std::string textstr = std::string(text);
        std::vector<std::string> keywords;
        for(auto &item : functions_internal){
            keywords.push_back(item.first);
        }
        for(auto &item : functions_endpoint){
            if(use_path.empty()) {
                keywords.push_back(item.first);
            } else if(item.first.substr(0, use_path.size()) == use_path) {
                keywords.push_back(item.first.substr(use_path.size()));
            }
        }
        for(auto &item : functions_bridge){
            if(use_path.empty()) {
                keywords.push_back(item.first);
            } else if(item.first.substr(0, use_path.size()) == use_path) {
                keywords.push_back(item.first.substr(use_path.size()));
            }
        }
        for(auto &item : func_aliases){
            keywords.push_back(item.first);
        }
        for(auto &item : session){
            keywords.push_back(item.first);
        }

        for (auto &word : keywords) {
            if (word.size() >= textstr.size() &&
                word.compare(0, textstr.size(), textstr) == 0) {
                matches.push_back(word);
            }
        }
    }

    if (match_index >= matches.size()) {
        return nullptr;
    } else {
        return strdup(matches[match_index++].c_str());
    }
}

char** completer(const char* text, int start, int end) {
    rl_completion_append_character = ' ';
    return rl_completion_matches(text, completion_generator);
}

void exiting() {
    std::cout << "Exiting" << std::endl;
}

struct CliArgsData {
    CliConfig config;
    vector<string> lines_to_process;
    vector<string> filenames;
};

void printHelp() {
    std::cout << "Usage: privmxcli [OPTION]" << std::endl;
    std::cout << "Example: privmxcli -iT" << std::endl;
    std::cout << "\truns cli i interactive mode with timestamps" << std::endl;
    std::cout << std::endl;
    std::cout << "-h, --help" << std::endl;
    std::cout << "\tdisplay this help and exit" << std::endl;
    std::cout << "-e, --error-exit" << std::endl;
    std::cout << "\texit on any error" << std::endl;
    std::cout << "-T, --timestamps" << std::endl;
    std::cout << "\tadd timestamps to executed command" << std::endl;
    std::cout << "-i, --interactive" << std::endl;
    std::cout << "\tenable interactive mode" << std::endl;
    std::cout << "-q, --quiet" << std::endl;
    std::cout << "\tprint only command results on stdout, everything else (logs, progress) goes to stderr" << std::endl;
    std::cout << "-g [NUM], --get-format=NUM" << std::endl;
    std::cout << "\tset output formatting for command 'get', NUM is a number where 0 represent default mode, 1 bash like, 2 c++ like, 3 python like " << std::endl;
    std::cout << "-f [PATH], --file=PATH" << std::endl;
    std::cout << "\tread commands from file " << std::endl;
    std::cout << "-s [VAR], --set=VAR" << std::endl;
    std::cout << "\texecute 'set' command. VAR represents string of variable name and variable data separated by space" << std::endl;
    std::cout << "-c [COM], --command=COM" << std::endl;
    std::cout << "\texecute command. COM represents command string" << std::endl;
    std::cout << std::endl;
    std::cout << "Every command result is stored in the variable 'last_result'. Use 'VAR = command ARGS' to store it under VAR too." << std::endl;
    std::cout << "A dotted variable reads a field of the stored JSON, e.g. ${last_result.solutionId} or ${last_result.readItems.0.contextId}." << std::endl;
}

CliArgsData parseArgs(int argc, char *argv[]) {
    CliConfig config;
    vector<string> lines_to_process;
    vector<string> filenames;
    const char* const short_opts = "c:s:f:g:iqTeh";
    const option long_opts[] = {
            {"command", required_argument, nullptr, 'c'},
            {"set", required_argument, nullptr, 's'},
            {"file", required_argument, nullptr, 'f'},
            {"get-format", required_argument, nullptr, 'g'},
            {"interactive", no_argument, nullptr, 'i'},
            {"quiet", no_argument, nullptr, 'q'},
            {"timestamps", no_argument, nullptr, 'T'},
            {"error-exit", no_argument, nullptr, 'e'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, no_argument, nullptr, 0}
    };
    int c;
    while((c = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1){
        switch(c){
            case 'c':
                {
                    string line = optarg;
                    lines_to_process.push_back(line);
                }
                break;
            case 's':
                {
                    string line = optarg;
                    lines_to_process.push_back("set " + line);
                }
                break; 
            case 'f':
                {
                    string filename = optarg;
                    filenames.push_back(filename);
                }
                break;
            case 'g':
                {  
                    std::string tmp = optarg;
                    if(tmp == "default" || tmp == "0") {
                        config.get_format = get_format_type::default_std;
                    } else if(tmp == "cpp" || tmp == "2") {
                        config.get_format = get_format_type::cpp;
                    } else if (tmp == "python" || tmp == "3") {
                        config.get_format = get_format_type::python;
                    } else if (tmp == "bash" || tmp == "1") {
                        config.get_format = get_format_type::bash;
                    } else {
                        cout << ConsoleStatusColor::normal << "-> " << ConsoleStatusColor::warning << "Unknown output format setting, using default setting" << endl;
                        config.get_format = get_format_type::default_std;
                    }
                }
                break;
            case 'i': //brak -i  auto podpowiedzi
                config.std_input = true;
                config.update_history = true;
                config_auto_completion = true;
                break;
            case 'q':
                config.quiet = true;
                break;
            case 'T':
                config.add_timestamps = true;
                break;
            case 'e':
                config.stop_on_error = true;
                break;
            case 'h':
                printHelp();
                exit(EXIT_SUCCESS);
                break;
        }
    }
    return {.config=config, .lines_to_process=lines_to_process, .filenames=filenames};
}

int main(int argc, char *argv[]){
    std::srand(std::time(nullptr));
    std::thread::id main_thread_id = this_thread::get_id();
    CliArgsData cli_args_data = parseArgs(argc, argv);
    if(cli_args_data.config.quiet) {
        // result_output keeps the real stdout, so library logs and progress text land on stderr
        std::cout.rdbuf(std::cerr.rdbuf());
    }
    string pre_filename = Poco::Environment::get("PRIVMXCLI_PRE", "");
    if(pre_filename != ""){
        cli_args_data.filenames.push_back(pre_filename);
    }
    std::shared_ptr<CliConfig> config = std::make_shared<CliConfig>(cli_args_data.config);
    std::shared_ptr<ConsoleWriter> console_writer = std::make_shared<ConsoleWriter>(main_thread_id, config);
    int missing_data = 0;
    
    DataProcesor data_procesor = DataProcesor(std::make_shared<Executer>(main_thread_id, config, console_writer), main_thread_id, config);

    // a failed command aborts the rest of the batch, so the following commands do not run on a broken state
    bool batch_aborted = false;
    auto batch_failed = [&]() {
        return console_writer->hadError() || missing_data == -1;
    };

    //executing data form args
    for(auto line : cli_args_data.lines_to_process) {
        missing_data = data_procesor.processLine(line);
        if(missing_data == -1) {
            cout << ConsoleStatusColor::normal << "-> " << ConsoleStatusColor::warning << "Incorrect JSON format - skipping command" << endl;
        }
        if(batch_failed()) {
            batch_aborted = true;
            break;
        }
    }
    missing_data = 0;
    for(auto &filename : cli_args_data.filenames){
        if(batch_aborted) break;
        ifstream f_stream(filename);
        if(!f_stream.good()){
            cerr << ConsoleStatusColor::warning << "File error " << filename << endl;
            if(config->stop_on_error) exit(EXIT_FAILURE);
            batch_aborted = true;
            break;
        }
        std::string line;
        while(getline(f_stream, line)){
            missing_data = data_procesor.processLine(line);
            if(batch_failed()) {
                batch_aborted = true;
                cerr << ConsoleStatusColor::warning << "Stopped on error, skipping the rest of " << filename << endl;
                break;
            }
        }
    }
    while(missing_data && !batch_aborted) {
        char *input_missing_data = readline("?> ");
        missing_data = data_procesor.processLine(input_missing_data);
        free(input_missing_data);
    }
    if(missing_data == -1) {
        
        if(config->stop_on_error) {
            cout << ConsoleStatusColor::error << "incorrect JSON format - skipping command" << endl;
            exit(EXIT_FAILURE);
        } else {
            cout << ConsoleStatusColor::warning << "incorrect JSON format - skipping command" << endl;
        }
    }
    

    if(batch_aborted && !config->std_input) {
        return EXIT_FAILURE;
    }

    //executing data form interactive mode
    if(config->std_input){
        rl_attempted_completion_function = completer;
        rl_basic_word_break_characters = " ";

        using_history();

        read_history(history_file_path.data());
        std::atexit(exiting);
        config->is_rl_input = true;
        std::string prev_input = "";
        while(1){
            //temporary solution - wait for all thread to stop writing
            // without colors
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            reset_c();
            std::string msg = "privmxcli >> ";
            if(use_path.size() > 0) {
                msg.append(use_path.substr(0,use_path.size()-1)+ " >> ");
            }
            // without colors
            // std::string msg = (std::string)get_reset_c() + "privmxcli >> ";
            // if(use_path.size() > 0) {
            //     msg.append((std::string)get_setcolor_c(Color::AQUA) + use_path.substr(0,use_path.size()-1)+ get_reset_c() +" >> ");
            // }
            char *input = readline(msg.c_str());
            if(!input) break;
            std::string str_input = input;
            // an error in interactive mode stops nothing, so every line starts clean
            console_writer->clearError();
            missing_data = data_procesor.processLine(input);
            if(!missing_data && config->update_history && prev_input != str_input) {
                prev_input = str_input;
                add_history(input);
                write_history(history_file_path.data());
            }
            free(input);
            while(missing_data) {
                char *input_missing_data = readline("?> ");
                str_input += std::string(input_missing_data);
                missing_data = data_procesor.processLine(input_missing_data);
                if(!missing_data && config->update_history && prev_input != str_input) {
                    prev_input = str_input;
                    add_history(str_input.data());
                    write_history(history_file_path.data());
                }
                free(input_missing_data);
            }
            if(missing_data == -1) {
                cout << ConsoleStatusColor::normal << "-> " << ConsoleStatusColor::warning << "Incorrect JSON format - skipping command" << endl;
            }
            
        }
        config->is_rl_input = false;
    }
    
    return EXIT_SUCCESS;
}



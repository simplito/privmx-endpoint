/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/programs/privmxcli/DataProcesor.hpp"
#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"

using namespace std;
using namespace privmx::endpoint::privmxcli;

DataProcesor::DataProcesor(std::thread::id main_thread_id, CliConfig config) :
    _executer(Executer(main_thread_id, config)), _config(config), _working_command(""),
    _working_command_braces(0), _working_command_square_brackets(0),
    _working_command_reading_string(0), _working_command_string_char('\0'), _loops({}) {}

void DataProcesor::updateCliConfig(CliConfig config) {
    _config = config;
    _executer.updateCliConfig(config);
}

void DataProcesor::clean() {
    _working_command = "";
    _working_command_braces = 0;
    _working_command_square_brackets = 0;
    _working_command_reading_string = false;
    _working_command_string_char = '\0';
}

int DataProcesor::processLine(const string &input_line){
    string line = Poco::trim(input_line);

    if((line.empty() || line[0] == '#') && !_working_command_reading_string) return false;
    char previus_char = '\0';
    
    for(auto c : line) {
        if(_working_command_reading_string) {
            if(previus_char == '\\' && c == '\\') {
                previus_char = '\0';
                continue;
            } else if(c == _working_command_string_char && previus_char != '\\') {
                _working_command_reading_string = false;
            }
        } else if(previus_char == '\\' && c == '\\') {
            previus_char = '\0';
            continue;
        } else if((c == '"' || c == '\'') && previus_char != '\\') {
            _working_command_string_char = c;
            _working_command_reading_string = true;
        } else if(c == '{' && previus_char != '\\') {
            _working_command_braces++;
        } else if(c == '}' && previus_char != '\\') {
            _working_command_braces--;
        } else if(c == '[' && previus_char != '\\') {
            _working_command_square_brackets++;
        } else if(c == ']' && previus_char != '\\') {
            _working_command_square_brackets--;
        }
        previus_char = c;
    }
    _working_command += line;
    if((_working_command_braces < 0) || (_working_command_square_brackets < 0)) {
        clean();
        return -1;
    }
    if(_working_command_reading_string || _working_command_braces != 0 || _working_command_square_brackets !=0) return 1;
    ExecuteCommand(ParseCommand(_working_command));
    clean();
    //execute command
    return 0;
}

Tokens DataProcesor::ParseCommand(string command) {
    string sep = " ";
    // help for '?' at end of line
    if(command.back() == '?') {
        int pos = 0;
        while(command.size() > pos && (command[pos] == '!' || command[pos] == '@')){
            ++pos;
        }
        command = "help" + sep + Poco::trim(command.substr(pos, command.size() - pos - 1));
    }
    auto tokensData = Tokenizer::tokenize(command);
    //if(-i dont execute waitEvent)
    Tokens result;
    result.push_back(std::get<std::string>(tokensData[0]));
    for(std::size_t i = 1; i < tokensData.size(); i++) {
        token_type token_type;
        std::string token_val;
        std::tie(token_val, token_type) = tokensData[i];
        auto processed_token = procesRawToken(token_type, token_val);
        if(processed_token.has_value()) {
        auto processed_token = procesRawToken(token_type, token_val);
            result.push_back(processed_token.value());
        } 
    }
    return result;
}

std::optional<std::string> DataProcesor::procesRawToken(const token_type& type, const std::string& val) {
    if(val == "") {
        return nullopt;
    } else if (type == token_type::text_no_eval) {
        return val;
    } else if (type == token_type::text_string || type == token_type::text_string_no_eval) {
        std::string tmp = val;
        char special_char = '\0';
        if(tmp.size() > 1 && tmp[0] == '\'' && tmp[tmp.size()-1] == '\'') {
            tmp = tmp.substr(1 ,tmp.size()-2);
            special_char = '\'';
        } else if(tmp.size() > 1 && tmp[0] == '"' && tmp[tmp.size()-1] == '"') {
            tmp = tmp.substr(1 ,tmp.size()-2);
            special_char = '"';
        }
        if(special_char == '\0') return evalArg(val);
        char previus = '\0';
        std::string result;
        for(auto c : tmp) {
            if(previus == '\\' && c == '\\') {
                previus = '\0';
                continue;
            } else if(previus == '\\' && c == special_char) {
                result[result.length()-1] = c;
            } else if(previus == '\\') {
                switch (c) {
                    case '\\':
                        result[result.length()-1] = '\\';
                        break;
                    case '?':
                        result[result.length()-1] = '\?';
                        break;
                    case 'a':
                        result[result.length()-1] = '\a';
                        break;
                    case 'b':
                        result[result.length()-1] = '\b';
                        break;
                    case 'f':
                        result[result.length()-1] = '\f';
                        break;
                    case 'n':
                        result[result.length()-1] = '\n';
                        break;
                    case 'r':
                        result[result.length()-1] = '\r';
                        break;
                    case 't':
                        result[result.length()-1] = '\t';
                        break;
                    case 'v':
                        result[result.length()-1] = '\v';
                        break;
                    default:
                        result += c;
                }
            } else {
                result += c;
            }
            previus = c;
        }
        if(type == token_type::text_string_no_eval) {
            return result;
        }
        return evalArg(result);
    }   
    return evalArg(val);
}

void DataProcesor::ExecuteCommand(const Tokens& command) {
    if(command.size() < 1) return;
    auto function_name = _executer.getFunc(command[0]);
    if (function_name == loopStart){
        for(std::size_t i = 0; i < _loops.size(); i++) _loops[i].commands.push_back(command);
        if(command.size() != 2 && command.size() != 3){ 
            cout << ConsoleStatusColor::error << "Invalid args count" << endl;
            if(_config.stop_on_error) {
                exit(EXIT_FAILURE);
            }
        }
        string id = "loop_" + to_string(_loops_id_gen++);
        if(command.size() == 3) id = command[2];
        print_msg("loop_start", id + ": Initialized");
        if(_config.add_timestamps) std::cout << ConsoleStatusColor::info << id << " initialized" << ConsoleStatusColor::normal << endl;
        _loops.push_back({.commands={}, .number_of_times=stoi(command[1]), .id=id, .start=chrono::system_clock::now(), .diffs={}});
    } else if (function_name == loopStop) {
        if(command.size() != 1){ 
            print_msg("loop_stop", "Invalid args count", true);
            return;
        }
        auto loop = _loops[_loops.size()-1];
        _loops.pop_back();
        for(std::size_t i = 0; i < _loops.size(); i++) _loops[i].commands.push_back(command);

        
        loop.diffs.push_back(getTimestamp(loop.start));

        for(int i = 1; i < loop.number_of_times; i++) {
            auto start = chrono::system_clock::now();
            for(auto c : loop.commands) {
                ExecuteCommand(c);
            }
            loop.diffs.push_back(getTimestamp(start));
        }
        if(_config.add_timestamps) {
            auto stop = chrono::system_clock::now();
            auto total_time = getTimestamp(loop.start);
            std::string output_data = loop.id + ": Run total - " + to_string(total_time.count()*1000)+"ms";
            if(loop.diffs.size() !=0) {
                double avg = 0;
                for(auto diff : loop.diffs) avg += diff.count()*1000;
                output_data += "\n" + loop.id + ": Run avg - " + to_string(avg / loop.diffs.size()) + "ms";
                
            }
            print_msg("loop_stop", output_data);
        }
    } else {
        for(std::size_t i = 0; i < _loops.size(); i++) _loops[i].commands.push_back(command);
        _executer.execute(command);
    }   
}

std::string DataProcesor::evalArg(std::string value) {
    size_t n = 10000;
    while (n-->0) {
        size_t var_pose_start;
        size_t var_pose_stop;
        std::tie(var_pose_start, var_pose_stop) = findNextVariablePos(value);
        if(var_pose_start == value.length()) {
            break;
        }
        if(var_pose_stop == value.length()) {
            print_msg("missing '}' on the end of variable", "", true);
            break;
        }
        if((var_pose_stop) - (var_pose_start+2) == 0) {
            value.erase(var_pose_start, var_pose_stop-var_pose_start+1);
            continue;
            //warning
        }
        auto S = value.substr(var_pose_start+2, (var_pose_stop) - (var_pose_start+2));
        value.erase(var_pose_start, var_pose_stop-var_pose_start+1);
        auto var = _executer.getS_var(S);
        if(var.isString()) {
            value.insert(var_pose_start, var.convert<std::string>());
        } else {
            print_msg("Variable " + S + " cannot be converted to string", "", true);
            break;
        }
    }

    return value;
}

std::tuple<size_t, size_t> DataProcesor::findNextVariablePos(const std::string &data, size_t skip) {
    bool string_data = false;
    char string_char = '\0';
    char last_char = '\0';
    bool variable_data = false;
    size_t start = data.length();
    size_t stop = data.length();
    for (size_t i = skip; i<data.length(); i++) {
        char c = data[i];
        if(string_data) {
            if (last_char != '\\' && string_char == c) {
                string_data = false;
            }
        } else if(variable_data) {
            if (c == '\\'|| c == '{' || c == '[' || c == '(' || c == ']' || c == ')' || c == '$' || c == '\'' || c == '"') {
                print_msg("Invalid params: unsupported char in var name", "", true);
            } else if (c == '}') {
                stop = i;
                return {start, stop};
            } 
        } else {
            if (last_char == '\\') {
                if(c == '\\') {
                    last_char = '\0';
                    continue;
                }
            } else if (c == '\'' || c == '"') {
                string_data = true;
                string_char = c;
            } else if (last_char == '$' && c == '{' && !variable_data) {
                variable_data = true;
                start = i-1;
            }
        }
        if (last_char == '\\') {
            last_char = '\0'; //solution for \${}
        } else {
            last_char = c;
        }

    }
    return {start, stop};
}

void DataProcesor::print_msg(const std::string &message, const std::string &data, bool is_error) {
    if(is_error) {
        
        if(data != "") {
            cout << ConsoleStatusColor::normal << "-> " << colors::ConsoleColor::blue << message << ConsoleStatusColor::normal 
                << " ... " << ConsoleStatusColor::error << "ERR" << endl;
            cout << ConsoleStatusColor::error << data << endl; return;
        } else {
            cout << ConsoleStatusColor::normal << "-> " << ConsoleStatusColor::warning << message << ConsoleStatusColor::normal << endl;
        }
    } else {
        cout << ConsoleStatusColor::normal << "-> " << colors::ConsoleColor::blue << message << ConsoleStatusColor::normal 
            << " ... " << ConsoleStatusColor::ok << "OK" << endl;
        if(data != "") {
            cout << ConsoleStatusColor::normal << data << endl; return;
        }
    }
}

chrono::duration<double> DataProcesor::getTimestamp(chrono::_V2::system_clock::time_point start) {
    auto stop = chrono::system_clock::now();
    chrono::duration<double> diff(stop - start);
    return diff;
}
#include "privmx/endpoint/programs/privmxcli/Tokenizer.hpp"
#include <Poco/String.h>
using namespace std;
using namespace privmx::endpoint::privmxcli;

TokensInfo Tokenizer::tokenize(const string &line) {
    auto sep = ' ';
    string line_with_end_sep = line + sep;
    char previous = '\0';
    auto it = line_with_end_sep.begin();
    auto end = line_with_end_sep.end();
    char last_special_char = '\0';

    TokensInfo result;
    string token;
    int braces = 0;
    int square_brackets = 0;
    bool special_substr = false;
    bool JSON = false;
    bool JSON_string = false;
    char JSON_string_character = '\0';

    for(; it != end; ++it){
        char val = (*it);
        if(val == sep && !special_substr && !JSON){
            token = Poco::trim(token);
            if(token.size() > 0 || previous == last_special_char){
                token_type type = token_type::text;
                if(last_special_char == '"') {
                    type = token_type::text_string;
                } else if( last_special_char == '\''){
                    type = token_type::text_string_no_eval;
                } else if(JSON_string_character != '\0'){
                    type = token_type::JSON;
                }
                result.push_back({token, type});
                token.clear();
                previous = '\0';
                last_special_char = '\0';
                continue;
            }
        }
        if(JSON_string) {
            if(val == JSON_string_character && previous != '\\') {
                JSON_string = false;
            }
        } else if(JSON) {
            if (val == '"') {
                JSON_string_character = val;
                JSON_string = true;
            } else if(val == '{') {
                braces++;
            } else if(val == '}') {
                braces--;
            } else if(val == '[') {
                square_brackets++;
            } else if(val == ']') {
                square_brackets--;
            }
            if(braces == 0 && square_brackets == 0) JSON = false;
        } else if (special_substr) {
            if (val == last_special_char && previous != '\\') {
                special_substr = false;
            }
        } else {
            if ((val == '"' || val == '\'') && previous != '\\') {
                last_special_char = val;
                special_substr = true;
            } else if ((val == '{' || val == '[') && previous != '\\') {
                if(val == '{') {
                    braces++;
                } else {
                    square_brackets++;
                }
                JSON = true;
            }
        }
        token.push_back(val);
        if(val == '\\' && previous == '\\') {
            previous = '\0';
        } else {
            previous = val;
        }
    }

    return result;
}
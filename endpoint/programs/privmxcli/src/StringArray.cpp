#include "privmx/endpoint/programs/privmxcli/StringArray.hpp"

using namespace std;
using namespace privmx::endpoint::privmxcli;

StringArray::StringArray(const vector<string> &list) : array(list) {
    copyStringsPtrs();
}
StringArray::StringArray(const StringArray& obj) : array(obj.array) {
    copyStringsPtrs();
};
StringArray::StringArray(StringArray&& obj) : array(move(obj.array)) {
    copyStringsPtrs();
};
const char** StringArray::data() const {
    return (const char**)val;
}
string StringArray::str() const {
    string res = "[ ";
    for(auto &item : array){
        res.append("\"").append(item).append("\" ");
    }
    res.append("]");

    return res;
}


void StringArray::copyStringsPtrs() {
    for(int i = 0; i < array.size(); ++i){
        val[i] = array[i].data();
    }
    val[array.size()] = NULL;
}

#include <gtest/gtest.h>
#include "privmx/endpoint/programs/privmxcli/colors/Colors.hpp"
#include "privmx/endpoint/programs/privmxcli/Tokenizer.hpp"
#include "privmx/endpoint/programs/privmxcli/DataProcesor.hpp"
#include "privmx/endpoint/programs/privmxcli/StringFormater.hpp"

using namespace std;
using namespace privmx::endpoint::privmxcli;

class CLITest : public testing::Test {

protected:
    CLITest() {}
    void SetUp() override {
        //reset all global variables
        session = {};
        func_aliases = {};
        config_auto_completion = false;
        history_file_path = Poco::Path(Poco::Path::cacheHome(), "privmxcli_history").toString();
    }
    void TearDown() override {
        
    }
private:

};

TEST_F(CLITest, Colors) {
    testing::internal::CaptureStdout();
    cout << ConsoleStatusColor::warning << "text";
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "text");
}

TEST_F(CLITest, Tockenzer_1_string) {
    std::string command = "help \"a\"";
    auto output = Tokenizer::tokenize(command);
    std::tuple<std::string, token_type> val_0 = {"help", token_type::text};
    std::tuple<std::string, token_type> val_1 = {"\"a\"", token_type::text_string};
    EXPECT_EQ(output.size(), 2);
    EXPECT_EQ(output[0], val_0);
    EXPECT_EQ(output[1], val_1);
}

TEST_F(CLITest, Tockenzer_2_string) {
    std::string command = "help \"\\\\\"";
    auto output = Tokenizer::tokenize(command);
    EXPECT_EQ(output.size(), 2);
    std::tuple<std::string, token_type> val_0 = {"help", token_type::text};
    std::tuple<std::string, token_type> val_1 = {"\"\\\\\"", token_type::text_string};
    EXPECT_EQ(output[0], val_0);
    EXPECT_EQ(output[1], val_1);
}

TEST_F(CLITest, Tockenzer_3_JSON_object) {
    std::string command = "get {\"JSON\": \"test\"}";
    auto output = Tokenizer::tokenize(command);
    EXPECT_EQ(output.size(), 2);
    std::tuple<std::string, token_type> val_0 = {"get", token_type::text};
    std::tuple<std::string, token_type> val_1 = {"{\"JSON\": \"test\"}", token_type::JSON};
    EXPECT_EQ(output[0], val_0);
    EXPECT_EQ(output[1], val_1);
}

TEST_F(CLITest, Tockenzer_4_JSON_array) {
    std::string command = "get [\"text\", text, 123]";
    auto output = Tokenizer::tokenize(command);
    EXPECT_EQ(output.size(), 2);
    std::tuple<std::string, token_type> val_0 = {"get", token_type::text};
    std::tuple<std::string, token_type> val_1 = {"[\"text\", text, 123]", token_type::JSON};
    EXPECT_EQ(output[0], val_0);
    EXPECT_EQ(output[1], val_1);
}

TEST_F(CLITest, Tockenzer_5_$) {
    std::string command = "get ${a}";
    auto output = Tokenizer::tokenize(command);
    EXPECT_EQ(output.size(), 2);
    std::tuple<std::string, token_type> val_0 = {"get", token_type::text};
    std::tuple<std::string, token_type> val_1 = {"${a}", token_type::text};
    EXPECT_EQ(output[0], val_0);
    EXPECT_EQ(output[1], val_1);
}

TEST_F(CLITest, Tockenzer_5_double_separator) {
    std::string command = "get  a";
    auto output = Tokenizer::tokenize(command);
    EXPECT_EQ(output.size(), 3);
    std::tuple<std::string, token_type> val_0 = {"get", token_type::text};
    std::tuple<std::string, token_type> val_1 = {"", token_type::text};
    std::tuple<std::string, token_type> val_2 = {"a", token_type::text};
    EXPECT_EQ(output[0], val_0);
    EXPECT_EQ(output[1], val_1);
    EXPECT_EQ(output[2], val_2);
}

TEST_F(CLITest, StringFormater_toCPP_1) {
    std::string text = "blach blach";
    std::ostringstream str;
    StringFormater::toCPP(str, text);
    std::string formatted_text = str.str();
    EXPECT_EQ(formatted_text, "\"blach blach\"");
}

TEST_F(CLITest, StringFormater_toCPP_2) {
    std::string text = "value_\"'_";
    std::ostringstream str;
    StringFormater::toCPP(str, text);
    std::string formatted_text = str.str();
    EXPECT_EQ(formatted_text, "\"value_\\\"'_\"");
}

TEST_F(CLITest, StringFormater_toPython_1) {
    std::string text = "blach blach";
    std::ostringstream str;
    StringFormater::toPython(str, text);
    std::string formatted_text = str.str();
    EXPECT_EQ(formatted_text, "'blach blach'");
}

TEST_F(CLITest, StringFormater_toPython_2) {
    std::string text = "value_\"'_";
    std::ostringstream str;
    StringFormater::toPython(str, text);
    std::string formatted_text = str.str();
    EXPECT_EQ(formatted_text, "'value_\"\\'_'");
}

TEST_F(CLITest, Executer_set) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    executer.execute({"s", "a", "b"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting variable ... OK \n-> RESULT:\n");
    EXPECT_EQ("b", session["a"]->convert<std::string>());
}

TEST_F(CLITest, Executer_set_2) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    executer.execute({"s", "a", "b"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting variable ... OK \n-> RESULT:\n");
    EXPECT_EQ("b", session["a"]->convert<std::string>());
}

TEST_F(CLITest, Executer_get) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na: a\n");
}

TEST_F(CLITest, Executer_set_get) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    executer.execute({"s", "a", "b"});
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting variable ... OK \n-> RESULT:\n-> getting variable ... OK \n-> RESULT:\na: b\n");
}

TEST_F(CLITest, Executer_set_get_$) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    executer.execute({"s", "a", "b"});
    executer.execute({"s", "b", "c"});
    executer.execute({"g", "${a}"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting variable ... OK \n-> RESULT:\n-> setting variable ... OK \n-> RESULT:\n-> getting variable ... OK \n-> RESULT:\n${a}: ${a}\n");
}

TEST_F(CLITest, Executer_alias) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    executer.execute({"s", "a", "a"});
    executer.execute({"a", "b", "a"});
    executer.execute({"g", "b"});
    executer.execute({"s", "a", "b"});
    executer.execute({"g", "b"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting variable ... OK \n-> RESULT:\n-> setting variable alias ... OK \n-> RESULT:\n-> getting variable ... OK \n-> RESULT:\nb: a\n-> setting variable ... OK \n-> RESULT:\n-> getting variable ... OK \n-> RESULT:\nb: b\n");
}

TEST_F(CLITest, Executer_falias) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    executer.execute({"fa", "gg", "get"});
    executer.execute({"gg", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting function alias ... OK \n-> RESULT:\n-> getting variable ... OK \n-> RESULT:\na: a\n");
}

TEST_F(CLITest, Executer_get_format_cpp_string) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::cpp});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("value_\"'_"));
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na: \"value_\\\"'_\"\n");
}

TEST_F(CLITest, Executer_get_format_cpp_number) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::cpp});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("1357"));
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na: 1357\n");
}

TEST_F(CLITest, Executer_get_format_python_string) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::python});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("value_\"'_"));
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na: 'value_\"\\'_'\n");
}

TEST_F(CLITest, Executer_get_format_python_number) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::python});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("1357"));
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na: 1357\n");
}

TEST_F(CLITest, Executer_get_format_bash_string) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("value_\"'_"));
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na: value_\"'_\n");
}

TEST_F(CLITest, Executer_get_format_bash_number) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("1357"));
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na: 1357\n");
}

TEST_F(CLITest, Executer_get_format_std_string) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::default_std});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("value_\"'_"));
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na (string): value_\"'_\n");
}

TEST_F(CLITest, Executer_get_format_std_number) {
    Executer executer = Executer(this_thread::get_id(), {.get_format=get_format_type::default_std});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("1357"));
    executer.execute({"g", "a"});
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na (number): 1357\n");
}

TEST_F(CLITest, DataProcesor_double_separator_set) {
    DataProcesor data_procesor = DataProcesor(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    data_procesor.processLine("s  a b");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting variable ... OK \n-> RESULT:\n");
    EXPECT_EQ("b", session["a"]->convert<std::string>());
}

TEST_F(CLITest, DataProcesor_set) {
    DataProcesor data_procesor = DataProcesor(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    data_procesor.processLine("s a b");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting variable ... OK \n-> RESULT:\n");
    EXPECT_EQ("b", session["a"]->convert<std::string>());
}

TEST_F(CLITest, DataProcesor_get) {
    DataProcesor data_procesor = DataProcesor(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    data_procesor.processLine("g a");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\na: a\n");
}

TEST_F(CLITest, DataProcesor_set_get_$) {
    DataProcesor data_procesor = DataProcesor(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    data_procesor.processLine("s a b");
    data_procesor.processLine("s b c");
    data_procesor.processLine("g ${a}");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> setting variable ... OK \n-> RESULT:\n-> setting variable ... OK \n-> RESULT:\n-> getting variable ... OK \n-> RESULT:\nb: c\n");
}

TEST_F(CLITest, DataProcesor_eval_$_val) {
    DataProcesor data_procesor = DataProcesor(this_thread::get_id(), {.get_format=get_format_type::bash});
    testing::internal::CaptureStdout();
    session["a"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("$"));
    session["b"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("{c}"));
    session["c"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("d"));
    session["d"] = std::make_shared<Poco::Dynamic::Var>(Poco::Dynamic::Var("value_d"));
    data_procesor.processLine("g ${a}${b}");
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(output, "-> getting variable ... OK \n-> RESULT:\nd: value_d\n");
}

int main(int argc, char **argv){
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
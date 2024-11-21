## Informacje

Privmxcli i simple command line interface fo privmx-endpoint and privmx-bridge

# Args
- `-c <command>`
    execute single cli command at the strat of program
- `-s <data>`
    set cli environment variable at the strat of program
- `-f <file>`
    execute cli commands form the file, it is executed after all commands form -c or -s
- `-g <format>` - set output printing mode
    "0"|"default" - bash like with information about data type
    "1"|"bash" - bash like
    "2"|"cpp" - cpp like
    "3"|"python" - python like
- `-i`
    interactive mode
- `-e`
    exit on error
- `-T`
    add timestamp for every command

# Basic privmxcli commands
- `alias` -  create new alias for variable
- `copy` - copy variable to other variable
- `falias` - create new alias for function
- `get` - read variable data
- `help`- help
- `loopStart` - stat of loop
- `loopStop` - end of loop
- `quit` - exit for cli
- `saveToFile` - write variable to file
- `set` - create variable
- `setFromFile` - read data form file to Var
- `sleep` - sleep for N ms
- `addFront` - add second variable to the front of first variable
- `addBack` - add second variable to the back of first variable
- `addFrontString` - add variable string to the front of variable
- `addBackString` - add variable string to the back of variable

# Default aliases
- `a` - alias for 'alias'
- `aF` - alias for 'addFront'
- `aB` - alias for 'addBack'
- `aFS` - alias for 'addFrontString'
- `aBS` - alias for 'addBackString'
- `c` - alias for 'copy'
- `exit` - alias for 'quit'
- `fa` - alias for 'falias'
- `g` - alias for 'get'
- `h` - alias for 'help'
- `s` - alias for 'set'


# Variables  
- `${<variable>}` - recursive reference to \<variable\> (evaluation is not performed only for data stored in '').
Such a variable can be placed in any text, but when it is between the characters " " it is not evaluated. Maximum times the text can be evaluated before program force stop evaluation is 1000000.

# Passing data
- `<data>`  - text or number (space or end of line is the separator), characters { } [ ] " ' $ may cause unusual behavior - is subjected to evaluation related to '${}'
- `"<data>"` - text, character \\ is used as escape character for \\ and " - is subjected to evaluation related to '${}'
- `'<data>'` - text, character \\ is used as escape character for \\ and ' - isn't subjected to evaluation related to '${}'
- `{<data>}` - JSON object - is subjected to evaluation related to '${}'
- `[<data>]` - JSON array - is subjected to evaluation related to '${}'

## Artifacts | Not obvious behavior

# Calling not initialized variable
- `get variable` -> variable
- `get ${variable}` -> variable

# creating variable starting and ending with "
- `set variable_0  "value_0"`- "value" is read as "\<data\>" 
- `get variable_0` -> value_0
- `set variable_1 \"value_1\"` - \"value\" is read as \<data\> 
- `get variable_1` -> \"value_1\"
- `set variable_2 "\"value_2\""`
- `get variable_2` -> "value_2"
- `set variable_3 '"value_3"'`
- `get variable_3` -> "value_3"

# Using variable in JSON
- `set path '"Path"'` - you must use '"<string>"' or "\"<string>\"" because the text in JSON must have ""
- `useJSONArrayString [${path}]`


# Loop in variable evaluation
- `set a '${b}'`
- It's imposable to use `set a ${b}` or `set a "${b}"`, because variable will be evaluated ${b} -> b
- `set b '${a}'`
- It's imposable to use `set b ${a}` or `set b "${a}"`, because variable will be evaluated ${a} -> ${b} -> b
- `get a` -> ${b}
- `get b` -> ${a}
- `get ${a}` -> data can be evaluated max 1000000 times


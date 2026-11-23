# PrivMX CLI

PrivMX CLI is a simple command line interface fo PrivMX Endpoint and PrivMX Bridge.

## Arguments

- `-c <command>`
  execute a single cli command at the start of a program
- `-s <data>`
  set cli environment variable at the start of a program
- `-f <file>`
  execute cli commands form the file, it is executed after all commands form -c or -s
- `-g <format>` - set output printing mode
  "0"|"default" - bash like with information about data type
  "1"|"bash" - bash like
  "2"|"cpp" - cpp like
  "3"|"python" - python like
- `-i`
  interactive mode
- `-q`
  quiet mode - only command results are printed on stdout, everything else (library logs, progress, errors) goes to stderr.
  A build with `PRIVMX_BUILD_LOGGER` still writes the library logs from before the arguments are parsed on stdout.
  Every result is printed on a single line, `get` prints the bare value, without the variable name and without the formatting set by -g
- `-e`
  exit the program on the first error, with a non-zero exit code
- `-T`
  add timestamp for every command
- `-h`
  print help and exit

## Basic PrivMX CLI commands

- `alias` - create new alias for a variable
- `copy` - copy variable to other variable
- `falias` - create new alias for a function
- `get` - read variable data, a dotted name reads a field of the stored JSON
- `help`- help
- `loopStart` - stat of a loop
- `loopStop` - end of a loop
- `quit` - exit cli
- `saveToFile` - write variable to a file, overwriting it
- `set` - create a variable
- `setFromFile` - read the whole file into a variable, its size is stored in \<variable\>_size
- `sleep` - sleep for N ms
- `addFront` - add a second variable to the front of first variable
- `addBack` - add a second variable to the back of first variable
- `addFrontString` - add a variable string to the front of variable
- `addBackString` - add a variable string to the back of variable

## Default aliases

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

## Variables

- `${<variable>}` - recursive reference to \<variable\> (evaluation is not performed only for data stored in '').
  Such a variable can be placed in any text, also between the characters " " and inside a JSON argument, for example `{"solution":"${solutionId}"}`.
  The value is inserted as it is, so a value holding `"` or `\` breaks the JSON around it. Maximum times the text can be evaluated before program forces stop evaluation is 1000000.
- `${<variable>.<field>}` - reads a field of the JSON stored in \<variable\>. Segments are separated by `.`, a numeric segment indexes a JSON array,
  for example `${last_result.solutionId}` or `${last_result.readItems.0.contextId}`. An unknown variable or field evaluates to the text of the reference itself, like any uninitialized variable.
  A dotted name can be used wherever a variable name is accepted, so also in `get` and `saveToFile`.

## Command results

Every endpoint and bridge command stores its result in the variable `last_result`. A result that is a plain value is stored as is, a JSON object or array is stored as its JSON text,
so `${last_result}` can be passed to the next command and `${last_result.<field>}` reads a single field.

- `<variable> = <command> <args>` - stores the result in \<variable\> as well as in `last_result`. Spaces around `=` are required

```
bridge.setBridgeApiCreds <api_key_id> <api_key_secret> <url>
bridge.solution.createSolution {"name": "my solution"}
context = bridge.context.createContext {"solution": "${last_result.solutionId}", "name": "my context", "scope": "private"}
get context.contextId
saveToFile context.contextId context_id.txt
```

With `-q` every command prints its result as one line on stdout, so a script that ends with a `get` needs no parsing:

```sh
CONTEXT_ID=$(privmxcli -q -e -f setup.pmx | tail -1)
```

## Error handling

Commands given with `-c`, `-s` and `-f` form one batch. A command that fails stops the batch - the rest of the current file and all the
files after it are not loaded, so no command runs on a state left behind by a failed one. The same applies to a file that cannot be opened.
If the batch was stopped and `-i` was not given, the program exits with a non-zero exit code.

`-e` is stronger: it ends the program on the first error instead of only stopping the batch, so not even interactive mode is entered.

In interactive mode nothing is stopped, every prompt starts over. An error reported by a command running in a background thread
(`core.waitEvent`) does not stop the batch either.

## Files

- `setFromFile <variable> <path>` - read the whole file into \<variable\>, the number of bytes read is stored in \<variable\>_size.
  Fails if the file cannot be read
- `saveToFile <variable> <path>` - write \<variable\> to the file, overwriting it. \<variable\> may be a dotted name.
  Fails if the variable holds no text or the file cannot be written

Files are read and written as they are, without any encoding conversion. A variable read from a binary file is kept whole and can be
written back with `saveToFile`, but passing it inside a JSON argument is not reliable - bytes that are not valid text break the JSON.

## Passing data

- `<data>` - text or number (space or end of line is the separator), characters { } [ ] " ' \$ may cause unusual behavior - is subjected to evaluation related to '${}'
- `"<data>"` - text, character \\ is used as escape character for \\ and " - is subjected to evaluation related to '${}'
- `'<data>'` - text, character \\ is used as escape character for \\ and ' - isn't subjected to evaluation related to '${}'
- `{<data>}` - JSON object - is subjected to evaluation related to '${}'
- `[<data>]` - JSON array - is subjected to evaluation related to '${}'

## Artifacts / Unusual behavior

## Calling not initialized variable

- `get variable` -> variable
- `get ${variable}` -> variable

## Creating variable starting and ending with "

- `set variable_0  "value_0"`- "value" is read as "\<data\>"
- `get variable_0` -> value_0
- `set variable_1 \"value_1\"` - \"value\" is read as \<data\>
- `get variable_1` -> \"value_1\"
- `set variable_2 "\"value_2\""`
- `get variable_2` -> "value_2"
- `set variable_3 '"value_3"'`
- `get variable_3` -> "value_3"

## Using variable in JSON

- `set path Path` and `useJSONArrayString ["${path}"]` - the quotes belong to the JSON, the variable holds the bare value
- `set path '"Path"'` and `useJSONArrayString [${path}]` - works as well, here the variable carries its own quotes

## Loop in variable evaluation

- `set a '${b}'`
- It's impossible to use `set a ${b}` or `set a "${b}"`, because variable will be evaluated ${b} -> b
- `set b '${a}'`
- It's impossible to use `set b ${a}` or `set b "${a}"`, because variable will be evaluated ${a} -> ${b} -> b
- `get a` -> ${b}
- `get b` -> ${a}
- `get ${a}` -> data can be evaluated max 1000000 times

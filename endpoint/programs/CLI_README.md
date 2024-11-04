## Informacje

# Opcje
- `-c <arg>` - wykonaj polecenie - function_name, Args
- `-s <arg>` - utwórz zmienną - var_name, var_value
- `-f <arg>` - wykonaj polecenia z pliku - filepath 
- `-g <arg>` - tryb wyświetlania get
    "1"|"bash" - bash like
    "2"|"cpp" - cpp like
    "3"|"python" - python like
- `-i` - tryb interaktywny
- `-e` - zatrzymaj działanie po wystąpieniu dowolnego błędu
- `-T` - dodaj timestampy to wykonywanych poleceń

# Polecenia privmxcli
- `a` - alias for 'alias'
- `alias` -  add alias for var
- `c` - alias for 'copy'
- `copy` - copy var
- `exit` - alias for 'quit'
- `fa` - alias for 'falias'
- `falias` - add function aliass
- `g` - alias for 'get'
- `get` - get Var
- `getEvent` - endpoint function
- `h` - alias for 'help'
- `help`- help
- `loopStart` - end of loop
- `loopStop` - start loop
- `quit` - quit
- `s` - alias for 'set'
- `saveToFile` - write data to file
- `set` - set Var
- `setFromFile` - read data form file to Var
- `sleep` - sleep for
- `addFront` - add variable to the fornt of variable
- `addBack` - add variable to the back of variable
- `addFrontString` - add string to the fornt of variable
- `addBackString` - add string to the back of variable
- `aF` - alias for 'addFront'
- `aB` - alias for 'addBack'
- `aFS` - alias for 'addFrontString'
- `aBS` - alias for 'addBackString'
- `sleep` - sleep for

# Czytanie danych
- `<text>`  - dane typu tekst albo liczba (spacja albo koniec lini jest separatorem) // znaki { } [ ] " ' $ mogą powodować nietypowe zachowanie - podlega ewaluacji związanej z '${}' 
- `"<text>"` - dane w formacie znakiem początku i końca jest ", znak \\ jest używany do eskepowania znaku \\ i " - podlega ewaluacji związanej z '${}'
- `'<text>'` - dane typu tekst gdzie znakiem początku i końca jest ', znak \\ jest używany do eskepowania \\ i ' - nie podlega ewaluacji związanej z '${}'
- `{<JSON>}` - dane zapisane w postacie JSON object - podlega ewaluacji związanej z '${}' 
- `[<JSON>]` - dane zapisane w postacie JSON array - podlega ewaluacji związanej z '${}' 

# Zmienne 
- `${<variable>}` - odwołanie rekurencyjne się do zmiennej \<variable\> (ewaluacja nie jest wykonywana tylko w przypadku danych zapisanych w "").
Można taką zmienna umieszczać w dowolnym tekście, jednak gdy znajduje sie ona pomiedzy znakami " " to nie jest ewaluowana

## Artefakty | Nie oczywiste zachowanie

# Wołanie nie zainicjowane zmiennej
- `get variable` -> variable
- `get ${variable}` -> variable

# Ustawianie zmiennej do użycia za pomocą  
- `set variable_0  value_0`
- `get variable_0` -> value_0
- `set variable_1 ${variable_0}`
- `get variable_1` -> value_0

# Tworzenie zmiennej zaczynającej i kończącej się ""
- `set variable_0  "value_0"`- "value" jest czytanie jako string
- `get variable_0` -> value_0
- `set variable_1 \"value_1\"` - \"value\" jest czytanie jako tekst (bo " jest użyty \\)
- `get variable_1` -> \"value_1\"
- `set variable_2 "\"value_2\""`
- `get variable_2` -> "value_2"
- `set variable_3 '"value_3"'`
- `get variable_3` -> "value_3"

# Użycie zmiennej w JSON
- `set path "\"<Path_cert>""` - trzeba użyć zapisy "\" \"" bo tekst w JSON msi posiadać "" // trzeba to naprawić by było czytelniejsze
- `setCertsPath [${path}]`

# Ewaluacja zmiennej
- następuje on po przeczytaniu danych w dowolnym formacie nie będącym c++ string'iem lub nie znajduję się pomiedzy ""

# Pętla przy ewaluacji
- `set a '${b}'`
- Nie jest możliwe użycie `set a ${b}` albo `set a "${b}"`, bo zostanie wykonana ewaluacja zmiennej ${b} -> b
- `set b '${a}'`
- Nie jest możliwe użycie `set b ${a}` albo `set b "${a}"`, bo zostanie wykonana ewaluacja zmiennej ${a} -> ${b} -> b (bo b jeszcze nie ma wartości)
- `get a` -> ${b}
- `get b` -> ${a}
- `get ${a}` -> program wykonuje max 10000 iteracji


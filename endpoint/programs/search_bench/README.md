# Search Bench

`search_bench` to program pomocniczy do ręcznego odpalania benchmarków i eksperymentów związanych z modułem search. `main.cpp` pełni rolę entrypointu i dispatchera, a właściwe scenariusze są implementowane jako osobne test suites w katalogu `suites/`.

## Build

Z głównego katalogu repo:

```bash
cmake --build build --target search_bench -j4
```

Jeżeli binarka nie startuje z powodu brakujących bibliotek współdzielonych, załaduj środowisko wygenerowane przez Conan.

Przykład:

```bash
source ./build/build/Debug/generators/conanrun.sh
./build/endpoint/programs/search_bench/search_bench --help
```

## Uruchamianie

Składnia:

```bash
search_bench [--profile <none|perf>] [--profile-out <dir>] [--list] \
  <PrivKey> <SolutionId> <BridgeUrl> <ContextId>

search_bench [--profile <none|perf>] [--profile-out <dir>] \
  <suite> [--search-index <id>] <PrivKey> <SolutionId> <BridgeUrl> <ContextId> <rfc_dir_path> <messages_dir_path>
```

Tryb listowania:

```bash
search_bench [--profile <none|perf>] [--profile-out <dir>] \
  --list <PrivKey> <SolutionId> <BridgeUrl> <ContextId>
```

Argumenty pozycyjne:

- `suite` - nazwa scenariusza do uruchomienia
- `PrivKey` - klucz prywatny użytkownika
- `SolutionId` - identyfikator solution
- `BridgeUrl` - adres Bridge
- `ContextId` - identyfikator kontekstu
- `rfc_dir_path` - katalog z plikami RFC lub innymi materiałami referencyjnymi dla suite'a
- `messages_dir_path` - katalog z wiadomościami lub dokumentami wejściowymi dla suite'a

Opcje:

- `--list` - ignoruje uruchomienie suite'a i wypisuje listę search indexów dla `ContextId`
- `--search-index <id>` - opcjonalne `search index id`, dostępne później w `runtime.options.searchIndex`
- `--profile none` - uruchomienie bez profilowania, domyślne zachowanie
- `--profile perf` - uruchomienie benchmarku pod `perf record`
- `--profile-out <dir>` - katalog, do którego zostanie zapisany wynik `perf`
- `--help` - wypisanie usage i listy dostępnych suite'ów

Uwagi:

- w trybie `--list` wymagane są tylko: `PrivKey`, `SolutionId`, `BridgeUrl`, `ContextId`
- jeśli `--list` zostanie podane razem z pełną formą wywołania zawierającą `suite`, `rfc_dir_path` i `messages_dir_path`, te dodatkowe argumenty są ignorowane
- jeśli `--search-index` nie zostanie podane, `runtime.options.searchIndex` jest pustym stringiem

## Dostępne suites

Aktualnie zarejestrowany jest jeden suite:

- `batch_add_and_search` - tworzy indeks, dodaje paczkę dokumentów i wykonuje zapytanie wyszukiwania

Rejestr suite'ów znajduje się w [SearchBenchSuites.cpp](SearchBenchSuites.cpp).

## Przykłady

Uruchomienie bez profilowania:

```bash
source ./build/build/Debug/generators/conanrun.sh
./build/endpoint/programs/search_bench/search_bench \
  batch_add_and_search \
  --search-index existing-index-id \
  "$PRIV_KEY" "$SOLUTION_ID" "$BRIDGE_URL" "$CONTEXT_ID" \
  <rfc_dir_path> \
  <messages_dir_path>
```

Uruchomienie z `perf`:

```bash
source ./build/build/Debug/generators/conanrun.sh
./build/endpoint/programs/search_bench/search_bench \
  --profile perf \
  --profile-out /tmp/search-bench-profiles \
  batch_add_and_search \
  "$PRIV_KEY" "$SOLUTION_ID" "$BRIDGE_URL" "$CONTEXT_ID" \
  <rfc_dir_path> \
  <messages_dir_path>
```

Wypisanie search indexów bez uruchamiania suite'a:

```bash
source ./build/build/Debug/generators/conanrun.sh
./build/endpoint/programs/search_bench/search_bench \
  --list \
  "$PRIV_KEY" "$SOLUTION_ID" "$BRIDGE_URL" "$CONTEXT_ID"
```

Pomocniczy skrypt z przykładowymi parametrami jest w [run.sh](run.sh).

Lista suite'ów wykonywanych przez skrypty pomocnicze jest w [suites.sh](suites.sh). Plik definiuje tablicę bashową `SEARCH_BENCH_SUITES`, której każdy wpis jest fragmentem komendy zaczynającym się od nazwy suite'a i może zawierać dodatkowe argumenty, np. `batch_add_1000 --search-index existing-index-id`. `run.sh` i `run-perf.sh` ładują tę listę przez `source` i wykonują wpisy po kolei.

## Profilowanie `perf`

Tryb `perf` jest zaimplementowany jako wrapper wokół właściwego uruchomienia benchmarku. Program:

1. uruchamia `perf record`
2. startuje pod nim ponownie `search_bench`
3. dziecku przekazuje `--profile=none`, żeby uniknąć zapętlenia
4. zapisuje wynik do pliku `<profile-out>/<suite>.perf.data`

Implementacja jest w [SearchBenchProfiler.cpp](SearchBenchProfiler.cpp).

Po udanym przebiegu można wygenerować flame graph komendą:

```bash
perf script -i /tmp/search-bench-profiles/batch_add_and_search.perf.data \
  | stackcollapse-perf.pl \
  | flamegraph.pl \
  > /tmp/search-bench-profiles/batch_add_and_search.svg
```

Uwagi praktyczne:

- `perf`, `stackcollapse-perf.pl` i `flamegraph.pl` muszą być dostępne w systemie
- na części maszyn `perf` może być zablokowany przez `kernel.perf_event_paranoid`
- jeśli `perf record` zakończy się błędem, program zwróci kod błędu tego procesu
- w trybie `--list --profile perf` wynik zapisuje się do `list_search_indexes.perf.data`

## Dane wejściowe

Program przyjmuje dwa niezależne katalogi wejściowe:

- `rfc_dir_path`
- `messages_dir_path`

Dzięki temu suite'y nie muszą zakładać, że dane leżą pod podkatalogami typu `rfc/` albo `msgs/`.

Dla obecnego `batch_add_and_search` wykorzystywany jest:

- `messages_dir_path` - katalog z plikami `*.json`

`rfc_dir_path` jest już dostępny w `runtime.options`, ale ten konkretny suite go obecnie nie używa.

Przykładowy układ danych:

```text
<rfc_dir_path>/
  *.txt
  *.md

<messages_dir_path>/
  *.json
```

Obecny suite:

- czyta dokumenty bezpośrednio z `messages_dir_path/*.json`
- z każdego pliku pobiera pole `data`
- ładuje maksymalnie 100 dokumentów

Wspólne helpery do pracy z danymi są w [SearchBenchHelpers.hpp](SearchBenchHelpers.hpp).

## Architektura

Podział odpowiedzialności:

- [main.cpp](main.cpp) - parsowanie opcji, wybór między listowaniem indeksów a uruchomieniem suite'a, uruchomienie profilera
- [SearchBenchCli.cpp](SearchBenchCli.cpp) - parser argumentów CLI
- [SearchBenchRuntime.cpp](SearchBenchRuntime.cpp) - tworzenie połączenia i API
- [SearchBenchHelpers.cpp](SearchBenchHelpers.cpp) - współdzielone helpery
- [SearchBenchSuites.cpp](SearchBenchSuites.cpp) - rejestr suite'ów
- `suites/*.cpp` - implementacje konkretnych scenariuszy

## Jak dodać nowy test suite

Najprostsza ścieżka:

1. Dodaj nowy plik nagłówkowy i implementację w `endpoint/programs/search_bench/suites/`, np. `MySuite.hpp` i `MySuite.cpp`.
2. Zadeklaruj funkcję w stylu:

```cpp
void runMySuite(RuntimeContext& runtime);
```

3. W implementacji używaj `runtime.options` do parametrów wejściowych, w szczególności `runtime.options.rfcDir` i `runtime.options.messagesDir`, oraz `runtime.connection`, `runtime.kvdbApi`, `runtime.storeApi`, `runtime.searchApi` do pracy z endpointem.
   `runtime.options.searchIndex` zawiera opcjonalne id indeksu przekazane z CLI.
4. Nie hardkoduj w suite'ach nazw podkatalogów typu `rfc` albo `msgs`. Jeśli suite potrzebuje takich danych, powinien korzystać z przekazanych ścieżek.
5. Jeśli potrzebujesz kodu współdzielonego między suite'ami, przenieś go do `SearchBenchHelpers.*` albo `SearchBenchRuntime.*`, zamiast duplikować logikę.
6. Dodaj nową wartość do `enum class SuiteId` w [SearchBenchSuites.hpp](SearchBenchSuites.hpp).
7. Dołącz nowy nagłówek w `SearchBenchSuites.cpp`.
8. Zarejestruj suite w `getSuiteDefinitions()` przez wpis zawierający:
   - `id`
   - `name`
   - `description`
   - wskaźnik do funkcji `run`
9. Przebuduj target:

```bash
cmake --build build --target search_bench -j4
```

10. Sprawdź, czy nowy suite jest widoczny w:

```bash
./build/endpoint/programs/search_bench/search_bench --help
```

11. Jeśli ma być uruchamiany przez skrypty wsadowe, dopisz jego nazwę do `SEARCH_BENCH_SUITES` w [suites.sh](suites.sh).

## Przykładowy szablon suite'a

Nagłówek:

```cpp
#pragma once

#include "SearchBenchRuntime.hpp"

namespace search_bench {

void runMySuite(RuntimeContext& runtime);

}  // namespace search_bench
```

Implementacja:

```cpp
#include "MySuite.hpp"

#include <iostream>

namespace search_bench {

void runMySuite(RuntimeContext& runtime) {
    std::cout << "Running suite for context: " << runtime.options.contextId << '\n';

    auto users = getContextUsersWithPubKeys(runtime);
    std::cout << "Users in context: " << users.size() << '\n';
}

}  // namespace search_bench
```

## Uwagi implementacyjne

- `CMakeLists.txt` używa `file(GLOB_RECURSE ... CONFIGURE_DEPENDS ...)`, więc nowe pliki `*.cpp` z `search_bench` są automatycznie dobierane do targetu po reconfigure/buildzie.
- CLI wymaga 7 argumentów pozycyjnych dla uruchomienia suite'a albo 4 argumentów pozycyjnych dla `--list`.
- Jeśli benchmark potrzebuje dodatkowych parametrów specyficznych dla suite'a, najprostsza droga to rozszerzenie `ProgramOptions` i parsera w `SearchBenchCli.*`.

/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_UTILS_SINGLETONSLOT_HPP_
#define _PRIVMXLIB_UTILS_SINGLETONSLOT_HPP_

#include <memory>

namespace privmx {
namespace utils {

/**
 * @brief Miejsce na instancje singletona trzymanego rowniez przez `SingletonsHolder`.
 *
 * **Problem, ktory rozwiazuje.** Kazdy z tych singletonow ma dwoch wlascicieli: wlasny statyczny
 * uchwyt oraz `SingletonsHolder`, ktory przy zamykaniu wola `freeInstance()` w ustalonej
 * kolejnosci. Kolejnosc niszczenia statykow miedzy jednostkami kompilacji jest **nieokreslona**,
 * wiec statyczny uchwyt moze zniknac przed destruktorem `SingletonsHolder` - i wtedy
 * `freeInstance()` siega do zwolnionej pamieci. Zdarzylo sie to realnie: po przeniesieniu
 * `PublicKeyCache` do `libprivmxendpointcore.so`, czyli do tej samej biblioteki co
 * `SingletonsHolder`, ASAN zglasza use-after-free przy wyjsciu z programu. Wczesniej uklad
 * bibliotek przypadkiem maskowal ten blad.
 *
 * **Jak dziala.** Znacznik `alive()` jest zwyklym `bool`-em: jest inicjowany stale i nie ma
 * destruktora, wiec mozna go czytac przez caly czas zycia programu - takze wtedy, gdy sam slot
 * juz nie istnieje. `freeInstance()` sprawdza go, zanim dotknie slotu.
 *
 * **Czego nie psuje.** Slot nadal niszczy sie sam, wiec program, ktory nie uzywa
 * `SingletonsHolder` (np. testy jednostkowe `utils`), dalej posprzata przy wyjsciu - to wazne
 * dla `Executor`, ktorego destruktor zatrzymuje pule watkow. A gdy `SingletonsHolder` istnieje,
 * to on trzyma ostatnia referencje, wiec faktyczna kolejnosc niszczenia obiektow pozostaje ta,
 * ktora narzuca jego destruktor.
 *
 * **Ograniczenie.** `ref()` wolno wolac tylko z zywego programu, nie w trakcie niszczenia
 * statykow. Zaden `getInstance()` nie jest wolany na tym etapie.
 */
template <typename T>
class SingletonSlot {
public:
    /// Czy slot jeszcze istnieje. Bezpieczne do czytania zawsze, takze po jego zniszczeniu.
    static bool alive() { return _alive; }

    std::shared_ptr<T>& ref() { return _ptr; }

    ~SingletonSlot() { _alive = false; }

private:
    std::shared_ptr<T> _ptr;
    static inline bool _alive = true;
};

} // namespace utils
} // namespace privmx

#endif // _PRIVMXLIB_UTILS_SINGLETONSLOT_HPP_

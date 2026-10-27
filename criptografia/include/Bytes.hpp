/**
 * @file Bytes.hpp
 * @brief Tipos e concept básicos para trabalhar com sequências de bytes.
 */

#ifndef BYTES_HPP
#define BYTES_HPP

#include <ranges>
#include <span>
#include <type_traits>
#include <vector>

/**
 * @brief Sequência de bytes genérica (chaves, nonces, textos cifrados...).
 */
using Bytes = std::vector<unsigned char>;

/**
 * @brief Concept: qualquer sequência contínua na memória cujos elementos
 *        têm 1 byte.
 *
 * Exemplos que satisfazem: `std::string`, `std::string_view`, `Bytes`,
 * `std::span<const unsigned char>`, `std::array<char, N>` e Segredo<T>.
 *
 * Arrays brutos (como o literal `"oi"`, que é um `const char[3]`) são
 * recusados de propósito: eles incluem o `'\0'` final, que seria
 * criptografado sem ninguém perceber. Use `std::string_view("oi")`.
 *
 * Um concept é uma condição que o compilador verifica ao instanciar um
 * template. Se o tipo não satisfizer, o erro aparece na chamada, com uma
 * mensagem clara, em vez de no meio da implementação.
 *
 * @tparam T Tipo a verificar.
 */
template <typename T>
concept ContainerDeBytes =
    std::ranges::contiguous_range<T> &&
    std::ranges::sized_range<T> &&
    sizeof(std::ranges::range_value_t<T>) == 1 &&
    !std::is_array_v<std::remove_cvref_t<T>>;

/**
 * @brief Enxerga qualquer ContainerDeBytes como uma sequência de
 *        `unsigned char`, sem copiar nada.
 *
 * @tparam R Tipo do container (deduzido automaticamente).
 * @param container Container a enxergar.
 * @return Uma visão (span) dos mesmos bytes.
 */
template <ContainerDeBytes R>
std::span<const unsigned char> comoBytes(const R& container) {
    return {reinterpret_cast<const unsigned char*>(std::ranges::data(container)),
            std::ranges::size(container)};
}

#endif // BYTES_HPP

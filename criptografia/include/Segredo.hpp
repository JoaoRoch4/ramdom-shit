/**
 * @file Segredo.hpp
 * @brief Template de classe que guarda um dado sensível e o apaga da memória
 *        automaticamente quando deixa de existir.
 */

#ifndef SEGREDO_HPP
#define SEGREDO_HPP

#include "Bytes.hpp"

#include <sodium.h>

#include <utility>

/**
 * @brief Guarda um segredo (senha, chave...) e o apaga da memória ao ser
 *        destruído (RAII).
 *
 * Sem isso, uma senha continua na memória RAM depois de usada e pode
 * aparecer em um despejo de memória ou no arquivo de swap. O destrutor usa
 * `sodium_memzero`, que o compilador não pode remover por otimização.
 *
 * Um Segredo não pode ser copiado sem querer (o construtor de cópia é
 * removido); para duplicar, use copia(). Ele pode ser movido.
 *
 * Como é um template, funciona com qualquer container de bytes que possa
 * ser esvaziado:
 * @code
 * Segredo<std::string> senha{std::string("abc")};
 * Segredo<Bytes> chave = cripto.gerarChave();
 * cripto.criptografar(std::string_view("oi"), chave);  // Segredo também é um ContainerDeBytes
 * @endcode
 *
 * @tparam T Container dono dos bytes, ex.: `std::string` ou `Bytes`.
 */
template <ContainerDeBytes T>
    requires requires(T& t) { t.clear(); }
class Segredo {
public:
    /// Cria um segredo vazio.
    Segredo() = default;

    /**
     * @brief Copia um valor existente para dentro do segredo.
     * @param valor Valor a copiar (o original não é alterado).
     */
    explicit Segredo(const T& valor) : valor_(valor) {}

    /**
     * @brief Recebe um valor temporário e apaga a origem depois de copiar.
     *
     * Um simples `std::move` poderia deixar restos do texto na origem (por
     * exemplo, no buffer interno de strings pequenas). Copiar e depois
     * apagar a origem garante que só sobra uma cópia: a deste objeto.
     *
     * @param valor Valor temporário; fica vazio e zerado após a chamada.
     */
    explicit Segredo(T&& valor) : valor_(valor) { apagar(valor); }

    /// Apaga o conteúdo da memória.
    ~Segredo() { apagar(valor_); }

    Segredo(const Segredo&) = delete;
    Segredo& operator=(const Segredo&) = delete;

    /**
     * @brief Move o segredo de outro objeto, zerando a origem.
     * @param outro Segredo de origem; fica vazio.
     */
    Segredo(Segredo&& outro) : valor_(outro.valor_) { apagar(outro.valor_); }

    /**
     * @brief Substitui o conteúdo pelo de outro segredo, zerando a origem.
     * @param outro Segredo de origem; fica vazio.
     * @return Este objeto.
     */
    Segredo& operator=(Segredo&& outro) {
        if (this != &outro) {
            apagar(valor_);
            valor_ = outro.valor_;
            apagar(outro.valor_);
        }
        return *this;
    }

    /**
     * @brief Cria uma cópia explícita (cópias acidentais são proibidas).
     * @return Um novo Segredo com o mesmo conteúdo.
     */
    Segredo copia() const { return Segredo(valor_); }

    /**
     * @brief Acesso somente leitura ao valor guardado.
     * @return Referência constante para o valor.
     */
    const T& valor() const { return valor_; }

    /// @return Ponteiro para o primeiro byte (permite usar como ContainerDeBytes).
    auto data() const { return std::ranges::data(valor_); }

    /// @return Quantidade de bytes.
    auto size() const { return std::ranges::size(valor_); }

    /// @return Iterador para o início.
    auto begin() const { return std::ranges::begin(valor_); }

    /// @return Iterador para o fim.
    auto end() const { return std::ranges::end(valor_); }

    /// @return true se o segredo estiver vazio.
    bool empty() const { return std::ranges::empty(valor_); }

    /**
     * @brief Compara dois segredos em tempo constante.
     *
     * O tempo gasto não depende de onde está a primeira diferença, então
     * ninguém consegue descobrir o segredo medindo o tempo da comparação.
     *
     * @param outro Segredo a comparar.
     * @return true se forem iguais.
     */
    bool operator==(const Segredo& outro) const {
        return size() == outro.size() &&
               sodium_memcmp(data(), outro.data(), size()) == 0;
    }

private:
    /**
     * @brief Zera os bytes de um container e o esvazia.
     * @param container Container a apagar.
     */
    static void apagar(T& container) {
        sodium_memzero(std::ranges::data(container), std::ranges::size(container));
        container.clear();
    }

    T valor_{}; ///< O segredo propriamente dito.
};

#endif // SEGREDO_HPP

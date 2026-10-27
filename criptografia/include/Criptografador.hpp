/**
 * @file Criptografador.hpp
 * @brief Declaração da classe Criptografador, que criptografa e descriptografa
 *        mensagens usando a biblioteca libsodium.
 *
 * Dois modos de uso são oferecidos:
 *  - **Chave aleatória**: uma chave de 32 bytes é gerada e precisa ser guardada.
 *  - **Senha**: a chave é derivada de uma senha com o algoritmo Argon2id.
 *
 * Em ambos os modos a cifra usada é a XChaCha20-Poly1305 (AEAD), que além de
 * esconder a mensagem detecta qualquer alteração no texto criptografado.
 */

#ifndef CRIPTOGRAFADOR_HPP
#define CRIPTOGRAFADOR_HPP

#include "Bytes.hpp"
#include "Segredo.hpp"

#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

/**
 * @brief Exceção lançada quando uma operação criptográfica falha.
 *
 * Exemplos: chave errada, senha errada, texto cifrado corrompido ou
 * hexadecimal inválido.
 */
class ErroCriptografia : public std::runtime_error {
public:
    /**
     * @brief Cria a exceção com uma mensagem explicativa.
     * @param mensagem Descrição do erro.
     */
    explicit ErroCriptografia(const std::string& mensagem)
        : std::runtime_error(mensagem) {}
};

/**
 * @brief Criptografa e descriptografa mensagens com a libsodium.
 *
 * As funções públicas são templates: aceitam qualquer ContainerDeBytes
 * (`std::string`, `std::string_view`, `Bytes`, Segredo<T>...). Elas apenas
 * convertem a entrada com comoBytes() e chamam a implementação real, que não
 * é template e fica no `.cpp`. Assim o header continua pequeno.
 *
 * O resultado da criptografia é sempre devolvido em hexadecimal para poder
 * ser exibido na tela, copiado e colado.
 *
 * Formato do texto cifrado:
 *  - Modo chave: `nonce (24 bytes) || cifrado + tag (n + 16 bytes)`
 *  - Modo senha: `salt (16 bytes) || nonce (24 bytes) || cifrado + tag`
 *
 * O nonce e o salt não são secretos; eles viajam junto com a mensagem para
 * que a descriptografia consiga reproduzir o processo.
 *
 * @code
 * Criptografador cripto;
 * Segredo<Bytes> chave = cripto.gerarChave();
 * std::string cifrado = cripto.criptografar(std::string("Ola, mundo!"), chave);
 * std::string original = cripto.descriptografar(cifrado, chave);
 * @endcode
 */
class Criptografador {
public:
    /**
     * @brief Inicializa a libsodium.
     *
     * Precisa ser chamado antes de qualquer função da biblioteca; pode ser
     * chamado várias vezes sem problema.
     *
     * @throws ErroCriptografia se a libsodium não puder ser inicializada.
     */
    Criptografador();

    /**
     * @brief Gera uma chave aleatória criptograficamente segura.
     * @return Chave de 32 bytes, apagada da memória automaticamente.
     */
    Segredo<Bytes> gerarChave() const;

    /**
     * @brief Criptografa uma mensagem com uma chave.
     *
     * Um nonce aleatório novo é gerado a cada chamada, então criptografar a
     * mesma mensagem duas vezes produz resultados diferentes.
     *
     * @tparam M Tipo da mensagem (deduzido).
     * @tparam C Tipo da chave (deduzido).
     * @param mensagem Texto ou bytes a criptografar.
     * @param chave Chave de 32 bytes (veja gerarChave()).
     * @return Nonce + texto cifrado, em hexadecimal.
     * @throws ErroCriptografia se a chave tiver tamanho errado.
     */
    template <ContainerDeBytes M, ContainerDeBytes C>
    std::string criptografar(const M& mensagem, const C& chave) const {
        return criptografarBytes(comoBytes(mensagem), comoBytes(chave));
    }

    /**
     * @brief Descriptografa uma mensagem produzida por criptografar().
     *
     * @tparam C Tipo da chave (deduzido).
     * @param cifradoHex Saída de criptografar(), em hexadecimal.
     * @param chave A mesma chave usada para criptografar.
     * @return A mensagem original.
     * @throws ErroCriptografia se a chave estiver errada ou se o texto
     *         cifrado tiver sido alterado.
     */
    template <ContainerDeBytes C>
    std::string descriptografar(std::string_view cifradoHex, const C& chave) const {
        return descriptografarBytes(cifradoHex, comoBytes(chave));
    }

    /**
     * @brief Criptografa uma mensagem usando uma senha.
     *
     * A chave é derivada da senha com Argon2id e um salt aleatório. Essa
     * derivação é propositalmente lenta para dificultar ataques de força bruta.
     *
     * @tparam M Tipo da mensagem (deduzido).
     * @tparam S Tipo da senha (deduzido).
     * @param mensagem Texto ou bytes a criptografar.
     * @param senha Senha escolhida pelo usuário.
     * @return Salt + nonce + texto cifrado, em hexadecimal.
     * @throws ErroCriptografia se faltar memória para derivar a chave.
     */
    template <ContainerDeBytes M, ContainerDeBytes S>
    std::string criptografarComSenha(const M& mensagem, const S& senha) const {
        return criptografarComSenhaBytes(comoBytes(mensagem), comoBytes(senha));
    }

    /**
     * @brief Descriptografa uma mensagem produzida por criptografarComSenha().
     *
     * @tparam S Tipo da senha (deduzido).
     * @param cifradoHex Saída de criptografarComSenha(), em hexadecimal.
     * @param senha A mesma senha usada para criptografar.
     * @return A mensagem original.
     * @throws ErroCriptografia se a senha estiver errada ou se o texto
     *         cifrado tiver sido alterado.
     */
    template <ContainerDeBytes S>
    std::string descriptografarComSenha(std::string_view cifradoHex, const S& senha) const {
        return descriptografarComSenhaBytes(cifradoHex, comoBytes(senha));
    }

    /**
     * @brief Converte bytes em texto hexadecimal (ex.: `{255, 10}` → `"ff0a"`).
     * @tparam R Tipo do container (deduzido).
     * @param bytes Bytes a converter.
     * @return Texto em hexadecimal minúsculo.
     */
    template <ContainerDeBytes R>
    static std::string paraHex(const R& bytes) {
        return paraHexBytes(comoBytes(bytes));
    }

    /**
     * @brief Converte texto hexadecimal em bytes (ex.: `"ff0a"` → `{255, 10}`).
     * @param hex Texto em hexadecimal.
     * @return Os bytes correspondentes.
     * @throws ErroCriptografia se o texto não for hexadecimal válido.
     */
    static Bytes deHex(std::string_view hex);

private:
    /// Implementação de criptografar().
    std::string criptografarBytes(std::span<const unsigned char> mensagem,
                                  std::span<const unsigned char> chave) const;

    /// Implementação de descriptografar().
    std::string descriptografarBytes(std::string_view cifradoHex,
                                     std::span<const unsigned char> chave) const;

    /// Implementação de criptografarComSenha().
    std::string criptografarComSenhaBytes(std::span<const unsigned char> mensagem,
                                          std::span<const unsigned char> senha) const;

    /// Implementação de descriptografarComSenha().
    std::string descriptografarComSenhaBytes(std::string_view cifradoHex,
                                             std::span<const unsigned char> senha) const;

    /// Implementação de paraHex().
    static std::string paraHexBytes(std::span<const unsigned char> bytes);

    /**
     * @brief Deriva uma chave de 32 bytes a partir de uma senha e um salt.
     * @param senha Senha do usuário.
     * @param salt Salt aleatório de 16 bytes.
     * @return Chave derivada, apagada da memória automaticamente.
     * @throws ErroCriptografia se faltar memória para o Argon2id.
     */
    Segredo<Bytes> derivarChave(std::span<const unsigned char> senha,
                                std::span<const unsigned char> salt) const;
};

#endif // CRIPTOGRAFADOR_HPP

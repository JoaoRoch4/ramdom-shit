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

#include <stdexcept>
#include <string>
#include <vector>

/**
 * @brief Sequência de bytes genérica (chaves, nonces, textos cifrados...).
 */
using Bytes = std::vector<unsigned char>;

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
 * @brief Criptografa e descriptografa mensagens de texto com a libsodium.
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
 * Bytes chave = cripto.gerarChave();
 * std::string cifrado = cripto.criptografar("Ola, mundo!", chave);
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
     * @return Chave de 32 bytes.
     */
    Bytes gerarChave() const;

    /**
     * @brief Criptografa uma mensagem com uma chave.
     *
     * Um nonce aleatório novo é gerado a cada chamada, então criptografar a
     * mesma mensagem duas vezes produz resultados diferentes.
     *
     * @param mensagem Texto a ser criptografado.
     * @param chave Chave de 32 bytes (veja gerarChave()).
     * @return Nonce + texto cifrado, em hexadecimal.
     * @throws ErroCriptografia se a chave tiver tamanho errado.
     */
    std::string criptografar(const std::string& mensagem, const Bytes& chave) const;

    /**
     * @brief Descriptografa uma mensagem produzida por criptografar().
     *
     * @param cifradoHex Saída de criptografar(), em hexadecimal.
     * @param chave A mesma chave usada para criptografar.
     * @return A mensagem original.
     * @throws ErroCriptografia se a chave estiver errada ou se o texto
     *         cifrado tiver sido alterado.
     */
    std::string descriptografar(const std::string& cifradoHex, const Bytes& chave) const;

    /**
     * @brief Criptografa uma mensagem usando uma senha.
     *
     * A chave é derivada da senha com Argon2id e um salt aleatório. Essa
     * derivação é propositalmente lenta para dificultar ataques de força bruta.
     *
     * @param mensagem Texto a ser criptografado.
     * @param senha Senha escolhida pelo usuário.
     * @return Salt + nonce + texto cifrado, em hexadecimal.
     * @throws ErroCriptografia se faltar memória para derivar a chave.
     */
    std::string criptografarComSenha(const std::string& mensagem, const std::string& senha) const;

    /**
     * @brief Descriptografa uma mensagem produzida por criptografarComSenha().
     *
     * @param cifradoHex Saída de criptografarComSenha(), em hexadecimal.
     * @param senha A mesma senha usada para criptografar.
     * @return A mensagem original.
     * @throws ErroCriptografia se a senha estiver errada ou se o texto
     *         cifrado tiver sido alterado.
     */
    std::string descriptografarComSenha(const std::string& cifradoHex, const std::string& senha) const;

    /**
     * @brief Converte bytes em texto hexadecimal (ex.: `{255, 10}` → `"ff0a"`).
     * @param bytes Bytes a converter.
     * @return Texto em hexadecimal minúsculo.
     */
    static std::string paraHex(const Bytes& bytes);

    /**
     * @brief Converte texto hexadecimal em bytes (ex.: `"ff0a"` → `{255, 10}`).
     * @param hex Texto em hexadecimal.
     * @return Os bytes correspondentes.
     * @throws ErroCriptografia se o texto não for hexadecimal válido.
     */
    static Bytes deHex(const std::string& hex);

private:
    /**
     * @brief Deriva uma chave de 32 bytes a partir de uma senha e um salt.
     * @param senha Senha do usuário.
     * @param salt Salt aleatório de 16 bytes.
     * @return Chave derivada.
     * @throws ErroCriptografia se faltar memória para o Argon2id.
     */
    Bytes derivarChave(const std::string& senha, const Bytes& salt) const;
};

#endif // CRIPTOGRAFADOR_HPP

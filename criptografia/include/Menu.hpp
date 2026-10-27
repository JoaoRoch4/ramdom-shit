/**
 * @file Menu.hpp
 * @brief Declaração da classe Menu, a interface de terminal do programa.
 */

#ifndef MENU_HPP
#define MENU_HPP

#include "Criptografador.hpp"

#include <string>
#include <string_view>

/**
 * @brief Menu interativo de terminal para criptografar e descriptografar.
 *
 * Exibe as opções, lê as respostas do usuário e usa um Criptografador para
 * fazer o trabalho. Senhas são lidas sem aparecer na tela.
 *
 * @code
 * Menu menu;
 * menu.executar();
 * @endcode
 */
class Menu {
public:
    /**
     * @brief Cria o menu e inicializa o Criptografador interno.
     * @throws ErroCriptografia se a libsodium não puder ser inicializada.
     */
    Menu() = default;

    /**
     * @brief Mostra o menu repetidamente até o usuário escolher sair.
     *
     * Erros de uma operação (senha errada, hex inválido...) são exibidos e o
     * menu continua funcionando.
     */
    void executar();

private:
    /**
     * @brief Gera uma chave, criptografa uma mensagem e mostra ambas.
     */
    void criptografarComChave();

    /**
     * @brief Lê uma mensagem cifrada e uma chave e mostra o texto original.
     */
    void descriptografarComChave();

    /**
     * @brief Criptografa uma mensagem com uma senha (digitada duas vezes).
     * @throws ErroCriptografia se as duas senhas digitadas forem diferentes.
     */
    void criptografarComSenha();

    /**
     * @brief Descriptografa uma mensagem com a senha e mostra o texto original.
     */
    void descriptografarComSenha();

    /**
     * @brief Mostra um texto e lê uma linha inteira digitada pelo usuário.
     * @param pergunta Texto exibido antes da leitura.
     * @return A linha digitada (pode conter espaços).
     */
    static std::string perguntar(std::string_view pergunta);

    /**
     * @brief Mostra um texto e lê uma senha sem exibi-la na tela.
     *
     * Se a entrada não for um terminal (ex.: redirecionada de um arquivo),
     * a leitura é feita normalmente.
     *
     * @param pergunta Texto exibido antes da leitura.
     * @return A senha digitada.
     */
    static std::string perguntarSenha(std::string_view pergunta);

    Criptografador cripto_; ///< Faz a criptografia de fato.
};

#endif // MENU_HPP

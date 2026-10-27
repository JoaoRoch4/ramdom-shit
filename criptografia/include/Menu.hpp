/**
 * @file Menu.hpp
 * @brief Declaração da classe Menu, a interface de terminal do programa.
 */

#ifndef MENU_HPP
#define MENU_HPP

#include "Cofre.hpp"
#include "Criptografador.hpp"
#include "Segredo.hpp"

#include <filesystem>
#include <string>
#include <string_view>

/**
 * @brief Menu interativo de terminal para criptografar e descriptografar.
 *
 * Exibe as opções, lê as respostas do usuário e usa um Criptografador para
 * fazer o trabalho. Senhas aparecem como `*` enquanto são digitadas.
 *
 * Toda chave ou senha criada é guardada em um Cofre protegido por senha
 * mestra. Ao descriptografar, o menu procura a mensagem no cofre, permite
 * usar o segredo guardado e compara o segredo digitado com o registrado.
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
     * @param arquivoCofre Caminho do arquivo do cofre.
     * @throws ErroCriptografia se a libsodium não puder ser inicializada.
     */
    explicit Menu(std::filesystem::path arquivoCofre = "cofre.dat");

    /**
     * @brief Abre (ou cria) o cofre e mostra o menu até o usuário escolher sair.
     *
     * Erros de uma operação (senha errada, hex inválido...) são exibidos e o
     * menu continua funcionando.
     *
     * @throws ErroCofre se a senha mestra for errada 3 vezes.
     */
    void executar();

private:
    /**
     * @brief Pede a senha mestra e abre o cofre, ou cria um novo se não existir.
     * @throws ErroCofre após 3 tentativas sem sucesso.
     */
    void abrirCofre();

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
     * @brief Lista todos os registros do cofre, com data, tipo e segredo.
     */
    void mostrarRegistro() const;

    /**
     * @brief Pede uma descrição e guarda o segredo usado no cofre.
     * @param tipo Chave ou senha.
     * @param segredo A chave (hex) ou a senha.
     * @param cifradoHex O texto cifrado gerado.
     * @throws ErroCofre se o cofre não puder ser salvo.
     */
    void registrarNoCofre(TipoSegredo tipo, Segredo<std::string> segredo, const std::string& cifradoHex);

    /**
     * @brief Procura a mensagem no cofre e informa o resultado ao usuário.
     * @param cifradoHex Texto cifrado digitado.
     * @param tipo Tipo de segredo esperado pela opção escolhida.
     * @return O registro, ou nullptr se não existir ou for de outro tipo.
     */
    const RegistroCofre* consultarCofre(std::string_view cifradoHex, TipoSegredo tipo) const;

    /**
     * @brief Decide qual segredo usar e compara com o registro do cofre.
     *
     * Se nada foi digitado, usa o segredo guardado. Caso contrário, informa
     * se o digitado confere com o do cofre e usa o digitado.
     *
     * @param registro Registro encontrado, ou nullptr.
     * @param digitado O que o usuário digitou.
     * @return O segredo a ser usado para descriptografar.
     */
    static Segredo<std::string> resolverSegredo(const RegistroCofre* registro,
                                                Segredo<std::string> digitado);

    /**
     * @brief Mostra um texto e lê uma linha inteira digitada pelo usuário.
     * @param pergunta Texto exibido antes da leitura.
     * @return A linha digitada (pode conter espaços).
     */
    static std::string perguntar(std::string_view pergunta);

    /**
     * @brief Mostra um texto e lê uma senha exibindo `*` no lugar de cada caractere.
     *
     * Aceita Backspace para apagar e Ctrl+C para cancelar. Se a entrada não
     * for um terminal (ex.: redirecionada de um arquivo), a leitura é feita
     * normalmente, linha a linha.
     *
     * @param pergunta Texto exibido antes da leitura.
     * @return A senha digitada, apagada da memória automaticamente.
     * @throws ErroCriptografia se o usuário cancelar com Ctrl+C.
     */
    static Segredo<std::string> perguntarSenha(std::string_view pergunta);

    // A ordem importa: cripto_ precisa ser construído antes de cofre_,
    // que guarda uma referência para ele.
    Criptografador cripto_; ///< Faz a criptografia de fato.
    Cofre cofre_;           ///< Registro das chaves e senhas criadas.
};

#endif // MENU_HPP

/**
 * @file main.cpp
 * @brief Menu interativo para criptografar e descriptografar mensagens.
 */

#include "Criptografador.hpp"

#include <iostream>
#include <string>

namespace {

/**
 * @brief Mostra um texto e lê uma linha inteira digitada pelo usuário.
 * @param pergunta Texto exibido antes da leitura.
 * @return A linha digitada (pode conter espaços).
 */
std::string perguntar(const std::string& pergunta) {
    std::cout << pergunta;
    std::string resposta;
    std::getline(std::cin, resposta);
    return resposta;
}

/**
 * @brief Gera uma chave, criptografa uma mensagem e mostra ambas.
 * @param cripto Criptografador já inicializado.
 */
void criptografarComChave(const Criptografador& cripto) {
    std::string mensagem = perguntar("Digite a mensagem: ");
    Bytes chave = cripto.gerarChave();

    std::cout << "\nChave (guarde-a!):      " << Criptografador::paraHex(chave) << '\n'
              << "Mensagem criptografada: " << cripto.criptografar(mensagem, chave) << "\n\n";
}

/**
 * @brief Lê uma mensagem cifrada e uma chave e mostra o texto original.
 * @param cripto Criptografador já inicializado.
 */
void descriptografarComChave(const Criptografador& cripto) {
    std::string cifrado = perguntar("Digite a mensagem criptografada (hex): ");
    Bytes chave = Criptografador::deHex(perguntar("Digite a chave (hex): "));

    // Calcula antes de imprimir: se lançar exceção, nada é exibido pela metade.
    std::string original = cripto.descriptografar(cifrado, chave);
    std::cout << "\nMensagem original: " << original << "\n\n";
}

/**
 * @brief Criptografa uma mensagem com uma senha e mostra o resultado.
 * @param cripto Criptografador já inicializado.
 */
void criptografarComSenha(const Criptografador& cripto) {
    std::string mensagem = perguntar("Digite a mensagem: ");
    std::string senha = perguntar("Digite a senha: ");

    std::cout << "\nMensagem criptografada: " << cripto.criptografarComSenha(mensagem, senha)
              << "\n\n";
}

/**
 * @brief Descriptografa uma mensagem com a senha e mostra o texto original.
 * @param cripto Criptografador já inicializado.
 */
void descriptografarComSenha(const Criptografador& cripto) {
    std::string cifrado = perguntar("Digite a mensagem criptografada (hex): ");
    std::string senha = perguntar("Digite a senha: ");

    std::string original = cripto.descriptografarComSenha(cifrado, senha);
    std::cout << "\nMensagem original: " << original << "\n\n";
}

} // namespace

/**
 * @brief Ponto de entrada: exibe o menu até o usuário escolher sair.
 * @return 0 em caso de sucesso, 1 se a libsodium não puder ser inicializada.
 */
int main() {
    try {
        Criptografador cripto;

        while (true) {
            std::cout << "=== Criptografia com libsodium ===\n"
                      << "1 - Criptografar (gera chave aleatoria)\n"
                      << "2 - Descriptografar com chave\n"
                      << "3 - Criptografar com senha\n"
                      << "4 - Descriptografar com senha\n"
                      << "0 - Sair\n"
                      << "Opcao: ";
            std::string opcao;
            if (!std::getline(std::cin, opcao) || opcao == "0") break;

            try {
                if (opcao == "1")      criptografarComChave(cripto);
                else if (opcao == "2") descriptografarComChave(cripto);
                else if (opcao == "3") criptografarComSenha(cripto);
                else if (opcao == "4") descriptografarComSenha(cripto);
                else                   std::cout << "Opcao invalida.\n\n";
            } catch (const ErroCriptografia& erro) {
                // Erros de uma operação não encerram o programa.
                std::cout << "\nErro: " << erro.what() << "\n\n";
            }
        }
    } catch (const ErroCriptografia& erro) {
        std::cerr << "Erro fatal: " << erro.what() << '\n';
        return 1;
    }
    return 0;
}

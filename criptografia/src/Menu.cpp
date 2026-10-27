/**
 * @file Menu.cpp
 * @brief Implementação da classe Menu, incluindo a leitura de senha oculta.
 */

#include "Menu.hpp"

#include <cstdio>
#include <iostream>
#include <print>

#ifdef _WIN32
    #define NOMINMAX
    #include <windows.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

namespace {

/**
 * @brief Desliga o eco do terminal enquanto o objeto existir (RAII).
 *
 * O construtor esconde o que é digitado e o destrutor restaura o terminal,
 * mesmo que uma exceção seja lançada no meio da leitura.
 */
class EcoDesligado {
public:
    /// Salva o modo atual do terminal e desliga o eco, se for um terminal.
    EcoDesligado() {
#ifdef _WIN32
        entrada_ = GetStdHandle(STD_INPUT_HANDLE);
        ativo_ = GetConsoleMode(entrada_, &modoOriginal_) != 0;
        if (ativo_) {
            SetConsoleMode(entrada_, modoOriginal_ & ~ENABLE_ECHO_INPUT);
        }
#else
        ativo_ = tcgetattr(STDIN_FILENO, &modoOriginal_) == 0;
        if (ativo_) {
            termios semEco = modoOriginal_;
            semEco.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &semEco);
        }
#endif
    }

    /// Restaura o modo original do terminal.
    ~EcoDesligado() {
        if (!ativo_) return;
#ifdef _WIN32
        SetConsoleMode(entrada_, modoOriginal_);
#else
        tcsetattr(STDIN_FILENO, TCSANOW, &modoOriginal_);
#endif
        // O Enter não foi ecoado, então pulamos a linha manualmente.
        std::println("");
    }

    EcoDesligado(const EcoDesligado&) = delete;
    EcoDesligado& operator=(const EcoDesligado&) = delete;

private:
    bool ativo_ = false; ///< true se a entrada é um terminal e o eco foi desligado.
#ifdef _WIN32
    HANDLE entrada_ = nullptr; ///< Handle da entrada do console.
    DWORD modoOriginal_ = 0;   ///< Modo do console antes da alteração.
#else
    termios modoOriginal_{};   ///< Configuração do terminal antes da alteração.
#endif
};

} // namespace

void Menu::executar() {
    while (true) {
        std::print("=== Criptografia com libsodium ===\n"
                   "1 - Criptografar (gera chave aleatoria)\n"
                   "2 - Descriptografar com chave\n"
                   "3 - Criptografar com senha\n"
                   "4 - Descriptografar com senha\n"
                   "0 - Sair\n"
                   "Opcao: ");
        std::string opcao;
        if (!std::getline(std::cin, opcao) || opcao == "0") break;

        try {
            if (opcao == "1")      criptografarComChave();
            else if (opcao == "2") descriptografarComChave();
            else if (opcao == "3") criptografarComSenha();
            else if (opcao == "4") descriptografarComSenha();
            else                   std::println("Opcao invalida.\n");
        } catch (const ErroCriptografia& erro) {
            // Erros de uma operação não encerram o programa.
            std::println("\nErro: {}\n", erro.what());
        }
    }
}

void Menu::criptografarComChave() {
    std::string mensagem = perguntar("Digite a mensagem: ");
    Bytes chave = cripto_.gerarChave();
    std::string cifrado = cripto_.criptografar(mensagem, chave);

    std::println("\nChave (guarde-a!):      {}", Criptografador::paraHex(chave));
    std::println("Mensagem criptografada: {}\n", cifrado);
}

void Menu::descriptografarComChave() {
    std::string cifrado = perguntar("Digite a mensagem criptografada (hex): ");
    Bytes chave = Criptografador::deHex(perguntar("Digite a chave (hex): "));

    // Calcula antes de imprimir: se lançar exceção, nada é exibido pela metade.
    std::string original = cripto_.descriptografar(cifrado, chave);
    std::println("\nMensagem original: {}\n", original);
}

void Menu::criptografarComSenha() {
    std::string mensagem = perguntar("Digite a mensagem: ");
    std::string senha = perguntarSenha("Digite a senha: ");
    if (senha != perguntarSenha("Confirme a senha: ")) {
        throw ErroCriptografia("As senhas nao conferem.");
    }

    std::string cifrado = cripto_.criptografarComSenha(mensagem, senha);
    std::println("\nMensagem criptografada: {}\n", cifrado);
}

void Menu::descriptografarComSenha() {
    std::string cifrado = perguntar("Digite a mensagem criptografada (hex): ");
    std::string senha = perguntarSenha("Digite a senha: ");

    std::string original = cripto_.descriptografarComSenha(cifrado, senha);
    std::println("\nMensagem original: {}\n", original);
}

std::string Menu::perguntar(std::string_view pergunta) {
    std::print("{}", pergunta);
    std::string resposta;
    std::getline(std::cin, resposta);
    return resposta;
}

std::string Menu::perguntarSenha(std::string_view pergunta) {
    std::print("{}", pergunta);
    std::fflush(stdout);  // garante que a pergunta apareça antes de desligar o eco

    std::string senha;
    {
        EcoDesligado semEco;  // eco volta automaticamente ao sair deste bloco
        std::getline(std::cin, senha);
    }
    return senha;
}

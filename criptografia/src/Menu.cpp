/**
 * @file Menu.cpp
 * @brief Implementação da classe Menu, incluindo a leitura de senha com asteriscos.
 */

#include "Menu.hpp"

#include <cstdio>
#include <iostream>
#include <print>

#ifdef _WIN32
    #define NOMINMAX
    #include <windows.h>
    #include <conio.h>
    #include <io.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

namespace {

/// Código da tecla Ctrl+C quando ela chega como caractere comum.
constexpr int CTRL_C = 3;

/// Código da tecla Ctrl+D (fim de entrada no Linux/macOS).
constexpr int CTRL_D = 4;

/// Backspace no Windows e em alguns terminais.
constexpr int BACKSPACE = 8;

/// Backspace na maioria dos terminais Linux/macOS.
constexpr int DELETE = 127;

/**
 * @brief Coloca o terminal em modo "tecla a tecla, sem eco" enquanto o
 *        objeto existir (RAII).
 *
 * O construtor altera o terminal e o destrutor restaura o modo original,
 * mesmo que uma exceção seja lançada no meio da leitura.
 */
class TerminalSenha {
public:
    /// Salva o modo atual e desliga eco, modo canônico e sinais, se for um terminal.
    TerminalSenha() {
#ifdef _WIN32
        // No Windows, _getch() já lê uma tecla por vez e sem eco.
        ativo_ = _isatty(_fileno(stdin)) != 0;
#else
        ativo_ = tcgetattr(STDIN_FILENO, &modoOriginal_) == 0;
        if (ativo_) {
            termios modo = modoOriginal_;
            // ECHO: não mostrar teclas; ICANON: não esperar o Enter;
            // ISIG: Ctrl+C chega como caractere em vez de matar o programa.
            modo.c_lflag &= ~static_cast<tcflag_t>(ECHO | ICANON | ISIG);
            modo.c_cc[VMIN] = 1;   // read() retorna a cada 1 tecla
            modo.c_cc[VTIME] = 0;  // sem tempo limite
            tcsetattr(STDIN_FILENO, TCSANOW, &modo);
        }
#endif
    }

    /// Restaura o modo original do terminal.
    ~TerminalSenha() {
#ifndef _WIN32
        if (ativo_) tcsetattr(STDIN_FILENO, TCSANOW, &modoOriginal_);
#endif
    }

    TerminalSenha(const TerminalSenha&) = delete;
    TerminalSenha& operator=(const TerminalSenha&) = delete;

    /**
     * @brief Informa se a entrada é um terminal interativo.
     * @return false quando a entrada vem de um arquivo ou pipe.
     */
    bool ativo() const { return ativo_; }

    /**
     * @brief Lê uma única tecla, sem esperar o Enter.
     * @return O código da tecla ou EOF se a entrada acabou.
     */
    int lerTecla() const {
#ifdef _WIN32
        int tecla = _getch();
        // Setas, F1... chegam como dois códigos (0 ou 0xE0 + código); ignoramos.
        while (tecla == 0 || tecla == 0xE0) {
            _getch();
            tecla = _getch();
        }
        return tecla;
#else
        return std::getchar();
#endif
    }

private:
    bool ativo_ = false; ///< true se a entrada é um terminal.
#ifndef _WIN32
    termios modoOriginal_{}; ///< Configuração do terminal antes da alteração.
#endif
};

/**
 * @brief Diz se um byte é a continuação de um caractere UTF-8 (10xxxxxx).
 * @param byte Byte a verificar.
 * @return true se não for o primeiro byte de um caractere.
 */
bool ehContinuacaoUtf8(unsigned char byte) {
    return (byte & 0xC0) == 0x80;
}

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
    std::fflush(stdout);

    TerminalSenha terminal;  // modo original volta automaticamente no fim da função
    std::string senha;

    if (!terminal.ativo()) {
        // Entrada redirecionada (arquivo/pipe): lê a linha normalmente.
        std::getline(std::cin, senha);
        return senha;
    }

    while (true) {
        int tecla = terminal.lerTecla();

        if (tecla == '\n' || tecla == '\r' || tecla == EOF || tecla == CTRL_D) {
            break;
        }
        if (tecla == CTRL_C) {
            std::println("");
            throw ErroCriptografia("Operacao cancelada.");
        }
        if (tecla == BACKSPACE || tecla == DELETE) {
            if (senha.empty()) continue;
            // Remove o caractere inteiro (acentos ocupam vários bytes em UTF-8).
            while (!senha.empty() && ehContinuacaoUtf8(static_cast<unsigned char>(senha.back()))) {
                senha.pop_back();
            }
            senha.pop_back();
            std::print("\b \b");  // volta, apaga o '*' com espaço, volta de novo
        } else if (static_cast<unsigned char>(tecla) >= 32) {
            senha.push_back(static_cast<char>(tecla));
            // Um '*' por caractere: bytes de continuação UTF-8 não ganham outro.
            if (!ehContinuacaoUtf8(static_cast<unsigned char>(tecla))) {
                std::print("*");
            }
        }
        std::fflush(stdout);
    }

    std::println("");  // o Enter não foi exibido, então pulamos a linha aqui
    return senha;
}

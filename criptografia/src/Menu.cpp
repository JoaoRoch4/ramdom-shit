/**
 * @file Menu.cpp
 * @brief Implementação da classe Menu: opções, integração com o cofre e
 *        leitura de senha com asteriscos.
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

Menu::Menu(std::filesystem::path arquivoCofre)
    : cofre_(std::move(arquivoCofre), cripto_) {}

void Menu::executar() {
    abrirCofre();

    while (true) {
        std::print("=== Criptografia com libsodium ===\n"
                   "1 - Criptografar (gera chave aleatoria)\n"
                   "2 - Descriptografar com chave\n"
                   "3 - Criptografar com senha\n"
                   "4 - Descriptografar com senha\n"
                   "5 - Ver registro do cofre\n"
                   "0 - Sair\n"
                   "Opcao: ");
        std::string opcao;
        if (!std::getline(std::cin, opcao) || opcao == "0") break;

        try {
            if (opcao == "1")      criptografarComChave();
            else if (opcao == "2") descriptografarComChave();
            else if (opcao == "3") criptografarComSenha();
            else if (opcao == "4") descriptografarComSenha();
            else if (opcao == "5") mostrarRegistro();
            else                   std::println("Opcao invalida.\n");
        } catch (const std::runtime_error& erro) {
            // ErroCriptografia e ErroCofre: erros de uma operação não encerram o programa.
            std::println("\nErro: {}\n", erro.what());
        }
    }
}

void Menu::abrirCofre() {
    constexpr int TENTATIVAS = 3;

    if (!cofre_.existe()) {
        std::println("Nenhum cofre encontrado. Vamos criar um novo.");
        for (int i = 0; i < TENTATIVAS; ++i) {
            Segredo<std::string> senha = perguntarSenha("Crie a senha mestra: ");
            if (senha.empty()) {
                std::println("A senha mestra nao pode ser vazia.");
            } else if (senha != perguntarSenha("Confirme a senha mestra: ")) {
                std::println("As senhas nao conferem.");
            } else {
                cofre_.abrir(std::move(senha));
                std::println("Cofre criado.\n");
                return;
            }
        }
        throw ErroCofre("Nao foi possivel criar o cofre.");
    }

    for (int i = 0; i < TENTATIVAS; ++i) {
        try {
            cofre_.abrir(perguntarSenha("Senha mestra: "));
            std::println("Cofre aberto ({} registros).\n", cofre_.registros().size());
            return;
        } catch (const ErroCofre& erro) {
            std::println("{}", erro.what());
        }
    }
    throw ErroCofre("Muitas tentativas erradas.");
}

void Menu::criptografarComChave() {
    std::string mensagem = perguntar("Digite a mensagem: ");
    Segredo<Bytes> chave = cripto_.gerarChave();
    Segredo<std::string> chaveHex(Criptografador::paraHex(chave));
    std::string cifrado = cripto_.criptografar(mensagem, chave);

    std::println("\nChave (guarde-a!):      {}", chaveHex.valor());
    std::println("Mensagem criptografada: {}\n", cifrado);
    registrarNoCofre(TipoSegredo::Chave, std::move(chaveHex), cifrado);
}

void Menu::descriptografarComChave() {
    std::string cifrado = perguntar("Digite a mensagem criptografada (hex): ");
    const RegistroCofre* registro = consultarCofre(cifrado, TipoSegredo::Chave);

    Segredo<std::string> chaveHex(perguntar(registro ? "Digite a chave (hex) [Enter = usar a do cofre]: "
                                                     : "Digite a chave (hex): "));
    chaveHex = resolverSegredo(registro, std::move(chaveHex));
    Segredo<Bytes> chave(Criptografador::deHex(chaveHex.valor()));

    // Calcula antes de imprimir: se lançar exceção, nada é exibido pela metade.
    std::string original = cripto_.descriptografar(cifrado, chave);
    std::println("\nMensagem original: {}\n", original);
}

void Menu::criptografarComSenha() {
    std::string mensagem = perguntar("Digite a mensagem: ");
    Segredo<std::string> senha = perguntarSenha("Digite a senha: ");
    if (senha != perguntarSenha("Confirme a senha: ")) {  // operator== do Segredo
        throw ErroCriptografia("As senhas nao conferem.");
    }

    std::string cifrado = cripto_.criptografarComSenha(mensagem, senha);
    std::println("\nMensagem criptografada: {}\n", cifrado);
    registrarNoCofre(TipoSegredo::Senha, std::move(senha), cifrado);
}

void Menu::descriptografarComSenha() {
    std::string cifrado = perguntar("Digite a mensagem criptografada (hex): ");
    const RegistroCofre* registro = consultarCofre(cifrado, TipoSegredo::Senha);

    Segredo<std::string> senha = perguntarSenha(registro ? "Digite a senha [Enter = usar a do cofre]: "
                                                         : "Digite a senha: ");
    senha = resolverSegredo(registro, std::move(senha));

    std::string original = cripto_.descriptografarComSenha(cifrado, senha);
    std::println("\nMensagem original: {}\n", original);
}

void Menu::mostrarRegistro() const {
    const auto& registros = cofre_.registros();
    if (registros.empty()) {
        std::println("O cofre esta vazio.\n");
        return;
    }

    std::println("\n=== Registro do cofre ({}) ===", registros.size());
    for (const RegistroCofre& r : registros) {
        std::println("#{:<3} {}  [{}]  msg {}...  {}", r.id, r.dataHora, nomeDoTipo(r.tipo),
                     r.impressaoDigital.substr(0, 8), r.segredo.valor());
        if (!r.descricao.empty()) {
            std::println("     {}", r.descricao);
        }
    }
    std::println("");
}

void Menu::registrarNoCofre(TipoSegredo tipo, Segredo<std::string> segredo, const std::string& cifradoHex) {
    std::string descricao = perguntar("Descricao para o cofre (opcional): ");
    const RegistroCofre& registro = cofre_.adicionar(tipo, std::move(segredo), cifradoHex, descricao);
    std::println("Salvo no cofre como #{}.\n", registro.id);
}

const RegistroCofre* Menu::consultarCofre(std::string_view cifradoHex, TipoSegredo tipo) const {
    const RegistroCofre* registro = cofre_.buscar(cifradoHex);
    if (!registro) {
        std::println("(mensagem nao encontrada no cofre)");
        return nullptr;
    }
    if (registro->tipo != tipo) {
        std::println("Aviso: no cofre (#{}) esta mensagem foi criptografada com {}; use a opcao {}.",
                     registro->id, nomeDoTipo(registro->tipo),
                     registro->tipo == TipoSegredo::Chave ? 2 : 4);
        return nullptr;
    }

    std::print("Encontrada no cofre: #{} de {}", registro->id, registro->dataHora);
    if (!registro->descricao.empty()) std::print(" ({})", registro->descricao);
    std::println("");
    return registro;
}

Segredo<std::string> Menu::resolverSegredo(const RegistroCofre* registro,
                                           Segredo<std::string> digitado) {
    if (!registro) return digitado;
    if (digitado.empty()) {
        std::println("Usando o segredo guardado no registro #{}.", registro->id);
        return registro->segredo.copia();  // cópia explícita: Segredo não copia sem querer
    }
    if (registro->confere(digitado)) {
        std::println("[OK] Confere com o registro #{} do cofre.", registro->id);
    } else {
        std::println("[DIFERENTE] Nao confere com o registro #{} do cofre.", registro->id);
    }
    return digitado;
}

std::string Menu::perguntar(std::string_view pergunta) {
    std::print("{}", pergunta);
    std::string resposta;
    std::getline(std::cin, resposta);
    return resposta;
}

Segredo<std::string> Menu::perguntarSenha(std::string_view pergunta) {
    std::print("{}", pergunta);
    std::fflush(stdout);

    TerminalSenha terminal;  // modo original volta automaticamente no fim da função
    std::string senha;

    if (!terminal.ativo()) {
        // Entrada redirecionada (arquivo/pipe): lê a linha normalmente.
        std::getline(std::cin, senha);
        return Segredo<std::string>(std::move(senha));
    }

    while (true) {
        int tecla = terminal.lerTecla();

        if (tecla == '\n' || tecla == '\r' || tecla == EOF || tecla == CTRL_D) {
            break;
        }
        if (tecla == CTRL_C) {
            std::println("");
            Segredo<std::string> descartada(std::move(senha));  // zera o que já foi digitado
            throw ErroCriptografia("Operacao cancelada.");
        }
        if (tecla == BACKSPACE || tecla == DELETE) {
            if (senha.empty()) continue;
            // Remove o caractere inteiro (acentos ocupam vários bytes em UTF-8).
            // Zera cada byte antes de remover: pop_back() só diminui o tamanho.
            while (!senha.empty() && ehContinuacaoUtf8(static_cast<unsigned char>(senha.back()))) {
                senha.back() = '\0';
                senha.pop_back();
            }
            senha.back() = '\0';
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
    return Segredo<std::string>(std::move(senha));  // zera a string local
}

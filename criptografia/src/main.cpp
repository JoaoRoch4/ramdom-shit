/**
 * @file main.cpp
 * @brief Ponto de entrada do programa.
 */

#include "Menu.hpp"

#include <cstdio>
#include <print>

/**
 * @brief Cria o menu e o executa até o usuário escolher sair.
 * @return 0 em caso de sucesso, 1 se a libsodium não puder ser inicializada.
 */
int main() {
    try {
        Menu menu;
        menu.executar();
    } catch (const ErroCriptografia& erro) {
        std::println(stderr, "Erro fatal: {}", erro.what());
        return 1;
    }
    return 0;
}

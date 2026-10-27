/**
 * @file main.cpp
 * @brief Ponto de entrada do programa.
 */

#include "Menu.hpp"

#include <cstdio>
#include <print>

/**
 * @brief Cria o menu e o executa até o usuário escolher sair.
 * @return 0 em caso de sucesso; 1 se a libsodium falhar ou o cofre não abrir.
 */
int main() {
    try {
        Menu menu;
        menu.executar();
    } catch (const std::runtime_error& erro) {  // ErroCriptografia ou ErroCofre
        std::println(stderr, "Erro fatal: {}", erro.what());
        return 1;
    }
    return 0;
}

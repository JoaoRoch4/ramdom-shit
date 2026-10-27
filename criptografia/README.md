# Criptografia com libsodium (C++)

Programa de terminal que criptografa e descriptografa mensagens de dois jeitos:

| Opção | Como funciona |
|---|---|
| 1 / 2 | Gera uma **chave aleatória** de 32 bytes, mostra a chave e a mensagem criptografada; com as duas, recupera o original. |
| 3 / 4 | Usa uma **senha**: a chave é derivada com **Argon2id** e um salt aleatório. |

Ao digitar a senha aparece `*` para cada caractere (Backspace apaga,
Ctrl+C cancela). A leitura é tecla a tecla: `termios` no Linux/macOS e
`_getch()` no Windows. A senha é pedida duas vezes ao criptografar.

A cifra é a **XChaCha20-Poly1305** (AEAD): esconde a mensagem e detecta qualquer
alteração, chave errada ou senha errada.

## Estrutura

```
include/Criptografador.hpp   declaração da classe + documentação Doxygen
src/Criptografador.cpp       implementação com libsodium
include/Menu.hpp             declaração do menu de terminal
src/Menu.cpp                 menu interativo + leitura de senha oculta
src/main.cpp                 apenas o int main
```

Formato do texto cifrado (em hexadecimal):

- chave: `nonce (24) || cifrado || tag (16)`
- senha: `salt (16) || nonce (24) || cifrado || tag (16)`

## Dependências

- Compilador **C++23** com `<print>` (GCC 14+, Clang 18+, MSVC 2022 17.7+), CMake ≥ 3.16, pkg-config
- libsodium
  - Ubuntu/Debian: `sudo apt install libsodium-dev pkg-config`
  - macOS: `brew install libsodium pkg-config`
  - Windows (MSYS2): `pacman -S mingw-w64-x86_64-libsodium mingw-w64-x86_64-pkgconf`

## Compilar e rodar

```bash
cmake -S . -B build          # se o g++ padrão for antigo: CXX=g++-14 cmake -S . -B build
cmake --build build
./build/cripto
```

Sem CMake:

```bash
g++-14 -std=c++23 -Iinclude src/*.cpp -lsodium -o cripto
```

## Documentação

```bash
doxygen Doxyfile      # abre docs/html/index.html
```

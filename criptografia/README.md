# Criptografia com libsodium (C++)

Programa de terminal que criptografa e descriptografa mensagens de dois jeitos:

| Opção | Como funciona |
|---|---|
| 1 / 2 | Gera uma **chave aleatória** de 32 bytes, mostra a chave e a mensagem criptografada; com as duas, recupera o original. |
| 3 / 4 | Usa uma **senha**: a chave é derivada com **Argon2id** e um salt aleatório. |

A cifra é a **XChaCha20-Poly1305** (AEAD): esconde a mensagem e detecta qualquer
alteração, chave errada ou senha errada.

## Estrutura

```
include/Criptografador.hpp   declaração da classe + documentação Doxygen
src/Criptografador.cpp       implementação com libsodium
src/main.cpp                 menu interativo
```

Formato do texto cifrado (em hexadecimal):

- chave: `nonce (24) || cifrado || tag (16)`
- senha: `salt (16) || nonce (24) || cifrado || tag (16)`

## Dependências

- Compilador C++17, CMake ≥ 3.16, pkg-config
- libsodium
  - Ubuntu/Debian: `sudo apt install libsodium-dev pkg-config`
  - macOS: `brew install libsodium pkg-config`
  - Windows (MSYS2): `pacman -S mingw-w64-x86_64-libsodium mingw-w64-x86_64-pkgconf`

## Compilar e rodar

```bash
cmake -S . -B build
cmake --build build
./build/cripto
```

Sem CMake:

```bash
g++ -std=c++17 -Iinclude src/*.cpp -lsodium -o cripto
```

## Documentação

```bash
doxygen Doxyfile      # abre docs/html/index.html
```

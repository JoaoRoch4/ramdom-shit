# Criptografia com libsodium (C++)

Programa de terminal que criptografa e descriptografa mensagens de dois jeitos:

| Opção | Como funciona |
|---|---|
| 1 / 2 | Gera uma **chave aleatória** de 32 bytes, mostra a chave e a mensagem criptografada; com as duas, recupera o original. |
| 3 / 4 | Usa uma **senha**: a chave é derivada com **Argon2id** e um salt aleatório. |
| 5 | Mostra o **registro do cofre**: todas as chaves e senhas criadas. |

## Cofre (registro de chaves e senhas)

Ao iniciar, o programa pede a **senha mestra** do arquivo `cofre.dat` (na
primeira vez, cria um cofre novo). Cada chave ou senha usada para criptografar
é guardada nele com data, tipo e uma descrição opcional.

Ao descriptografar, a mensagem é reconhecida pela sua *impressão digital*
(os 16 primeiros bytes do texto cifrado, que são aleatórios):

- **Enter** sem digitar nada usa o segredo guardado no cofre;
- digitando um segredo, o programa diz se ele **confere** com o registrado
  (comparação em tempo constante).

O `cofre.dat` é criptografado com a própria classe `Criptografador`
(Argon2id + XChaCha20-Poly1305): sem a senha mestra ele é ilegível, e
qualquer alteração no arquivo faz a abertura falhar. **Se a senha mestra for
esquecida, o cofre não pode ser recuperado.**

Ao digitar a senha aparece `*` para cada caractere (Backspace apaga,
Ctrl+C cancela). A leitura é tecla a tecla: `termios` no Linux/macOS e
`_getch()` no Windows. A senha é pedida duas vezes ao criptografar.

A cifra é a **XChaCha20-Poly1305** (AEAD): esconde a mensagem e detecta qualquer
alteração, chave errada ou senha errada.

## Estrutura

```
include/Bytes.hpp            alias Bytes + concept ContainerDeBytes (templates)
include/Segredo.hpp          template Segredo<T>: apaga segredos da memória (RAII)
include/Criptografador.hpp   declaração da classe + documentação Doxygen
src/Criptografador.cpp       implementação com libsodium
include/Cofre.hpp            registro criptografado de chaves e senhas
src/Cofre.cpp                implementação do cofre
include/Menu.hpp             declaração do menu de terminal
src/Menu.cpp                 menu interativo + leitura de senha oculta
src/main.cpp                 apenas o int main
```

Formato do texto cifrado (em hexadecimal):

- chave: `nonce (24) || cifrado || tag (16)`
- senha: `salt (16) || nonce (24) || cifrado || tag (16)`

## Templates

- **`ContainerDeBytes`** (concept C++20): qualquer sequência contínua de bytes
  (`std::string`, `std::string_view`, `Bytes`, `std::span`, `std::array`,
  `Segredo`). Arrays brutos como `"oi"` são recusados porque incluiriam o `'\0'`.
- **Funções do `Criptografador`** são templates finos no header que convertem a
  entrada para `std::span` e chamam a implementação no `.cpp`.
- **`Segredo<T>`** guarda senhas e chaves e as zera com `sodium_memzero` ao ser
  destruído; não pode ser copiado sem querer (`copia()` é explícito) e compara
  em tempo constante (`operator==`).

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

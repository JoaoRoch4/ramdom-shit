/**
 * @file Criptografador.cpp
 * @brief Implementação da classe Criptografador usando a libsodium.
 */

#include "Criptografador.hpp"

#include <sodium.h>

namespace {

/// Tamanho da chave da XChaCha20-Poly1305 (32 bytes).
constexpr std::size_t TAMANHO_CHAVE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;

/// Tamanho do nonce da XChaCha20-Poly1305 (24 bytes).
constexpr std::size_t TAMANHO_NONCE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

/// Tamanho da tag de autenticação Poly1305 (16 bytes).
constexpr std::size_t TAMANHO_TAG = crypto_aead_xchacha20poly1305_ietf_ABYTES;

/// Tamanho do salt usado pelo Argon2id (16 bytes).
constexpr std::size_t TAMANHO_SALT = crypto_pwhash_SALTBYTES;

/**
 * @brief Garante que a chave tem o tamanho certo.
 * @param chave Chave a verificar.
 * @throws ErroCriptografia se não tiver 32 bytes.
 */
void validarChave(std::span<const unsigned char> chave) {
    if (chave.size() != TAMANHO_CHAVE) {
        throw ErroCriptografia("A chave deve ter " + std::to_string(TAMANHO_CHAVE) + " bytes.");
    }
}

/**
 * @brief Criptografa bytes com XChaCha20-Poly1305.
 * @param mensagem Texto puro.
 * @param chave Chave de 32 bytes.
 * @return `nonce || cifrado + tag`.
 */
Bytes cifrar(std::span<const unsigned char> mensagem, std::span<const unsigned char> chave) {
    validarChave(chave);

    // O nonce ("number used once") garante que a mesma mensagem com a mesma
    // chave gere textos cifrados diferentes. Ele não é secreto.
    Bytes resultado(TAMANHO_NONCE + mensagem.size() + TAMANHO_TAG);
    unsigned char* nonce = resultado.data();
    unsigned char* cifrado = resultado.data() + TAMANHO_NONCE;
    randombytes_buf(nonce, TAMANHO_NONCE);

    unsigned long long tamanhoCifrado = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        cifrado, &tamanhoCifrado,
        mensagem.data(), mensagem.size(),
        nullptr, 0,  // sem dados adicionais autenticados
        nullptr,     // parâmetro não usado por este algoritmo
        nonce, chave.data());

    return resultado;
}

/**
 * @brief Descriptografa bytes produzidos por cifrar().
 * @param dados `nonce || cifrado + tag`.
 * @param chave Chave de 32 bytes.
 * @return A mensagem original.
 */
std::string decifrar(std::span<const unsigned char> dados, std::span<const unsigned char> chave) {
    validarChave(chave);
    if (dados.size() < TAMANHO_NONCE + TAMANHO_TAG) {
        throw ErroCriptografia("Texto cifrado curto demais.");
    }

    std::span<const unsigned char> nonce = dados.first(TAMANHO_NONCE);
    std::span<const unsigned char> cifrado = dados.subspan(TAMANHO_NONCE);

    std::string mensagem(cifrado.size() - TAMANHO_TAG, '\0');
    unsigned long long tamanhoMensagem = 0;

    // Se a tag não bater (chave errada ou dados alterados), a função
    // retorna -1 e não entrega nenhum dado.
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(mensagem.data()), &tamanhoMensagem,
            nullptr,
            cifrado.data(), cifrado.size(),
            nullptr, 0,
            nonce.data(), chave.data()) != 0) {
        throw ErroCriptografia("Falha ao descriptografar: chave/senha errada ou mensagem alterada.");
    }

    mensagem.resize(tamanhoMensagem);
    return mensagem;
}

} // namespace

Criptografador::Criptografador() {
    // sodium_init() retorna 0 na primeira vez, 1 se já foi inicializada
    // e -1 em caso de erro.
    if (sodium_init() < 0) {
        throw ErroCriptografia("Nao foi possivel inicializar a libsodium.");
    }
}

Segredo<Bytes> Criptografador::gerarChave() const {
    Bytes chave(TAMANHO_CHAVE);
    crypto_aead_xchacha20poly1305_ietf_keygen(chave.data());
    return Segredo<Bytes>(std::move(chave));  // a cópia temporária é zerada
}

std::string Criptografador::criptografarBytes(std::span<const unsigned char> mensagem,
                                              std::span<const unsigned char> chave) const {
    return paraHex(cifrar(mensagem, chave));
}

std::string Criptografador::descriptografarBytes(std::string_view cifradoHex,
                                                 std::span<const unsigned char> chave) const {
    return decifrar(deHex(cifradoHex), chave);
}

std::string Criptografador::criptografarComSenhaBytes(std::span<const unsigned char> mensagem,
                                                      std::span<const unsigned char> senha) const {
    // Um salt novo por mensagem faz a mesma senha gerar chaves diferentes.
    Bytes salt(TAMANHO_SALT);
    randombytes_buf(salt.data(), salt.size());

    // A chave derivada é um Segredo: é apagada sozinha ao fim da função.
    Segredo<Bytes> chave = derivarChave(senha, salt);
    Bytes cifrado = cifrar(mensagem, chave);

    // Resultado final: salt || nonce || cifrado + tag
    Bytes resultado(salt);
    resultado.insert(resultado.end(), cifrado.begin(), cifrado.end());
    return paraHex(resultado);
}

std::string Criptografador::descriptografarComSenhaBytes(std::string_view cifradoHex,
                                                         std::span<const unsigned char> senha) const {
    Bytes dados = deHex(cifradoHex);
    if (dados.size() < TAMANHO_SALT) {
        throw ErroCriptografia("Texto cifrado curto demais.");
    }

    // Separa o salt do restante para reconstruir a mesma chave.
    std::span<const unsigned char> tudo(dados);
    Segredo<Bytes> chave = derivarChave(senha, tudo.first(TAMANHO_SALT));
    return decifrar(tudo.subspan(TAMANHO_SALT), chave);
}

std::string Criptografador::paraHexBytes(std::span<const unsigned char> bytes) {
    // Cada byte vira 2 caracteres, mais 1 para o '\0' final.
    std::string hex(bytes.size() * 2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), bytes.data(), bytes.size());
    hex.pop_back();  // remove o '\0'
    return hex;
}

Bytes Criptografador::deHex(std::string_view hex) {
    Bytes bytes(hex.size() / 2);
    std::size_t tamanho = 0;
    const char* fim = nullptr;

    if (sodium_hex2bin(bytes.data(), bytes.size(), hex.data(), hex.size(),
                       nullptr, &tamanho, &fim) != 0
        || fim != hex.data() + hex.size()) {
        throw ErroCriptografia("Texto hexadecimal invalido.");
    }

    bytes.resize(tamanho);
    return bytes;
}

Segredo<Bytes> Criptografador::derivarChave(std::span<const unsigned char> senha,
                                            std::span<const unsigned char> salt) const {
    Bytes chave(TAMANHO_CHAVE);

    // OPSLIMIT/MEMLIMIT_INTERACTIVE: ~64 MiB de memória e algumas iterações.
    // É o custo recomendado para uso interativo.
    if (crypto_pwhash(chave.data(), chave.size(),
                      reinterpret_cast<const char*>(senha.data()), senha.size(),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw ErroCriptografia("Memoria insuficiente para derivar a chave.");
    }
    return Segredo<Bytes>(std::move(chave));
}

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
 * @brief Criptografa bytes com XChaCha20-Poly1305.
 * @param mensagem Texto puro.
 * @param chave Chave de 32 bytes.
 * @return `nonce || cifrado + tag`.
 */
Bytes cifrar(const std::string& mensagem, const Bytes& chave) {
    if (chave.size() != TAMANHO_CHAVE) {
        throw ErroCriptografia("A chave deve ter " + std::to_string(TAMANHO_CHAVE) + " bytes.");
    }

    // O nonce ("number used once") garante que a mesma mensagem com a mesma
    // chave gere textos cifrados diferentes. Ele não é secreto.
    Bytes resultado(TAMANHO_NONCE + mensagem.size() + TAMANHO_TAG);
    unsigned char* nonce = resultado.data();
    unsigned char* cifrado = resultado.data() + TAMANHO_NONCE;
    randombytes_buf(nonce, TAMANHO_NONCE);

    unsigned long long tamanhoCifrado = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        cifrado, &tamanhoCifrado,
        reinterpret_cast<const unsigned char*>(mensagem.data()), mensagem.size(),
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
std::string decifrar(const Bytes& dados, const Bytes& chave) {
    if (chave.size() != TAMANHO_CHAVE) {
        throw ErroCriptografia("A chave deve ter " + std::to_string(TAMANHO_CHAVE) + " bytes.");
    }
    if (dados.size() < TAMANHO_NONCE + TAMANHO_TAG) {
        throw ErroCriptografia("Texto cifrado curto demais.");
    }

    const unsigned char* nonce = dados.data();
    const unsigned char* cifrado = dados.data() + TAMANHO_NONCE;
    const std::size_t tamanhoCifrado = dados.size() - TAMANHO_NONCE;

    std::string mensagem(tamanhoCifrado - TAMANHO_TAG, '\0');
    unsigned long long tamanhoMensagem = 0;

    // Se a tag não bater (chave errada ou dados alterados), a função
    // retorna -1 e não entrega nenhum dado.
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(mensagem.data()), &tamanhoMensagem,
            nullptr,
            cifrado, tamanhoCifrado,
            nullptr, 0,
            nonce, chave.data()) != 0) {
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

Bytes Criptografador::gerarChave() const {
    Bytes chave(TAMANHO_CHAVE);
    crypto_aead_xchacha20poly1305_ietf_keygen(chave.data());
    return chave;
}

std::string Criptografador::criptografar(const std::string& mensagem, const Bytes& chave) const {
    return paraHex(cifrar(mensagem, chave));
}

std::string Criptografador::descriptografar(const std::string& cifradoHex, const Bytes& chave) const {
    return decifrar(deHex(cifradoHex), chave);
}

std::string Criptografador::criptografarComSenha(const std::string& mensagem,
                                                 const std::string& senha) const {
    // Um salt novo por mensagem faz a mesma senha gerar chaves diferentes.
    Bytes salt(TAMANHO_SALT);
    randombytes_buf(salt.data(), salt.size());

    Bytes chave = derivarChave(senha, salt);
    Bytes cifrado = cifrar(mensagem, chave);
    sodium_memzero(chave.data(), chave.size());  // apaga a chave da memória

    // Resultado final: salt || nonce || cifrado + tag
    Bytes resultado(salt);
    resultado.insert(resultado.end(), cifrado.begin(), cifrado.end());
    return paraHex(resultado);
}

std::string Criptografador::descriptografarComSenha(const std::string& cifradoHex,
                                                    const std::string& senha) const {
    Bytes dados = deHex(cifradoHex);
    if (dados.size() < TAMANHO_SALT) {
        throw ErroCriptografia("Texto cifrado curto demais.");
    }

    // Separa o salt do restante para reconstruir a mesma chave.
    Bytes salt(dados.begin(), dados.begin() + TAMANHO_SALT);
    Bytes resto(dados.begin() + TAMANHO_SALT, dados.end());

    Bytes chave = derivarChave(senha, salt);
    try {
        std::string mensagem = decifrar(resto, chave);
        sodium_memzero(chave.data(), chave.size());
        return mensagem;
    } catch (...) {
        sodium_memzero(chave.data(), chave.size());
        throw;
    }
}

std::string Criptografador::paraHex(const Bytes& bytes) {
    // Cada byte vira 2 caracteres, mais 1 para o '\0' final.
    std::string hex(bytes.size() * 2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), bytes.data(), bytes.size());
    hex.pop_back();  // remove o '\0'
    return hex;
}

Bytes Criptografador::deHex(const std::string& hex) {
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

Bytes Criptografador::derivarChave(const std::string& senha, const Bytes& salt) const {
    Bytes chave(TAMANHO_CHAVE);

    // OPSLIMIT/MEMLIMIT_INTERACTIVE: ~64 MiB de memória e algumas iterações.
    // É o custo recomendado para uso interativo.
    if (crypto_pwhash(chave.data(), chave.size(),
                      senha.data(), senha.size(),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw ErroCriptografia("Memoria insuficiente para derivar a chave.");
    }
    return chave;
}

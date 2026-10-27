/**
 * @file Cofre.cpp
 * @brief Implementação da classe Cofre.
 */

#include "Cofre.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <format>
#include <fstream>
#include <sstream>

namespace {

/// Primeira linha do texto do cofre; identifica o formato e a versão.
constexpr std::string_view CABECALHO = "COFRE1";

/// Quantos caracteres hex do início do texto cifrado formam a impressão digital (16 bytes).
constexpr std::size_t TAMANHO_IMPRESSAO = 32;

/**
 * @brief Converte um texto para minúsculas (hex pode vir em maiúsculas).
 * @param texto Texto original.
 * @return Cópia em minúsculas.
 */
std::string minusculas(std::string_view texto) {
    std::string resultado(texto);
    std::ranges::transform(resultado, resultado.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return resultado;
}

/**
 * @brief Calcula a impressão digital de um texto cifrado.
 * @param cifradoHex Texto cifrado em hexadecimal.
 * @return Os primeiros 32 caracteres hex em minúsculas, ou vazio se for curto demais.
 */
std::string impressaoDigital(std::string_view cifradoHex) {
    if (cifradoHex.size() < TAMANHO_IMPRESSAO) return {};
    return minusculas(cifradoHex.substr(0, TAMANHO_IMPRESSAO));
}

/**
 * @brief Data e hora local atual, ex.: "2026-10-27 14:02:11".
 * @return Data e hora formatadas (em UTC se o fuso local não estiver disponível).
 */
std::string agora() {
    const auto instante = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    try {
        return std::format("{:%Y-%m-%d %H:%M:%S}",
                           std::chrono::zoned_time{std::chrono::current_zone(), instante});
    } catch (const std::exception&) {
        return std::format("{:%Y-%m-%d %H:%M:%S} UTC", instante);
    }
}

/**
 * @brief Converte texto livre em hex, para não conflitar com os separadores.
 * @param texto Texto a codificar.
 * @return Texto em hexadecimal.
 */
std::string textoParaHex(std::string_view texto) {
    return Criptografador::paraHex(Bytes(texto.begin(), texto.end()));
}

/**
 * @brief Desfaz textoParaHex().
 * @param hex Texto em hexadecimal.
 * @return Texto original.
 */
std::string hexParaTexto(const std::string& hex) {
    Bytes bytes = Criptografador::deHex(hex);
    return std::string(bytes.begin(), bytes.end());
}

/**
 * @brief Divide uma linha nos campos separados por TAB (mantém campos vazios).
 * @param linha Linha a dividir.
 * @return Lista de campos.
 */
std::vector<std::string> dividir(const std::string& linha) {
    std::vector<std::string> campos(1);
    for (char c : linha) {
        if (c == '\t') campos.emplace_back();
        else           campos.back().push_back(c);
    }
    return campos;
}

/**
 * @brief Apaga o conteúdo de uma string da memória.
 * @param texto String a apagar.
 */
void apagar(std::string& texto) {
    sodium_memzero(texto.data(), texto.size());
    texto.clear();
}

} // namespace

std::string_view nomeDoTipo(TipoSegredo tipo) {
    return tipo == TipoSegredo::Chave ? "chave" : "senha";
}

bool RegistroCofre::confere(std::string_view outro) const {
    // Chaves em hex são comparadas sem diferenciar maiúsculas/minúsculas.
    const std::string normalizado = tipo == TipoSegredo::Chave ? minusculas(outro) : std::string(outro);
    if (normalizado.size() != segredo.size()) return false;
    return sodium_memcmp(normalizado.data(), segredo.data(), segredo.size()) == 0;
}

Cofre::Cofre(std::filesystem::path arquivo, const Criptografador& cripto)
    : arquivo_(std::move(arquivo)), cripto_(cripto) {}

Cofre::~Cofre() {
    apagar(senhaMestra_);
    for (RegistroCofre& registro : registros_) {
        apagar(registro.segredo);
    }
}

bool Cofre::existe() const {
    return std::filesystem::exists(arquivo_);
}

void Cofre::abrir(const std::string& senhaMestra) {
    if (!existe()) {
        // Cofre novo: começa vazio e já é gravado no disco.
        senhaMestra_ = senhaMestra;
        registros_.clear();
        aberto_ = true;
        salvar();
        return;
    }

    std::ifstream entrada(arquivo_);
    std::string conteudo;
    if (!entrada || !(entrada >> conteudo)) {
        throw ErroCofre("Nao foi possivel ler o cofre: " + arquivo_.string());
    }

    std::string texto;
    try {
        texto = cripto_.descriptografarComSenha(conteudo, senhaMestra);
    } catch (const ErroCriptografia&) {
        throw ErroCofre("Senha mestra incorreta ou cofre corrompido.");
    }

    desserializar(texto);
    apagar(texto);
    senhaMestra_ = senhaMestra;
    aberto_ = true;
}

const RegistroCofre& Cofre::adicionar(TipoSegredo tipo, const std::string& segredo,
                                      std::string_view cifradoHex, const std::string& descricao) {
    if (!aberto_) throw ErroCofre("O cofre nao esta aberto.");

    RegistroCofre registro;
    registro.id = registros_.empty() ? 1 : registros_.back().id + 1;
    registro.dataHora = agora();
    registro.tipo = tipo;
    registro.segredo = tipo == TipoSegredo::Chave ? minusculas(segredo) : segredo;
    registro.impressaoDigital = impressaoDigital(cifradoHex);
    registro.descricao = descricao;
    registros_.push_back(std::move(registro));

    try {
        salvar();
    } catch (...) {
        // Se não deu para gravar, desfaz para memória e disco continuarem iguais.
        apagar(registros_.back().segredo);
        registros_.pop_back();
        throw;
    }
    return registros_.back();
}

const RegistroCofre* Cofre::buscar(std::string_view cifradoHex) const {
    const std::string procurada = impressaoDigital(cifradoHex);
    if (procurada.empty()) return nullptr;

    auto encontrado = std::ranges::find(registros_, procurada, &RegistroCofre::impressaoDigital);
    return encontrado != registros_.end() ? &*encontrado : nullptr;
}

const std::vector<RegistroCofre>& Cofre::registros() const {
    return registros_;
}

void Cofre::salvar() const {
    if (!aberto_) throw ErroCofre("O cofre nao esta aberto.");

    std::string texto = serializar();
    const std::string conteudo = cripto_.criptografarComSenha(texto, senhaMestra_);
    apagar(texto);

    // Grava num temporário e só então substitui o arquivo antigo.
    std::filesystem::path temporario = arquivo_;
    temporario += ".tmp";
    {
        std::ofstream saida(temporario, std::ios::trunc);
        saida << conteudo << '\n';
        if (!saida) throw ErroCofre("Nao foi possivel gravar o cofre: " + temporario.string());
    }

    std::error_code erro;
    std::filesystem::rename(temporario, arquivo_, erro);
    if (erro) throw ErroCofre("Nao foi possivel gravar o cofre: " + erro.message());
}

std::string Cofre::serializar() const {
    // Formato (antes de criptografar):
    //   COFRE1
    //   id<TAB>dataHora<TAB>tipo<TAB>impressao<TAB>segredoHex<TAB>descricaoHex
    // Segredo e descrição vão em hex para que TAB e quebra de linha não
    // atrapalhem a leitura.
    std::ostringstream saida;
    saida << CABECALHO << '\n';
    for (const RegistroCofre& r : registros_) {
        saida << r.id << '\t' << r.dataHora << '\t' << nomeDoTipo(r.tipo) << '\t'
              << r.impressaoDigital << '\t' << textoParaHex(r.segredo) << '\t'
              << textoParaHex(r.descricao) << '\n';
    }
    return saida.str();
}

void Cofre::desserializar(const std::string& texto) {
    std::istringstream entrada(texto);
    std::string linha;
    if (!std::getline(entrada, linha) || linha != CABECALHO) {
        throw ErroCofre("Formato de cofre desconhecido.");
    }

    std::vector<RegistroCofre> lidos;
    try {
        while (std::getline(entrada, linha)) {
            if (linha.empty()) continue;
            std::vector<std::string> campos = dividir(linha);
            if (campos.size() != 6) throw ErroCofre("Registro do cofre invalido.");

            RegistroCofre r;
            r.id = std::stoi(campos[0]);
            r.dataHora = campos[1];
            r.tipo = campos[2] == "chave" ? TipoSegredo::Chave : TipoSegredo::Senha;
            r.impressaoDigital = campos[3];
            r.segredo = hexParaTexto(campos[4]);
            r.descricao = hexParaTexto(campos[5]);
            lidos.push_back(std::move(r));
            apagar(campos[4]);
        }
    } catch (const ErroCofre&) {
        throw;
    } catch (const std::exception&) {
        throw ErroCofre("Registro do cofre invalido.");
    }

    registros_ = std::move(lidos);
}

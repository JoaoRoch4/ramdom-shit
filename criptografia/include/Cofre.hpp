/**
 * @file Cofre.hpp
 * @brief Declaração da classe Cofre, que guarda as chaves e senhas criadas
 *        pelo programa em um arquivo criptografado com uma senha mestra.
 */

#ifndef COFRE_HPP
#define COFRE_HPP

#include "Criptografador.hpp"
#include "Segredo.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

/**
 * @brief Exceção lançada quando o cofre não pode ser aberto, lido ou salvo.
 */
class ErroCofre : public std::runtime_error {
public:
    /**
     * @brief Cria a exceção com uma mensagem explicativa.
     * @param mensagem Descrição do erro.
     */
    explicit ErroCofre(const std::string& mensagem)
        : std::runtime_error(mensagem) {}
};

/**
 * @brief Tipo de segredo usado para criptografar uma mensagem.
 */
enum class TipoSegredo {
    Chave, ///< Chave aleatória de 32 bytes (guardada em hexadecimal).
    Senha  ///< Senha digitada pelo usuário.
};

/**
 * @brief Um registro do cofre: qual segredo criptografou qual mensagem.
 */
struct RegistroCofre {
    int id = 0;                       ///< Número sequencial do registro (1, 2, 3...).
    std::string dataHora;             ///< Quando foi criado, ex.: "2026-10-27 14:02".
    TipoSegredo tipo = TipoSegredo::Chave; ///< Chave ou senha.
    Segredo<std::string> segredo;     ///< A chave (hex) ou a senha; apagada da memória sozinha.
    std::string impressaoDigital;     ///< Primeiros 16 bytes do texto cifrado, em hex.
    std::string descricao;            ///< Texto livre opcional para identificar o registro.

    /**
     * @brief Compara um segredo digitado com o guardado, em tempo constante.
     *
     * Tempo constante significa que a comparação demora o mesmo tanto
     * independentemente de onde está a primeira diferença, o que impede
     * que alguém descubra o segredo medindo o tempo de resposta.
     *
     * @param outro Segredo a comparar (chave em hex ou senha).
     * @return true se forem iguais.
     */
    bool confere(const Segredo<std::string>& outro) const;
};

/**
 * @brief Registro persistente e criptografado das chaves e senhas criadas.
 *
 * O arquivo inteiro é criptografado com Criptografador::criptografarComSenha()
 * usando a senha mestra (Argon2id + XChaCha20-Poly1305). Sem a senha mestra,
 * o arquivo é ilegível; se for alterado, a abertura falha.
 *
 * Cada mensagem é reconhecida pela sua "impressão digital": os primeiros
 * 16 bytes do texto cifrado, que são aleatórios (salt ou nonce) e únicos.
 *
 * A senha mestra e os segredos ficam em objetos Segredo<std::string>, que se
 * apagam da memória sozinhos quando o cofre é destruído.
 *
 * @code
 * Criptografador cripto;
 * Cofre cofre("cofre.dat", cripto);
 * cofre.abrir(Segredo<std::string>(std::string("senha mestra")));
 * cofre.adicionar(TipoSegredo::Senha, Segredo<std::string>(std::string("abc")),
 *                 cifradoHex, "teste");
 * if (const RegistroCofre* r = cofre.buscar(cifradoHex)) { ... }
 * @endcode
 */
class Cofre {
public:
    /**
     * @brief Prepara o cofre, sem abri-lo.
     * @param arquivo Caminho do arquivo do cofre.
     * @param cripto Criptografador usado para proteger o arquivo; precisa
     *        continuar existindo enquanto o cofre existir.
     */
    Cofre(std::filesystem::path arquivo, const Criptografador& cripto);

    Cofre(const Cofre&) = delete;
    Cofre& operator=(const Cofre&) = delete;

    /**
     * @brief Informa se o arquivo do cofre já existe no disco.
     * @return true se existe (será aberto); false se será criado.
     */
    bool existe() const;

    /**
     * @brief Abre o cofre existente ou cria um vazio, se não existir.
     * @param senhaMestra Senha que protege o arquivo.
     * @throws ErroCofre se a senha mestra estiver errada, o arquivo estiver
     *         corrompido ou não puder ser criado.
     */
    void abrir(Segredo<std::string> senhaMestra);

    /**
     * @brief Adiciona um registro e salva o cofre no disco.
     * @param tipo Chave ou senha.
     * @param segredo A chave (hex) ou a senha.
     * @param cifradoHex O texto cifrado produzido com esse segredo.
     * @param descricao Texto livre opcional.
     * @return O registro criado.
     * @throws ErroCofre se o cofre não estiver aberto ou não puder ser salvo.
     */
    const RegistroCofre& adicionar(TipoSegredo tipo, Segredo<std::string> segredo,
                                   std::string_view cifradoHex, const std::string& descricao);

    /**
     * @brief Procura o registro de uma mensagem criptografada.
     * @param cifradoHex Texto cifrado em hexadecimal.
     * @return Ponteiro para o registro, ou nullptr se não estiver no cofre.
     */
    const RegistroCofre* buscar(std::string_view cifradoHex) const;

    /**
     * @brief Todos os registros, do mais antigo para o mais novo.
     * @return Lista de registros.
     */
    const std::vector<RegistroCofre>& registros() const;

private:
    /**
     * @brief Criptografa todos os registros e grava no disco de forma segura.
     *
     * Grava primeiro em um arquivo temporário e depois o renomeia, para que
     * uma falha no meio da gravação nunca destrua o cofre antigo.
     *
     * @throws ErroCofre se a gravação falhar.
     */
    void salvar() const;

    /**
     * @brief Converte os registros em texto (antes de criptografar).
     * @return Texto com um registro por linha.
     */
    std::string serializar() const;

    /**
     * @brief Reconstrói os registros a partir do texto descriptografado.
     * @param texto Saída de serializar().
     * @throws ErroCofre se o formato for inválido.
     */
    void desserializar(const std::string& texto);

    std::filesystem::path arquivo_;          ///< Onde o cofre é gravado.
    const Criptografador& cripto_;           ///< Usado para (des)criptografar o arquivo.
    Segredo<std::string> senhaMestra_;       ///< Necessária para salvar de novo.
    std::vector<RegistroCofre> registros_;   ///< Registros carregados.
    bool aberto_ = false;                    ///< true depois de abrir() com sucesso.
};

/**
 * @brief Converte o tipo de segredo em texto ("chave" ou "senha").
 * @param tipo Tipo a converter.
 * @return Nome do tipo.
 */
std::string_view nomeDoTipo(TipoSegredo tipo);

#endif // COFRE_HPP

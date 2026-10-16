/*
 * Atividade Avaliativa 02 - Algoritmo e Pensamento Computacional
 * Criptografia simples + progressoes e series
 *
 * Camada 1: Cifra de Cesar (SHIFT fixo)
 * Camada 2: deslocamento dinamico pela sequencia numerica
 * Deslocamento total por letra = SHIFT + sequencia[i]
 *
 * Compilar: gcc -Wall -o cifra_dupla cifra_dupla.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>

#define ALFABETO      26
#define MAX_LETRAS    15
#define ARQ_RESULTADO "resultado_criptografia.txt"
#define ARQ_LOG       "log_execucao.txt"

/* Parametros padrao das progressoes (editaveis pelo grupo) */
#define PA_INICIO  1
#define PA_RAZAO   2
#define PG_INICIO  1
#define PG_RAZAO   2

enum { PA = 1, PG = 2, FIBONACCI = 3, PRIMOS = 4 };

static const char *nome_sequencia(int tipo)
{
    switch (tipo) {
        case PA:        return "PA";
        case PG:        return "PG";
        case FIBONACCI: return "Fibonacci";
        case PRIMOS:    return "Primos";
        default:        return "Invalida";
    }
}

/* ------------------------------------------------------------------ log */
static void registrar_log(const char *fmt, ...)
{
    FILE *f = fopen(ARQ_LOG, "a");
    if (!f) return;

    time_t agora = time(NULL);
    char data[32];
    strftime(data, sizeof data, "%Y-%m-%d %H:%M:%S", localtime(&agora));
    fprintf(f, "[%s] ", data);

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fprintf(f, "\n");
    fclose(f);
}

/* ------------------------------------------------------------ sequencias */
static int eh_primo(int n)
{
    if (n < 2) return 0;
    for (int d = 2; d * d <= n; d++)
        if (n % d == 0) return 0;
    return 1;
}

/*
 * Preenche seq[0..n-1] com os n primeiros termos da sequencia escolhida.
 * Os termos ja sao guardados modulo 26 (so importam como deslocamento),
 * o que evita overflow na PG e na serie de Fibonacci.
 */
static void gerar_sequencia(int tipo, int n, int *seq)
{
    int a = 1, b = 1, termo = PG_INICIO % ALFABETO, candidato = 2;

    for (int i = 0; i < n; i++) {
        switch (tipo) {
            case PA:  /* an = a1 + (n-1)*r */
                seq[i] = (PA_INICIO + i * PA_RAZAO) % ALFABETO;
                break;
            case PG:  /* an = a1 * q^(n-1) */
                seq[i] = termo;
                termo = (termo * PG_RAZAO) % ALFABETO;
                break;
            case FIBONACCI: /* F1 = F2 = 1 */
                seq[i] = a % ALFABETO;
                { int prox = (a + b) % ALFABETO; a = b; b = prox; }
                break;
            case PRIMOS:
                while (!eh_primo(candidato)) candidato++;
                seq[i] = candidato % ALFABETO;
                candidato++;
                break;
        }
    }
}

/* Versao "bruta" (sem modulo) so para exibir a sequencia ao usuario */
static void mostrar_sequencia(int tipo, int n)
{
    long long a = 1, b = 1, termo = PG_INICIO;
    int candidato = 2;

    for (int i = 0; i < n; i++) {
        long long v = 0;
        switch (tipo) {
            case PA:  v = PA_INICIO + (long long)i * PA_RAZAO; break;
            case PG:  v = termo; termo *= PG_RAZAO; break;
            case FIBONACCI: v = a; { long long p = a + b; a = b; b = p; } break;
            case PRIMOS:
                while (!eh_primo(candidato)) candidato++;
                v = candidato++;
                break;
        }
        printf("%lld%s", v, i < n - 1 ? ", " : "\n");
    }
}

/* --------------------------------------------------------------- cifragem */
static int normalizar(int x)
{
    return ((x % ALFABETO) + ALFABETO) % ALFABETO;
}

/* sentido = +1 criptografa, -1 descriptografa */
static void transformar(const char *entrada, char *saida, int shift,
                        const int *seq, int sentido)
{
    int i = 0;
    for (const char *p = entrada; *p; p++, i++) {
        int pos = *p - 'a';
        int total = shift + seq[i];           /* camada 1 + camada 2 */
        saida[i] = (char)('a' + normalizar(pos + sentido * total));
    }
    saida[i] = '\0';
}

/* ---------------------------------------------------------------- entrada */
static int ler_palavra(char *dest)
{
    char buf[64];

    printf("Palavra secreta (ate %d letras, sem acentos): ", MAX_LETRAS);
    if (!fgets(buf, sizeof buf, stdin)) return 0;
    buf[strcspn(buf, "\r\n")] = '\0';

    size_t len = strlen(buf);
    if (len == 0 || len > MAX_LETRAS) {
        printf("Erro: a palavra deve ter de 1 a %d letras.\n", MAX_LETRAS);
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (!isalpha((unsigned char)buf[i]) || (unsigned char)buf[i] > 127) {
            printf("Erro: use apenas letras de A a Z, sem acentos ou simbolos.\n");
            return 0;
        }
        dest[i] = (char)tolower((unsigned char)buf[i]);
    }
    dest[len] = '\0';
    return 1;
}

static int ler_inteiro(const char *msg, int *valor)
{
    char buf[32];
    printf("%s", msg);
    if (!fgets(buf, sizeof buf, stdin)) return 0;
    char *fim;
    long v = strtol(buf, &fim, 10);
    if (fim == buf) { printf("Erro: digite um numero inteiro.\n"); return 0; }
    *valor = (int)v;
    return 1;
}

static int ler_tipo(void)
{
    int tipo;
    printf("\nSequencia: 1-PA  2-PG  3-Fibonacci  4-Primos\n");
    if (!ler_inteiro("Escolha: ", &tipo) || tipo < PA || tipo > PRIMOS) {
        printf("Erro: sequencia invalida.\n");
        return 0;
    }
    return tipo;
}

/* ------------------------------------------------------------------ acoes */
static void acao_criptografar(void)
{
    char palavra[MAX_LETRAS + 1], cifrada[MAX_LETRAS + 1];
    int shift, tipo, seq[MAX_LETRAS];

    if (!ler_palavra(palavra)) return;
    if (!ler_inteiro("SHIFT: ", &shift)) return;
    if (!(tipo = ler_tipo())) return;

    int n = (int)strlen(palavra);
    gerar_sequencia(tipo, n, seq);
    transformar(palavra, cifrada, shift, seq, +1);

    printf("\nSequencia %s: ", nome_sequencia(tipo));
    mostrar_sequencia(tipo, n);
    printf("Palavra criptografada: %s\n", cifrada);

    FILE *f = fopen(ARQ_RESULTADO, "w");
    if (!f) {
        printf("Erro ao gravar %s\n", ARQ_RESULTADO);
        registrar_log("ERRO ao abrir %s para escrita", ARQ_RESULTADO);
        return;
    }
    fprintf(f, "Palavra codificada: %s | SHIFT: %d | Tipo: %d | Letras: %d\n",
            cifrada, shift, tipo, n);
    fclose(f);

    printf("Resultado gravado em %s\n", ARQ_RESULTADO);
    registrar_log("CRIPTOGRAFIA | original=%s | SHIFT=%d | sequencia=%s | resultado=%s",
                  palavra, shift, nome_sequencia(tipo), cifrada);
}

static void acao_descriptografar(void)
{
    char cifrada[MAX_LETRAS + 1], original[MAX_LETRAS + 1];
    int shift, tipo, seq[MAX_LETRAS];

    if (!ler_palavra(cifrada)) return;
    if (!ler_inteiro("SHIFT: ", &shift)) return;
    if (!(tipo = ler_tipo())) return;

    int n = (int)strlen(cifrada);
    gerar_sequencia(tipo, n, seq);
    transformar(cifrada, original, shift, seq, -1);

    printf("\nPalavra original: %s\n", original);
    registrar_log("DESCRIPTOGRAFIA | cifrada=%s | SHIFT=%d | sequencia=%s | resultado=%s",
                  cifrada, shift, nome_sequencia(tipo), original);
}

/* Analisar / Avaliar: mesma palavra e SHIFT com todas as sequencias */
static void acao_comparar(void)
{
    char palavra[MAX_LETRAS + 1], cifrada[MAX_LETRAS + 1];
    int shift, seq[MAX_LETRAS];

    if (!ler_palavra(palavra)) return;
    if (!ler_inteiro("SHIFT: ", &shift)) return;

    int n = (int)strlen(palavra);
    printf("\n%-10s %-16s %s\n", "Sequencia", "Resultado", "Letras distintas");
    for (int t = PA; t <= PRIMOS; t++) {
        gerar_sequencia(t, n, seq);
        transformar(palavra, cifrada, shift, seq, +1);

        int visto[ALFABETO] = {0}, distintas = 0;
        for (int i = 0; i < n; i++)
            if (!visto[cifrada[i] - 'a']++) distintas++;

        printf("%-10s %-16s %d de %d\n", nome_sequencia(t), cifrada, distintas, n);
        registrar_log("COMPARACAO | original=%s | SHIFT=%d | %s -> %s | distintas=%d",
                      palavra, shift, nome_sequencia(t), cifrada, distintas);
    }
}

/* ------------------------------------------------------------------- main */
int main(void)
{
    int opcao;

    registrar_log("Programa iniciado");
    do {
        printf("\n=== CIFRA EM DUAS CAMADAS ===\n");
        printf("1 - Criptografar\n2 - Descriptografar\n");
        printf("3 - Comparar sequencias\n0 - Sair\n");
        if (!ler_inteiro("Opcao: ", &opcao)) opcao = -1;

        switch (opcao) {
            case 1: acao_criptografar();   break;
            case 2: acao_descriptografar(); break;
            case 3: acao_comparar();       break;
            case 0: break;
            default: printf("Opcao invalida.\n");
        }
    } while (opcao != 0);

    registrar_log("Programa encerrado");
    return 0;
}

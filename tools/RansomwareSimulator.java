/*
 * ============================================================================
 *  RansomwareSimulator — simulador BENIGNO de comportamento de ransomware
 * ============================================================================
 *
 *  Serve só para testar o FileWatch. Reproduz o COMPORTAMENTO observável
 *  (muitas escritas rápidas, salto de entropia, extensão estranha, nota de
 *  resgate) sem ser malicioso.
 *
 *  INVARIANTES DE SEGURANÇA (verificadas no código, não só prometidas):
 *
 *   1. Só roda quando chamado explicitamente com o caminho do sandbox E a flag
 *      --confirm. Sem --confirm, apenas mostra o que faria (dry run).
 *   2. Recusa rodar se o sandbox não contiver o arquivo marcador
 *      ".filewatch-sandbox", se for a raiz de um disco ou a pasta home do
 *      usuário. Apontar para "Documentos" por engano não funciona.
 *   3. Toda escrita acontece dentro de <sandbox>/victims/run-<timestamp>/,
 *      uma pasta NOVA que o próprio simulador cria nesta execução. Cada
 *      caminho é conferido contra essa pasta antes de qualquer operação.
 *   4. Só sobrescreve/renomeia arquivos que ele mesmo criou nesta execução
 *      (lista em memória). Nunca abre, lê, altera ou apaga arquivo preexistente.
 *      Criação usa CREATE_NEW (falha se já existir); renomeação não substitui
 *      destino existente; nenhuma operação segue symlinks.
 *   5. Não criptografa nada: sobrescreve arquivos descartáveis com bytes
 *      aleatórios (SecureRandom). Não existe chave nem "decifrar".
 *   6. Não se copia, não persiste, não cria autostart, não abre rede, não
 *      executa processos. Fora do modo --clean, não apaga nada.
 *   7. As pastas victims/ e run-<timestamp>/ são conferidas pelo caminho
 *      canônico (toRealPath): se alguma delas for symlink ou junction
 *      apontando para fora do sandbox, o simulador para antes de escrever.
 *   8. O modo --clean só apaga pastas victims/run-<timestamp>/ que contêm
 *      EXCLUSIVAMENTE arquivos com os nomes que o simulador gera. Qualquer
 *      outro arquivo, subpasta ou link faz a pasta inteira ser preservada.
 *
 *  Uso (a partir da raiz do projeto, de preferência dentro de uma VM com snapshot):
 *
 *     java tools/RansomwareSimulator.java ./sandbox            # dry run
 *     java tools/RansomwareSimulator.java ./sandbox --confirm  # executa
 *     java tools/RansomwareSimulator.java ./sandbox --clean            # lista o que apagaria
 *     java tools/RansomwareSimulator.java ./sandbox --clean --confirm  # limpa as execuções
 *
 *  Opções:
 *     --files N            nº de arquivos-vítima (padrão 40)
 *     --settle-seconds S   espera após criar as vítimas, para o FileWatch
 *                          registrá-las no baseline com entropia baixa (padrão 5)
 *     --pause-millis M     pausa entre sobrescrever e renomear (padrão 1500)
 *
 *  Limpeza: --clean --confirm (ou apague a pasta victims/run-<timestamp>/ à mão).
 * ============================================================================
 */

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class RansomwareSimulator {

    static final String MARKER = ".filewatch-sandbox";
    static final int VICTIM_SIZE = 16 * 1024; // pequeno demais distorce a entropia medida
    static final Pattern RUN_DIR = Pattern.compile("run-\\d{8}-\\d{6}");
    static final Pattern OWN_FILE = Pattern.compile("relatorio-\\d{3}\\.txt(\\.encrypted)?|README_DECRYPT\\.txt");

    private final Path runDir;
    private final List<Path> ownedFiles = new ArrayList<>();

    private RansomwareSimulator(Path runDir) {
        this.runDir = runDir;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].startsWith("--")) {
            System.err.println("Uso: java tools/RansomwareSimulator.java <sandbox> [--confirm] [--clean] [--files N] [--settle-seconds S] [--pause-millis M]");
            System.exit(2);
        }
        Path sandboxArg = Path.of(args[0]);
        boolean confirm = false;
        boolean clean = false;
        int files = 40;
        int settleSeconds = 5;
        int pauseMillis = 1500;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--confirm" -> confirm = true;
                case "--clean" -> clean = true;
                case "--files" -> files = Integer.parseInt(args[++i]);
                case "--settle-seconds" -> settleSeconds = Integer.parseInt(args[++i]);
                case "--pause-millis" -> pauseMillis = Integer.parseInt(args[++i]);
                default -> fail("Opção desconhecida: " + args[i]);
            }
        }
        if (files < 1 || files > 500) {
            fail("--files deve estar entre 1 e 500");
        }

        Path sandbox = validateSandbox(sandboxArg);
        if (clean) {
            clean(sandbox, confirm);
            return;
        }
        String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        Path runDir = sandbox.resolve("victims").resolve("run-" + stamp);

        System.out.println("Sandbox validado: " + sandbox);
        System.out.println("Pasta desta execução: " + runDir);
        System.out.printf("Plano: criar %d vítimas fake -> esperar %ds -> sobrescrever com bytes aleatórios -> "
                + "esperar %dms -> renomear para .encrypted -> criar README_DECRYPT.txt%n", files, settleSeconds, pauseMillis);

        if (!confirm) {
            System.out.println("Dry run: nada foi escrito. Rode de novo com --confirm para executar.");
            return;
        }

        Path victims = sandbox.resolve("victims");
        Files.createDirectories(victims);
        requireCanonical(victims);
        Files.createDirectory(runDir); // falha se já existir: a pasta é sempre nova
        requireCanonical(runDir);
        RansomwareSimulator simulator = new RansomwareSimulator(runDir.toRealPath());

        simulator.createVictims(files);
        System.out.printf("[1/4] %d vítimas criadas. Aguardando %ds para o baseline...%n", files, settleSeconds);
        Thread.sleep(settleSeconds * 1000L);

        simulator.overwriteWithRandom();
        System.out.println("[2/4] Conteúdo sobrescrito com bytes aleatórios.");
        Thread.sleep(pauseMillis);

        simulator.renameAll(".encrypted");
        System.out.println("[3/4] Arquivos renomeados para .encrypted.");

        simulator.dropRansomNote();
        System.out.println("[4/4] Nota de resgate fake criada. Fim.");
        System.out.println("Para limpar: apague " + runDir);
    }

    /** Invariante 2: marcador obrigatório, nada de raiz de disco nem home. */
    static Path validateSandbox(Path candidate) throws IOException {
        if (!Files.isDirectory(candidate, LinkOption.NOFOLLOW_LINKS)) {
            fail("Sandbox não existe ou não é diretório: " + candidate);
        }
        Path real = candidate.toRealPath();
        if (real.getParent() == null) {
            fail("Recusado: o sandbox não pode ser a raiz de um disco: " + real);
        }
        Path home = Path.of(System.getProperty("user.home")).toRealPath();
        if (real.equals(home)) {
            fail("Recusado: o sandbox não pode ser a pasta home do usuário: " + real);
        }
        if (!Files.isRegularFile(real.resolve(MARKER), LinkOption.NOFOLLOW_LINKS)) {
            fail("Recusado: " + real + " não contém o marcador " + MARKER
                    + ". Crie-o só na pasta que é de fato o sandbox de teste.");
        }
        return real;
    }

    /**
     * Invariante 7: o caminho canônico tem que ser exatamente o caminho montado a partir do sandbox.
     * Pega symlinks e também junctions do Windows, que {@link Files#isSymbolicLink} não reconhece.
     */
    static void requireCanonical(Path expected) throws IOException {
        Path lexical = expected.toAbsolutePath().normalize();
        if (!Files.isDirectory(lexical, LinkOption.NOFOLLOW_LINKS) || !lexical.toRealPath().equals(lexical)) {
            fail("Recusado: " + lexical + " é link/junction ou aponta para outro lugar (" + lexical.toRealPath() + ").");
        }
    }

    /** Invariante 8: só apaga pastas de execução que contêm apenas arquivos gerados pelo simulador. */
    static void clean(Path sandbox, boolean confirm) throws IOException {
        Path victims = sandbox.resolve("victims");
        if (!Files.exists(victims, LinkOption.NOFOLLOW_LINKS)) {
            System.out.println("Nada para limpar: " + victims + " não existe.");
            return;
        }
        requireCanonical(victims);
        List<Path> runs;
        try (Stream<Path> children = Files.list(victims)) {
            runs = children.filter(p -> RUN_DIR.matcher(p.getFileName().toString()).matches()).sorted().toList();
        }
        int removed = 0;
        for (Path run : runs) {
            List<Path> files = ownFilesOnly(run);
            if (files == null) {
                continue;
            }
            if (!confirm) {
                System.out.printf("Apagaria %s (%d arquivos)%n", run, files.size());
                continue;
            }
            for (Path file : files) {
                Files.delete(file);
            }
            Files.delete(run); // falha se sobrou algo: nunca apaga pasta com conteúdo inesperado
            removed++;
            System.out.println("Removido " + run);
        }
        if (runs.isEmpty()) {
            System.out.println("Nenhuma pasta run-<timestamp> em " + victims);
        } else if (!confirm) {
            System.out.println("Dry run: nada foi apagado. Rode de novo com --clean --confirm.");
        } else {
            System.out.printf("%d pasta(s) removida(s).%n", removed);
        }
    }

    /** Lista os arquivos da execução, ou null (e explica) se houver qualquer coisa que o simulador não criaria. */
    private static List<Path> ownFilesOnly(Path run) throws IOException {
        Path lexical = run.toAbsolutePath().normalize();
        if (!Files.isDirectory(lexical, LinkOption.NOFOLLOW_LINKS) || !lexical.toRealPath().equals(lexical)) {
            System.out.println("Preservado (link/junction ou não é pasta): " + lexical);
            return null;
        }
        List<Path> files = new ArrayList<>();
        try (Stream<Path> children = Files.list(lexical)) {
            for (Path child : children.toList()) {
                boolean ours = Files.isRegularFile(child, LinkOption.NOFOLLOW_LINKS)
                        && OWN_FILE.matcher(child.getFileName().toString()).matches();
                if (!ours) {
                    System.out.println("Preservado (contém " + child.getFileName() + ", que o simulador não cria): " + lexical);
                    return null;
                }
                files.add(child);
            }
        }
        return files;
    }

    /** Invariante 3: todo caminho tocado precisa estar dentro da pasta desta execução. */
    private Path guarded(Path target) {
        Path normalized = target.toAbsolutePath().normalize();
        if (!normalized.startsWith(runDir) || normalized.equals(runDir)) {
            throw new SecurityException("Bloqueado: " + normalized + " está fora de " + runDir);
        }
        if (Files.isSymbolicLink(normalized)) {
            throw new SecurityException("Bloqueado: " + normalized + " é um symlink");
        }
        return normalized;
    }

    private void createVictims(int count) throws IOException {
        for (int i = 1; i <= count; i++) {
            Path victim = guarded(runDir.resolve("relatorio-%03d.txt".formatted(i)));
            Files.write(victim, fakeText(i), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            ownedFiles.add(victim);
        }
    }

    /** Invariantes 4 e 5: só nos arquivos desta execução, só bytes aleatórios. */
    private void overwriteWithRandom() throws IOException {
        SecureRandom random = new SecureRandom();
        byte[] noise = new byte[VICTIM_SIZE];
        for (Path victim : ownedFiles) {
            random.nextBytes(noise);
            Files.write(guarded(victim), noise,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, LinkOption.NOFOLLOW_LINKS);
        }
    }

    private void renameAll(String extension) throws IOException {
        List<Path> renamed = new ArrayList<>();
        for (Path victim : ownedFiles) {
            Path target = guarded(victim.resolveSibling(victim.getFileName() + extension));
            // Sem REPLACE_EXISTING: nunca sobrescreve um destino que já exista.
            Files.move(guarded(victim), target, LinkOption.NOFOLLOW_LINKS);
            renamed.add(target);
        }
        ownedFiles.clear();
        ownedFiles.addAll(renamed);
    }

    private void dropRansomNote() throws IOException {
        Path note = guarded(runDir.resolve("README_DECRYPT.txt"));
        String text = """
                *** SIMULAÇÃO — NADA FOI CRIPTOGRAFADO ***
                Este arquivo foi gerado pelo RansomwareSimulator do projeto FileWatch
                para testar a detecção de "nota de resgate". Os arquivos .encrypted
                desta pasta são apenas bytes aleatórios em arquivos descartáveis
                criados pelo próprio simulador. Pode apagar esta pasta.
                """;
        Files.writeString(note, text, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
    }

    /** Texto comum (entropia ~4–5 bits/byte), do tamanho das vítimas. */
    private static byte[] fakeText(int index) {
        String paragraph = ("Relatório %d. Este é um documento fictício criado pelo simulador do FileWatch. "
                + "O conteúdo é texto comum, com entropia típica de linguagem natural. ").formatted(index);
        StringBuilder sb = new StringBuilder(VICTIM_SIZE);
        while (sb.length() < VICTIM_SIZE) {
            sb.append(paragraph);
        }
        return sb.substring(0, VICTIM_SIZE).getBytes(StandardCharsets.UTF_8);
    }

    private static void fail(String message) {
        System.err.println(message);
        System.exit(1);
    }
}

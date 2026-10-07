package com.serignolli.filewatch.security;

import com.serignolli.filewatch.config.FileWatchProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Optional;

/**
 * Confinamento à pasta monitorada (SPEC §7).
 * <p>
 * Todo {@link Path} que entra no fluxo passa por aqui. A comparação é feita sobre o caminho
 * canônico ({@link Path#toRealPath}), que resolve {@code ..} e symlinks — assim não dá para
 * escapar do sandbox por path traversal nem por link apontando para fora.
 */
@Component
public class PathGuard {

    private static final Logger log = LoggerFactory.getLogger(PathGuard.class);

    /** Arquivo que marca uma pasta como sandbox de teste. O simulador exige o mesmo marcador. */
    public static final String SANDBOX_MARKER = ".filewatch-sandbox";

    private final Path base;

    public PathGuard(FileWatchProperties properties) throws IOException {
        Path configured = properties.monitoredDir().toAbsolutePath().normalize();
        if (properties.requireSandboxMarker()) {
            // Com o marcador exigido não faz sentido criar a pasta: ela precisa existir e ter sido marcada à mão.
            if (!Files.isDirectory(configured)) {
                throw new IllegalStateException("monitored-path não existe: " + configured
                        + ". Crie a pasta e, dentro dela, o arquivo " + SANDBOX_MARKER + ".");
            }
        } else {
            Files.createDirectories(configured);
        }
        this.base = configured.toRealPath();
        if (base.getParent() == null) {
            throw new IllegalStateException("monitored-path não pode ser a raiz do sistema de arquivos: " + base);
        }
        Path home = Path.of(System.getProperty("user.home")).toAbsolutePath().normalize();
        if (home.startsWith(base) || (Files.exists(home) && home.toRealPath().startsWith(base))) {
            throw new IllegalStateException("monitored-path não pode ser a pasta home nem uma pasta que a contenha: " + base);
        }
        if (properties.requireSandboxMarker()
                && !Files.isRegularFile(base.resolve(SANDBOX_MARKER), LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("Recusado: " + base + " não contém o marcador " + SANDBOX_MARKER
                    + ". Crie-o só na pasta que é de fato o sandbox de teste"
                    + " (ou use filewatch.require-sandbox-marker=false para observar uma pasta real).");
        }
    }

    /** Caminho canônico da pasta monitorada. */
    public Path base() {
        return base;
    }

    /**
     * Retorna o caminho canônico se ele estiver dentro do sandbox; vazio (e loga) caso contrário.
     * Funciona também para arquivos que já foram apagados: nesse caso canoniza o ancestral
     * mais próximo que ainda existe e reanexa o restante.
     */
    public Optional<Path> resolveInside(Path candidate) {
        Path real;
        try {
            real = canonical(candidate);
        } catch (IOException e) {
            log.warn("Não foi possível resolver {} ({}); descartado", candidate, e.toString());
            return Optional.empty();
        }
        if (real.startsWith(base)) {
            return Optional.of(real);
        }
        log.warn("Caminho fora do sandbox, descartado: {} -> {}", candidate, real);
        return Optional.empty();
    }

    public boolean isInside(Path candidate) {
        return resolveInside(candidate).isPresent();
    }

    private static Path canonical(Path candidate) throws IOException {
        Path current = candidate.toAbsolutePath().normalize();
        Deque<Path> missing = new ArrayDeque<>();
        while (true) {
            try {
                Path real = current.toRealPath();
                for (Path name : missing) {
                    real = real.resolve(name);
                }
                return real;
            } catch (NoSuchFileException e) {
                Path parent = current.getParent();
                if (parent == null || current.getFileName() == null) {
                    throw e;
                }
                missing.addFirst(current.getFileName());
                current = parent;
            }
        }
    }
}

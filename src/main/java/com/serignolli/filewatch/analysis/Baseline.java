package com.serignolli.filewatch.analysis;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.serignolli.filewatch.config.FileWatchProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A linha de base: o que sabemos sobre cada arquivo (SPEC §5.3).
 * Em memória num {@link ConcurrentHashMap}; persistida em JSON no shutdown e carregada no start.
 */
@Component
public class Baseline {

    private static final Logger log = LoggerFactory.getLogger(Baseline.class);

    /** Formato no disco: path e mtime como texto para não depender de (de)serializadores de Path/Instant. */
    public record StoredEntry(String path, long size, String mtime, String sha256, double entropy) {}

    private final ConcurrentHashMap<Path, BaselineEntry> entries = new ConcurrentHashMap<>();
    private final Path file;
    private final ObjectMapper mapper;
    private volatile boolean loadedFromDisk;

    public Baseline(FileWatchProperties properties, ObjectMapper mapper) {
        this.file = properties.baselinePath().toAbsolutePath().normalize();
        this.mapper = mapper;
    }

    @PostConstruct
    public void load() {
        if (!Files.isRegularFile(file)) {
            log.info("Sem baseline em {}; será criado na primeira varredura", file);
            return;
        }
        try {
            List<StoredEntry> stored = mapper.readValue(file.toFile(), new TypeReference<>() {});
            for (StoredEntry s : stored) {
                Path path = Path.of(s.path());
                entries.put(path, new BaselineEntry(path, s.size(), Instant.parse(s.mtime()), s.sha256(), s.entropy()));
            }
            loadedFromDisk = true;
            log.info("Baseline carregado: {} arquivos de {}", entries.size(), file);
        } catch (IOException | RuntimeException e) {
            // Baseline corrompido não pode derrubar o monitor: começa do zero e avisa.
            log.error("Não foi possível ler o baseline {}; começando vazio", file, e);
            entries.clear();
        }
    }

    @PreDestroy
    public synchronized void save() {
        List<StoredEntry> stored = entries.values().stream()
                .sorted(Comparator.comparing(e -> e.path().toString()))
                .map(e -> new StoredEntry(e.path().toString(), e.size(), e.mtime().toString(), e.sha256(), e.entropy()))
                .toList();
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            // Escreve num temporário e troca: um crash no meio não deixa o baseline pela metade.
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), stored);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            log.info("Baseline salvo: {} arquivos em {}", stored.size(), file);
        } catch (IOException e) {
            log.error("Falha ao salvar baseline em {}", file, e);
        }
    }

    public boolean loadedFromDisk() {
        return loadedFromDisk;
    }

    public Optional<BaselineEntry> get(Path path) {
        return Optional.ofNullable(entries.get(path));
    }

    public void put(BaselineEntry entry) {
        entries.put(entry.path(), entry);
    }

    /** Remove o path e, se era um diretório, tudo abaixo dele. Devolve o que foi removido. */
    public List<BaselineEntry> removeTree(Path path) {
        List<BaselineEntry> removed = new ArrayList<>();
        for (Path key : entries.keySet()) {
            if (key.startsWith(path)) {
                BaselineEntry entry = entries.remove(key);
                if (entry != null) {
                    removed.add(entry);
                }
            }
        }
        return removed;
    }

    public Set<Path> paths() {
        return Set.copyOf(entries.keySet());
    }

    public int size() {
        return entries.size();
    }
}

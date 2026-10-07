package com.serignolli.filewatch.alert;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.serignolli.filewatch.config.FileWatchProperties;
import com.serignolli.filewatch.detection.RansomwareSuspectedEvent;
import com.serignolli.filewatch.detection.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reage aos alertas (SPEC §5.5). Fase 1: loga e acrescenta uma linha JSON em {@code alerts-file}.
 * <p>
 * Não toma nenhuma ação sobre os arquivos (quarentena etc. fica como ideia no README):
 * mexer em arquivo do usuário sem confirmação está fora de escopo.
 */
@Component
public class AlertListener {

    private static final Logger log = LoggerFactory.getLogger(AlertListener.class);
    private static final int MAX_FILES_IN_LOG = 20;

    private final Path alertsFile;
    private final ObjectMapper mapper;

    public AlertListener(FileWatchProperties properties, ObjectMapper mapper) {
        this.alertsFile = properties.alertsPath().toAbsolutePath().normalize();
        this.mapper = mapper;
    }

    @EventListener
    public void onAlert(RansomwareSuspectedEvent alert) {
        List<Path> files = alert.involvedFiles();
        String message = "[{}] Suspeita de ransomware | motivos: {} | {} arquivo(s) envolvido(s): {}{}";
        Object[] args = {
                alert.severity(),
                String.join("; ", alert.reasons()),
                files.size(),
                files.subList(0, Math.min(files.size(), MAX_FILES_IN_LOG)),
                files.size() > MAX_FILES_IN_LOG ? " ..." : ""
        };
        if (alert.severity() == Severity.HIGH) {
            log.error(message, args);
        } else {
            log.warn(message, args);
        }
        append(alert);
    }

    private synchronized void append(RansomwareSuspectedEvent alert) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("at", alert.at().toString());
        json.put("severity", alert.severity().name());
        json.put("reasons", alert.reasons());
        json.put("involvedFiles", alert.involvedFiles().stream().map(Path::toString).toList());
        try {
            String line = mapper.writeValueAsString(json) + System.lineSeparator();
            Path parent = alertsFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(alertsFile, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (JsonProcessingException e) {
            log.error("Falha ao serializar alerta", e);
        } catch (IOException e) {
            log.error("Falha ao gravar alerta em {}", alertsFile, e);
        }
    }
}

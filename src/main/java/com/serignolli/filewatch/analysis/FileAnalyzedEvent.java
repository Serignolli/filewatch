package com.serignolli.filewatch.analysis;

import com.serignolli.filewatch.watcher.ChangeType;

import java.nio.file.Path;
import java.time.Instant;

public record FileAnalyzedEvent(
        Path path,
        ChangeType type,
        long size,
        String sha256,          // null para DELETED
        double entropy,         // bits por byte, 0.0 – 8.0
        Double previousEntropy, // null se não havia baseline
        boolean contentChanged, // hash diferente do baseline
        Instant at
) {}

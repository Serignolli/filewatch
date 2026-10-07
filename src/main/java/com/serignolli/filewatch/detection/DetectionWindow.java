package com.serignolli.filewatch.detection;

import com.serignolli.filewatch.analysis.FileAnalyzedEvent;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

/** Janela deslizante de tempo sobre os eventos analisados mais recentes. */
public class DetectionWindow {

    private final Duration size;
    private final ConcurrentLinkedDeque<FileAnalyzedEvent> events = new ConcurrentLinkedDeque<>();

    public DetectionWindow(Duration size) {
        this.size = size;
    }

    public void add(FileAnalyzedEvent event) {
        events.addLast(event);
    }

    /** Descarta do início da fila os eventos mais velhos que o tamanho da janela. */
    public void prune(Instant now) {
        Instant cutoff = now.minus(size);
        FileAnalyzedEvent head;
        while ((head = events.peekFirst()) != null && head.at().isBefore(cutoff)) {
            events.pollFirst();
        }
    }

    public List<FileAnalyzedEvent> snapshot() {
        return List.copyOf(events);
    }

    public Duration size() {
        return size;
    }
}

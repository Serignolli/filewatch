package com.serignolli.filewatch.watcher;

import java.nio.file.Path;
import java.time.Instant;

public record FileChangedEvent(Path path, ChangeType type, Instant at) {}

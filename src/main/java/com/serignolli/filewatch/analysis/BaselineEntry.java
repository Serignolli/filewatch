package com.serignolli.filewatch.analysis;

import java.nio.file.Path;
import java.time.Instant;

public record BaselineEntry(Path path, long size, Instant mtime, String sha256, double entropy) {}

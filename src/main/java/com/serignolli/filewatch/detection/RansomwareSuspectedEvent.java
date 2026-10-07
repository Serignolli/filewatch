package com.serignolli.filewatch.detection;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

public record RansomwareSuspectedEvent(
        Severity severity,
        List<String> reasons,       // sinais que dispararam
        List<Path> involvedFiles,
        Instant at
) {}

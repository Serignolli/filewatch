package com.serignolli.filewatch.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.time.Clock;
import java.util.concurrent.ThreadPoolExecutor;

@Configuration
@EnableAsync
public class AsyncConfig {

    public static final String ANALYSIS_EXECUTOR = "analysisExecutor";

    /**
     * Pool das análises (hash + entropia). O gargalo é I/O de disco, então não adianta
     * muitas threads: core ~ nº de núcleos e fila limitada.
     * <p>
     * Com a fila cheia, {@link ThreadPoolExecutor.CallerRunsPolicy} faz a thread que publicou
     * rodar a análise ela mesma: isso freia o produtor (backpressure) em vez de descartar eventos.
     * Quem publica é a thread de debounce do watcher, não a do {@code WatchService.take()}.
     */
    @Bean(name = ANALYSIS_EXECUTOR)
    public ThreadPoolTaskExecutor analysisExecutor() {
        int cores = Runtime.getRuntime().availableProcessors();
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(cores);
        executor.setMaxPoolSize(cores * 2);
        executor.setQueueCapacity(1_000);
        executor.setThreadNamePrefix("analyzer-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(10);
        return executor;
    }

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}

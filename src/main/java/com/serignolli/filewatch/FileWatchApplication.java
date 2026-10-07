package com.serignolli.filewatch;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class FileWatchApplication {

    public static void main(String[] args) {
        SpringApplication.run(FileWatchApplication.class, args);
    }
}

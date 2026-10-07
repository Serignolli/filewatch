package com.serignolli.filewatch.analysis;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class EntropyCalculatorTest {

    @Test
    void emptyAndConstantBuffersHaveZeroEntropy() {
        assertThat(EntropyCalculator.of(new byte[0])).isZero();
        assertThat(EntropyCalculator.of(new byte[4096])).isZero();
    }

    @Test
    void uniformDistributionHasEightBits() {
        byte[] all = new byte[256 * 16];
        for (int i = 0; i < all.length; i++) {
            all[i] = (byte) i;
        }
        assertThat(EntropyCalculator.of(all)).isCloseTo(8.0, within(1e-9));
    }

    @Test
    void textIsLowAndRandomIsNearEight() {
        String text = "O FileWatch observa uma única pasta e reage a mudanças nos arquivos dela. ".repeat(500);
        byte[] random = new byte[256 * 1024];
        new SecureRandom().nextBytes(random);

        assertThat(EntropyCalculator.of(text.getBytes(StandardCharsets.UTF_8))).isBetween(3.5, 5.0);
        assertThat(EntropyCalculator.of(random)).isGreaterThan(7.99);
    }

    @Test
    void onlyTheFirstLimitBytesAreSampled() {
        EntropyCalculator calculator = new EntropyCalculator(1024);
        calculator.update(new byte[1024], 0, 1024); // zeros
        byte[] random = new byte[8192];
        new SecureRandom().nextBytes(random);
        calculator.update(random, 0, random.length); // ignorado: já saturou

        assertThat(calculator.isSaturated()).isTrue();
        assertThat(calculator.entropy()).isZero();
    }
}

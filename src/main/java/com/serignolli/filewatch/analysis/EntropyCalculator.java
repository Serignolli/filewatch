package com.serignolli.filewatch.analysis;

/**
 * Entropia de Shannon em bits por byte (0.0 – 8.0), SPEC §6.
 * <pre>
 *   H = - Σ p(x) · log2(p(x))   para cada byte x de 0..255 que aparece
 * </pre>
 * Funciona por streaming: {@link #update} pode ser chamado a cada bloco lido e só os primeiros
 * {@code limit} bytes entram na conta (amostragem barata para arquivos grandes).
 */
public final class EntropyCalculator {

    private static final double LN_2 = Math.log(2);

    private final long[] counts = new long[256];
    private final long limit;
    private long total;

    public EntropyCalculator(long limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit deve ser positivo");
        }
        this.limit = limit;
    }

    public static double of(byte[] data) {
        EntropyCalculator calculator = new EntropyCalculator(Math.max(1, data.length));
        calculator.update(data, 0, data.length);
        return calculator.entropy();
    }

    public void update(byte[] buffer, int offset, int length) {
        int n = (int) Math.min(length, limit - total);
        for (int i = offset; i < offset + n; i++) {
            counts[buffer[i] & 0xFF]++;
        }
        total += n;
    }

    public boolean isSaturated() {
        return total >= limit;
    }

    public double entropy() {
        if (total == 0) {
            return 0.0;
        }
        double h = 0.0;
        for (long count : counts) {
            if (count > 0) {
                double p = (double) count / total;
                h -= p * (Math.log(p) / LN_2);
            }
        }
        return h;
    }
}

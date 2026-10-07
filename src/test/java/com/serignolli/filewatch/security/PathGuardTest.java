package com.serignolli.filewatch.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static com.serignolli.filewatch.TestSupport.properties;
import static com.serignolli.filewatch.TestSupport.propertiesRequiringMarker;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PathGuardTest {

    @TempDir
    Path root;

    Path sandbox;
    Path outside;
    PathGuard guard;

    @BeforeEach
    void setUp() throws IOException {
        sandbox = Files.createDirectories(root.resolve("sandbox"));
        outside = Files.createDirectories(root.resolve("outside"));
        guard = new PathGuard(properties(sandbox, root));
    }

    @Test
    void acceptsFilesInsideTheSandbox() throws IOException {
        Path file = Files.writeString(sandbox.resolve("a.txt"), "x");
        Path nested = Files.createDirectories(sandbox.resolve("sub/deep")).resolve("b.txt");

        assertThat(guard.isInside(file)).isTrue();
        assertThat(guard.isInside(nested)).isTrue(); // ainda não existe: resolve pelo ancestral
    }

    @Test
    void rejectsFilesOutsideAndPathTraversal() throws IOException {
        Path secret = Files.writeString(outside.resolve("secret.txt"), "x");

        assertThat(guard.isInside(secret)).isFalse();
        assertThat(guard.isInside(sandbox.resolve("../outside/secret.txt"))).isFalse();
        assertThat(guard.isInside(sandbox.resolve("sub/../../outside/secret.txt"))).isFalse();
    }

    @Test
    void acceptsDeletedFilesInsideSoDeletionsCanBeTracked() {
        assertThat(guard.resolveInside(sandbox.resolve("gone/already-deleted.txt")))
                .isPresent()
                .get().satisfies(p -> assertThat(p.startsWith(guard.base())).isTrue());
    }

    @Test
    void rejectsSymlinkPointingOutside() throws IOException {
        Path link = sandbox.resolve("escape");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (IOException | UnsupportedOperationException e) {
            assumeTrue(false, "Sem permissão para criar symlink neste SO: " + e);
        }
        Files.writeString(outside.resolve("secret.txt"), "x");

        assertThat(guard.isInside(link.resolve("secret.txt"))).isFalse();
    }

    @Test
    void refusesFilesystemRootAsSandbox() {
        Path fsRoot = root.getRoot();
        assertThatThrownBy(() -> new PathGuard(properties(fsRoot, root)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void refusesHomeAndFoldersThatContainIt() {
        Path home = Path.of(System.getProperty("user.home"));
        assertThatThrownBy(() -> new PathGuard(properties(home, root)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("home");
        Path parentOfHome = home.toAbsolutePath().getParent();
        if (parentOfHome != null && parentOfHome.getParent() != null) {
            assertThatThrownBy(() -> new PathGuard(properties(parentOfHome, root)))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void withMarkerRequiredRefusesUnmarkedOrMissingFolder() {
        assertThatThrownBy(() -> new PathGuard(propertiesRequiringMarker(sandbox, root)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(PathGuard.SANDBOX_MARKER);

        Path missing = root.resolve("does-not-exist");
        assertThatThrownBy(() -> new PathGuard(propertiesRequiringMarker(missing, root)))
                .isInstanceOf(IllegalStateException.class);
        assertThat(missing).doesNotExist(); // não cria pastas quando o marcador é exigido
    }

    @Test
    void withMarkerRequiredAcceptsMarkedFolder() throws IOException {
        Files.writeString(sandbox.resolve(PathGuard.SANDBOX_MARKER), "marcador");

        PathGuard marked = new PathGuard(propertiesRequiringMarker(sandbox, root));

        assertThat(marked.base()).isEqualTo(sandbox.toRealPath());
    }
}

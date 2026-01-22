package com.apiposture.core.analysis;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Loads and parses Java source files using JavaParser.
 */
public class SourceFileLoader {

    private final JavaParser parser;
    private final List<String> excludePatterns;

    public SourceFileLoader() {
        this(List.of());
    }

    public SourceFileLoader(List<String> excludePatterns) {
        this.excludePatterns = excludePatterns;

        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21);
        this.parser = new JavaParser(config);
    }

    /**
     * Parse Java source code from string.
     */
    public Optional<CompilationUnit> parseText(String code) {
        ParseResult<CompilationUnit> result = parser.parse(code);
        if (result.isSuccessful() && result.getResult().isPresent()) {
            return result.getResult();
        }
        return Optional.empty();
    }

    /**
     * Parse a single Java file.
     */
    public Optional<CompilationUnit> parseFile(Path filePath) {
        try {
            ParseResult<CompilationUnit> result = parser.parse(filePath);
            if (result.isSuccessful() && result.getResult().isPresent()) {
                CompilationUnit cu = result.getResult().get();
                cu.setStorage(filePath);
                return Optional.of(cu);
            }
        } catch (IOException e) {
            // Log and continue - we want to process what we can
            System.err.println("Warning: Could not parse file " + filePath + ": " + e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Find all Java files in a directory.
     */
    public List<Path> findJavaFiles(Path directory) throws IOException {
        List<Path> files = new ArrayList<>();

        if (!Files.exists(directory)) {
            return files;
        }

        Files.walkFileTree(directory, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                String dirName = dir.getFileName().toString();
                // Skip common non-source directories
                if (dirName.equals("target") || dirName.equals("build") ||
                        dirName.equals(".git") || dirName.equals(".idea") ||
                        dirName.equals("node_modules") || dirName.equals("test")) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                // Check exclude patterns
                for (String pattern : excludePatterns) {
                    if (matchesPattern(dir, pattern)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (file.toString().endsWith(".java")) {
                    // Skip test files by default
                    String pathStr = file.toString();
                    if (!pathStr.contains("/test/") && !pathStr.contains("\\test\\") &&
                            !pathStr.contains("/tests/") && !pathStr.contains("\\tests\\")) {
                        boolean excluded = false;
                        for (String pattern : excludePatterns) {
                            if (matchesPattern(file, pattern)) {
                                excluded = true;
                                break;
                            }
                        }
                        if (!excluded) {
                            files.add(file);
                        }
                    }
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });

        return files;
    }

    /**
     * Load and parse all Java files from a directory.
     */
    public List<ParsedFile> loadProject(Path projectPath) throws IOException {
        List<ParsedFile> parsedFiles = new ArrayList<>();
        List<Path> javaFiles = findJavaFiles(projectPath);

        for (Path file : javaFiles) {
            parseFile(file).ifPresent(cu ->
                parsedFiles.add(new ParsedFile(file, cu))
            );
        }

        return parsedFiles;
    }

    /**
     * Check if a path matches a glob pattern.
     */
    private boolean matchesPattern(Path path, String pattern) {
        try {
            PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + pattern);
            return matcher.matches(path) || matcher.matches(path.getFileName());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Represents a parsed Java file.
     */
    public record ParsedFile(Path path, CompilationUnit compilationUnit) {
        public String getFileName() {
            return path.getFileName().toString();
        }

        public String getAbsolutePath() {
            return path.toAbsolutePath().toString();
        }
    }
}

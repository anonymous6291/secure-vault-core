package com.securevault;

import java.nio.file.Path;

public class FileManager {
    private static final String FILE_STORAGE_FOLDER_NAME = "files";
    private static final String FILE_DATA_NAME = "files.data";
    private final Path basePath;

    FileManager(Path basePath) {
        this.basePath = basePath;
    }
}

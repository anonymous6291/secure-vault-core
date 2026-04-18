package com.securevault;

import java.nio.file.Path;

public interface FileTransferManagerListener {
    String getFileName(Path from, Path to, FileTransferMode mode);

    void fileTransferCompleted(Path from, Path to, FileTransferMode mode);
}
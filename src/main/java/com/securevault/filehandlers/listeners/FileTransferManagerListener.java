package com.securevault.filehandlers.listeners;

import com.securevault.filehandlers.FileTransferMode;

import java.nio.file.Path;

public interface FileTransferManagerListener {
    void fileTransferCompleted(Path from, Path to, FileTransferMode mode);
}
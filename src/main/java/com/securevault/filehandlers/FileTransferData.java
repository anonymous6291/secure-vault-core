package com.securevault.filehandlers;

import java.nio.file.Path;

public record FileTransferData(Path from, Path to, FileTransferMode mode) {
}

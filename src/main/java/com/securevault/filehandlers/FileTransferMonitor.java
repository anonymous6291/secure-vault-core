package com.securevault.filehandlers;

import java.util.List;

public interface FileTransferMonitor {
    int getNumberOfFilesPending();

    int getNumberOfFilesFailed();

    List<String> getFailedFilesList();

    double getProgress();
}
package com.securevault;

import java.util.List;

public interface FileTransferMonitor {
    public int getNumberOfFilesPending();

    public int getNumberOfFilesFailed();

    public List<String> getFailedFilesList();

    public double getProgress();
}
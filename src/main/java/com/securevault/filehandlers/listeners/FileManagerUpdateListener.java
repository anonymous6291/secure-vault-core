package com.securevault.filehandlers.listeners;

import com.securevault.filehandlers.FileTransferMonitor;

import java.util.List;

public interface FileManagerUpdateListener {

    void setFileTransferMonitor(FileTransferMonitor fileTransferMonitor);

    int askForResponse(List<String> query);

    void newUpdate(String update);
}

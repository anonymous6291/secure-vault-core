package com.securevault;

import com.securevault.filehandlers.FileTransferMonitor;
import com.securevault.filehandlers.listeners.FileManagerUpdateListener;

public class Main {
    static void main() throws Exception {
        String password1 = "WORLD";
        String password = "Hello";
        FileManagerUpdateListener fileManagerUpdateListener = new FileManagerUpdateListener() {
            @Override
            public void setFileTransferMonitor(FileTransferMonitor fileTransferMonitor) {
            }

            @Override
            public ResponseType askForResponse(String query) {
                return ResponseType.YES;
            }

            @Override
            public void newUpdate(String update) {

            }
        };
        //Vault vault = new Vault(System.getProperty("user.dir"), true, password.toCharArray());
        Vault vault = new Vault(System.getProperty("user.dir") + "/Secure Vault", false, password.toCharArray(), fileManagerUpdateListener);
        //Logger.clearLogs();
        //vault.changeVaultPassword(password.toCharArray(), password1.toCharArray());
        try {
            //vault.putFiles(Path.of("/home/anonymous/Desktop/text.txt"));
        } catch (Exception e) {
            IO.println(e);
        }
        String logs = Logger.getLogs(100);
        IO.println("Logs :\n" + logs);
        if (logs.length() > 400) {
            //Logger.clearLogs();
        }
        vault.closeVault();
    }
}

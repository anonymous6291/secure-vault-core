package com.securevault.filehandlers;

import com.securevault.Logger;
import com.securevault.configurations.CipherManager;
import com.securevault.configurations.ConfigurationDefaults;
import com.securevault.configurations.RandomValueGenerator;
import com.securevault.filehandlers.listeners.FileManagerUpdateListener;
import com.securevault.filehandlers.listeners.FileTransferManagerListener;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

public class FileManager implements FileTransferManagerListener {
    private static final String FILE_STORAGE_FOLDER_NAME = "files";
    private static final String FILE_DATA_NAME = "files.data";
    private static final String FILE_DATA_END_MARKER = "#############################END#############################";
    private static final Duration DELAY = Duration.ofMillis(300);
    private final Semaphore lock = new Semaphore(1);
    private final Path fileDataPath;
    private final Path fileStoragePath;
    private final char[] vaultKey;
    private final byte[] iv;
    private final byte[] salt;
    private final ConcurrentMap<Path, FileData> allFilesDataMapping;
    private final ConcurrentMap<Path, Path> allFilesMaskedNameMapping;
    private final FileTransferManager fileTransferManager;
    private final FileManagerUpdateListener fileManagerUpdateListener;
    private volatile char[] nextFileName;

    public FileManager(Path basePath, char[] vaultKey, FileManagerUpdateListener fileManagerUpdateListener) throws Exception {
        fileDataPath = basePath.resolve(FILE_DATA_NAME);
        fileStoragePath = basePath.resolve(FILE_STORAGE_FOLDER_NAME);
        if (!Files.isRegularFile(fileDataPath)) {
            Files.createFile(fileDataPath);
        }
        if (!Files.isDirectory(fileStoragePath)) {
            Files.createDirectories(fileStoragePath);
        }
        this.vaultKey = vaultKey;
        this.fileManagerUpdateListener = fileManagerUpdateListener;
        allFilesDataMapping = new ConcurrentHashMap<>();
        allFilesMaskedNameMapping = new ConcurrentHashMap<>();
        File dataFile = fileDataPath.toFile();
        String lastFileName = "0";
        Logger.logInfo("FileManager started.");
        if (dataFile.length() > 0) {
            BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(fileDataPath));
            iv = bufferedInputStream.readNBytes(ConfigurationDefaults.IV_LENGTH);
            salt = bufferedInputStream.readNBytes(ConfigurationDefaults.SALT_LENGTH);
            Cipher cipher = CipherManager.getCipher(vaultKey, iv, salt, Cipher.DECRYPT_MODE);
            CipherInputStream cipherInputStream = new CipherInputStream(bufferedInputStream, cipher);
            String fileData = new String(cipherInputStream.readAllBytes());
            cipherInputStream.close();
            String[] data = fileData.split("\n");
            int n = data.length;
            for (int i = 2; i < n; i += 3) {
                String path = data[i - 2];
                String maskedName = data[i - 1];
                String originalName = data[i];
                Path mainPath = fileStoragePath.resolve(path);
                Path maskedFilePath = mainPath.resolve(maskedName);
                File file = maskedFilePath.toFile();
                if (!file.exists()) {
                    Logger.logError("File [" + originalName + "] has entry but doesn't exist, skipping it.");
                } else {
                    if (!isValidFileName(maskedName)) {
                        Logger.logError("[" + maskedName + "] is not a valid file name, skipping it.");
                    } else {
                        if (lastFileName.compareTo(maskedName) < 0) {
                            lastFileName = maskedName;
                        }
                        FileData currentFileData = new FileData(originalName, maskedName, file.length(), path);
                        allFilesDataMapping.put(maskedFilePath, currentFileData);
                        allFilesMaskedNameMapping.put(mainPath.resolve(originalName), maskedFilePath);
                    }
                }
            }
            Logger.logInfo("Total [" + allFilesDataMapping.size() + "] file entries scanned.");
        } else {
            iv = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.IV_LENGTH);
            salt = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.SALT_LENGTH);
        }
        this.nextFileName = lastFileName.toCharArray();
        fileTransferManager = new FileTransferManager(vaultKey, this);
        fileTransferManager.start();
        fileManagerUpdateListener.setFileTransferMonitor(fileTransferManager);
        if (!allFilesDataMapping.isEmpty()) {
            incrementNextFileName();
        }
    }

    private Path removeParent(Path childPath, Path parentPath) {
        String child = childPath.toString();
        String parent = parentPath.toString();
        return Path.of(child.substring(child.indexOf(parent) + parent.length()));
    }

    @Override
    public void fileTransferCompleted(Path from, Path to, FileTransferMode mode) {
        if (mode == FileTransferMode.ENCRYPT) {
            File toFile = to.toFile();
            String fromFileName = from.getFileName().toString();
            FileData fileData = new FileData(fromFileName, toFile.getName(), toFile.length(), removeParent(to.getParent(), fileStoragePath).toString());
            allFilesDataMapping.put(to, fileData);
            allFilesMaskedNameMapping.put(fileStoragePath.resolve(fileData.getOriginalFilePath()), to);
        }
        Logger.logInfo("File [" + from + "] transfer complete.");
    }

    private void incrementNextFileName() {
        for (int i = nextFileName.length - 1; i >= 0; i--) {
            if (nextFileName[i] == '9') {
                nextFileName[i] = '0';
            } else {
                nextFileName[i]++;
                return;
            }
        }
        int n = nextFileName.length;
        char[] nextFileName = new char[n + 1];
        Arrays.fill(nextFileName, 0, n + 1, '0');
        this.nextFileName = nextFileName;
    }

    private boolean lock() {
        try {
            lock.acquire();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void unlock() {
        lock.release();
    }

    private boolean isValidFileName(String name) {
        int n = name.length();
        for (int i = 0; i < n; i++) {
            char x = name.charAt(i);
            if (x < '0' || x > '9') {
                return false;
            }
        }
        return true;
    }

    private boolean fileExists(Path filePath, FileTransferMode mode) {
        if (mode == FileTransferMode.ENCRYPT) {
            return allFilesMaskedNameMapping.containsKey(filePath);
        } else {
            return Files.exists(filePath);
        }
    }

    private Path renameFile(Path toFilePath, FileTransferMode mode) {
        Path parent = toFilePath.getParent();
        String fileName = toFilePath.getFileName().toString();
        int dotIndex = fileName.indexOf(".");
        String firstName, extension;
        if (dotIndex == -1) {
            firstName = fileName;
            extension = "";
        } else {
            firstName = fileName.substring(0, dotIndex);
            extension = fileName.substring(dotIndex);
        }
        int start = 1;
        Path newFilePath;
        while (fileExists(newFilePath = parent.resolve(firstName + start + extension), mode)) {
            start++;
        }
        return newFilePath;
    }

    private void addFile0(Path from, Path to, FileTransferMode mode, List<FileTransferData> fileTransferDataList, FileCopyOption fileCopyOption) {
        Path toFilePath = null;
        if (mode == FileTransferMode.ENCRYPT) {
        } else {
            FileData fileData = allFilesDataMapping.get(from);
            String originalFileName = fileData.getOriginalName();
            toFilePath = to.resolve(originalFileName);
            if (Files.exists(toFilePath)) {
                FileCopyOption.Type fileCopyType = fileCopyOption.getType();
                if (fileCopyType == FileCopyOption.Type.RENAME_ALL || fileCopyType == FileCopyOption.Type.RENAME) {
                    toFilePath = renameFile(toFilePath, mode);
                } else if (fileCopyType == FileCopyOption.Type.SKIP_ALL || fileCopyType == FileCopyOption.Type.SKIP) {
                    return;
                } else if (fileCopyType != FileCopyOption.Type.REPLACE_ALL) {
                    int index = fileManagerUpdateListener.askForResponse(FileCopyOption.options);
                    fileCopyOption.setType(index);
                    return;
                }
            }
        }
        FileTransferData fileTransferData = new FileTransferData(from, toFilePath, mode);
        fileTransferDataList.add(fileTransferData);
    }

    private void recursivelyAddFiles(Path from, Path to, FileTransferMode mode, List<FileTransferData> fileTransferDataList, FileCopyOption fileCopyOption) {
        if (Files.isDirectory(from)) {
            Path toSubDirectory = to.resolve(from.getFileName());
            try (Stream<Path> pathStream = Files.list(from)) {
                pathStream.forEach(fromSubDirectory -> recursivelyAddFiles(fromSubDirectory, toSubDirectory, mode, fileTransferDataList, fileCopyOption));
            } catch (Exception e) {
            }
        } else if (Files.isRegularFile(from)) {
            addFile0(from, to, mode, fileTransferDataList, fileCopyOption);
        }
    }

    public void addFiles(Path from) throws FileNotFoundException {
        if (!Files.exists(from)) {
            throw new FileNotFoundException("[" + from + "] doesn't exist.");
        }
        List<FileTransferData> fileTransferDataList = new LinkedList<>();
        recursivelyAddFiles(from, fileStoragePath, FileTransferMode.ENCRYPT, fileTransferDataList, new FileCopyOption());
        fileTransferManager.transferFiles(fileTransferDataList);
    }

    public void getFiles(Path from, Path to) throws FileNotFoundException {
        Path fromPath = fileStoragePath.resolve(from);
        if (!Files.exists(fromPath)) {
            throw new FileNotFoundException("[" + from + "] doesn't exist.");
        }
        List<FileTransferData> fileTransferDataList = new LinkedList<>();
        recursivelyAddFiles(from, to, FileTransferMode.DECRYPT, fileTransferDataList, new FileCopyOption());
        fileTransferManager.transferFiles(fileTransferDataList);
    }

    public boolean changeFileName(Path path, String newOriginalName) {
        Path maskedPath = allFilesMaskedNameMapping.remove(path);
        if (maskedPath == null) {
            Logger.logError("Attempted to rename a file which doesn't has entry.");
            return false;
        }
        FileData fileData = allFilesDataMapping.get(maskedPath);
        fileData.setOriginalName(newOriginalName);
        allFilesMaskedNameMapping.put(path.resolveSibling(newOriginalName), maskedPath);
        return true;
    }

    private void deleteFile0(Path originalFilePath) {
        Path maskedFilePath = allFilesMaskedNameMapping.remove(originalFilePath);
        if (maskedFilePath != null) {
            try {
                allFilesDataMapping.remove(maskedFilePath);
                Files.delete(maskedFilePath);
            } catch (Exception e) {
                Logger.logError("Failed to delete file [" + originalFilePath + "] : " + e);
            }
        }
    }

    private void deleteDirectory0(Path filePath) {
        if (Files.isDirectory(filePath)) {
            try (Stream<Path> files = Files.list(filePath)) {
                files.forEach(this::deleteDirectory0);
                Files.delete(filePath);
            } catch (Exception e) {
                Logger.logError("Failed to delete file [" + filePath + "] : " + e);
            }
        } else {
            try {
                FileData fileData = allFilesDataMapping.get(filePath);
                Files.delete(filePath);
                allFilesDataMapping.remove(filePath);
                allFilesMaskedNameMapping.remove(filePath.resolveSibling(fileData.getOriginalName()));
            } catch (Exception e) {
                Logger.logError("Failed to delete file [" + filePath + "] : " + e);
            }
        }
    }

    public void deleteDirectory(Path path) {
        if (!lock()) {
            return;
        }
        Path fileToBeDeleted = fileStoragePath.resolve(path);
        if (Files.isDirectory(fileToBeDeleted)) {
            Logger.logWarn("Deleting directory [" + path + "] .");
            deleteDirectory0(fileToBeDeleted);
        }
        unlock();
    }

    public List<String> getFilesList() {
        if (!lock()) {
            return null;
        }
        List<String> fileDataList = allFilesDataMapping.values().stream().map(fileData -> fileData.getOriginalFilePath().toString()).toList();
        unlock();
        Logger.logInfo("All files list accessed.");
        return fileDataList;
    }

    public void close() throws Exception {
        if (!lock()) {
            return;
        }
        fileTransferManager.shutdown();
        try {
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(Files.newOutputStream(fileDataPath));
            bufferedOutputStream.write(iv);
            bufferedOutputStream.write(salt);
            Cipher cipher = CipherManager.getCipher(vaultKey, iv, salt, Cipher.ENCRYPT_MODE);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(bufferedOutputStream, cipher);
            for (FileData data : allFilesDataMapping.values()) {
                String value = data.getFilePath() + "\n" + data.getMaskedName() + "\n" + data.getOriginalName() + "\n";
                cipherOutputStream.write(value.getBytes());
            }
            cipherOutputStream.write(FILE_DATA_END_MARKER.getBytes());
            cipherOutputStream.close();
            Logger.logInfo("FileManager closed.");
        } catch (Exception e) {
            Logger.logError("Exception occurred while closing the FileManager : " + e);
            throw e;
        } finally {
            unlock();
        }
    }

    static class FileCopyOption {
        enum Type {
            DEFAULT, REPLACE, REPLACE_ALL, RENAME, RENAME_ALL, SKIP, SKIP_ALL
        }

        private static final List<String> options = Arrays.stream(Type.values()).filter(x -> x != Type.DEFAULT).map(Enum::toString).toList();

        private Type type;

        FileCopyOption() {
            this.type = Type.DEFAULT;
        }

        static List<String> getOptions() {
            return options;
        }

        Type getType() {
            return type;
        }

        void setType(Type type) {
            this.type = type;
        }

        void setType(int type) {
            this.type = switch (type) {
                case 0 -> Type.REPLACE;
                case 1 -> Type.REPLACE_ALL;
                case 2 -> Type.RENAME;
                case 3 -> Type.RENAME_ALL;
                case 4 -> Type.SKIP;
                default -> Type.SKIP_ALL;
            };
        }
    }
}
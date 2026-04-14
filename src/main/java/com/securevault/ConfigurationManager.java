package com.securevault;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

public class ConfigurationManager {
    private static final String VERSION = "1.0.0";
    private static final int KEY_LENGTH = 50;
    private static final int IV_LENGTH = 12;
    private static final int SALT_LENGTH = 16;
    private static final int MAX_TRIES = 5;
    private static final long WRONG_TRY_DELAY_MILLIS = 5 * 60 * 1000;
    private static final ObjectMapper json = new ObjectMapper();
    private static final Base64.Encoder base64Encoder = Base64.getEncoder();
    private static final Base64.Decoder base64Decoder = Base64.getDecoder();
    private final Path configurationPath;
    private final Configuration configuration;
    private final char[] vaultKey;

    static {
        json.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    ConfigurationManager(Path config, boolean create, char[] key) throws Exception {
        configurationPath = config;
        ConfigurationDefaults.Data configurationManagerData = ConfigurationDefaults.getDefault(ConfigurationManager.class);
        if (create) {
            byte[] generatedChar = generateRandomBytes(KEY_LENGTH);
            vaultKey = base64Encoder.encodeToString(generatedChar).toCharArray();
            byte[] iv = generateRandomBytes(IV_LENGTH);
            byte[] salt = generateRandomBytes(SALT_LENGTH);
            Cipher cipher = CipherManager.getCipher(key, iv, salt, true);
            byte[] encr = cipher.doFinal(generatedChar);
            configuration = new Configuration(VERSION, false, 0, 1, false, 0, base64Encoder.encodeToString(encr), base64Encoder.encodeToString(iv), base64Encoder.encodeToString(salt));
        } else {
            byte[] configData = Files.readAllBytes(config);
            Cipher cipher = CipherManager.getCipher(configurationManagerData.key(), configurationManagerData.iv(), configurationManagerData.salt(), false);
            String configString = new String(cipher.doFinal(configData), StandardCharsets.UTF_16);
            configuration = json.readValue(configString, Configuration.class);
            IO.println(configString);
            if (configuration.getLockdown() && configuration.getLockdown_end_time() >= System.currentTimeMillis()) {
                throw new LockdownModeException("Vault is in lockdown mode.");
            }
            byte[] encrKey = base64Decoder.decode(configuration.getKey());
            byte[] iv = base64Decoder.decode(configuration.getIv());
            byte[] salt = base64Decoder.decode(configuration.getSalt());
            try {
                Cipher cipher1 = CipherManager.getCipher(key, iv, salt, false);
                byte[] decrKey = cipher1.doFinal(encrKey);
                vaultKey = base64Encoder.encodeToString(decrKey).toCharArray();
                configuration.setLockdown(false);
                configuration.setTries(0);
            } catch (AEADBadTagException e) {
                int tries = configuration.getTries() + 1;
                if (tries > MAX_TRIES) {
                    if (configuration.getSelf_destruct() && configuration.getSelf_destruct_limit() < tries) {
                        String modify = base64Encoder.encodeToString(generateRandomBytes(configuration.getKey().length()));
                        configuration.setKey(modify);
                        configuration.setSelf_destruct(false);
                        configuration.setSelf_destruct_limit(0);
                    } else {
                        long delay = Math.max(0, ((tries - MAX_TRIES + 2) / 2)) * WRONG_TRY_DELAY_MILLIS;
                        configuration.setLockdown(true);
                        configuration.setLockdown_end_time(delay + System.currentTimeMillis());
                        configuration.setTries(tries);
                    }
                } else {
                    configuration.setTries(tries);
                }
                writeConfiguration();
                throw e;
            }
        }
    }

    private byte[] generateRandomBytes(int len) {
        byte[] random = new byte[len];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(random);
        return random;
    }

    public boolean isLockdownModeEnabled() {
        return configuration.getLockdown();
    }

    public void enableLockdownMode(long duration) {
        configuration.setLockdown(true);
        configuration.setLockdown_end_time(duration + System.currentTimeMillis());
    }

    public boolean isSelfDestructEnabled() {
        return configuration.getSelf_destruct();
    }

    public void disableSelfDestructMode() {
        configuration.setSelf_destruct(false);
        configuration.setSelf_destruct_limit(0);
    }

    public void setSelfDestructMode(int tries) {
        if (tries <= 0) {
            disableSelfDestructMode();
        } else {
            configuration.setSelf_destruct(true);
            configuration.setSelf_destruct_limit(tries);
        }
    }

    public char[] getVaultKey() {
        return vaultKey.clone();
    }

    public void writeConfiguration() throws Exception {
        ConfigurationDefaults.Data defaultConfigurationManagerData = ConfigurationDefaults.getDefault(ConfigurationManager.class);
        String configData = json.writeValueAsString(configuration);
        byte[] data = configData.getBytes(StandardCharsets.UTF_16);
        Cipher cipher = CipherManager.getCipher(defaultConfigurationManagerData.key(), defaultConfigurationManagerData.iv(), defaultConfigurationManagerData.salt(), true);
        data = cipher.doFinal(data);
        Files.write(configurationPath, data);
    }

    static class Configuration {
        private String version;
        private boolean lockdown;
        private long lockdown_end_time;
        private int tries;
        private boolean self_destruct;
        private int self_destruct_limit;
        private String key;
        private String iv;
        private String salt;

        public Configuration(String version, boolean lockdown, long lockdown_end_time, int tries, boolean self_destruct, int self_destruct_limit, String key, String iv, String salt) {
            this.version = version;
            this.lockdown = lockdown;
            this.lockdown_end_time = lockdown_end_time;
            this.tries = tries;
            this.self_destruct = self_destruct;
            this.self_destruct_limit = self_destruct_limit;
            this.key = key;
            this.iv = iv;
            this.salt = salt;
        }

        public Configuration() {
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public boolean getLockdown() {
            return lockdown;
        }

        public void setLockdown(boolean lockdown) {
            this.lockdown = lockdown;
        }

        public long getLockdown_end_time() {
            return lockdown_end_time;
        }

        public void setLockdown_end_time(long lockdown_end_time) {
            this.lockdown_end_time = lockdown_end_time;
        }

        public int getTries() {
            return tries;
        }

        public void setTries(int tries) {
            this.tries = tries;
        }

        public boolean getSelf_destruct() {
            return self_destruct;
        }

        public void setSelf_destruct(boolean self_destruct) {
            this.self_destruct = self_destruct;
        }

        public int getSelf_destruct_limit() {
            return self_destruct_limit;
        }

        public void setSelf_destruct_limit(int self_destruct_limit) {
            this.self_destruct_limit = self_destruct_limit;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getIv() {
            return iv;
        }

        public void setIv(String iv) {
            this.iv = iv;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }
    }
}

class LockdownModeException extends RuntimeException {
    LockdownModeException(String message) {
        super(message);
    }
}

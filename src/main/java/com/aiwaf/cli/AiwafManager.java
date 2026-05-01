package com.aiwaf.cli;

import com.aiwaf.runtime.BlacklistManager;
import com.aiwaf.runtime.RuntimeStorage;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AiwafManager {
    private final String dataPath;

    public AiwafManager() {
        this("aiwaf_data.bin");
    }

    public AiwafManager(String dataPath) {
        this.dataPath = (dataPath == null || dataPath.isBlank()) ? "aiwaf_data.bin" : dataPath;
        RuntimeStorage.initialize("file", this.dataPath);
    }

    public boolean addWhitelistIp(String ip, String reason) {
        if (ip == null || ip.isBlank()) return false;
        BlacklistManager.addToWhitelist(ip.trim(), reason);
        return true;
    }

    public boolean addToWhitelist(String ip) {
        return addWhitelistIp(ip, null);
    }

    public boolean removeWhitelistIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        return BlacklistManager.removeFromWhitelist(ip.trim());
    }

    public boolean removeFromWhitelist(String ip) {
        return removeWhitelistIp(ip);
    }

    public Set<String> listWhitelistIps() {
        Map<String, Object> wl = BlacklistManager.getWhitelist();
        Object ips = wl.get("ips");
        if (!(ips instanceof Set<?> values)) {
            return Set.of();
        }
        Set<String> out = new java.util.HashSet<>();
        for (Object value : values) {
            if (value != null) {
                out.add(String.valueOf(value));
            }
        }
        return out;
    }

    public Set<String> listWhitelist() {
        return listWhitelistIps();
    }

    public boolean addBlacklistIp(String ip, String reason) {
        if (ip == null || ip.isBlank()) return false;
        return BlacklistManager.block(ip.trim(), reason == null ? "manual blacklist" : reason, null);
    }

    public boolean addToBlacklist(String ip, String reason, Map<String, Object> extendedRequestInfo) {
        if (ip == null || ip.isBlank()) return false;
        return BlacklistManager.block(ip.trim(), reason == null ? "manual blacklist" : reason, null, extendedRequestInfo);
    }

    public boolean addToBlacklist(String ip, String reason) {
        return addBlacklistIp(ip, reason);
    }

    public boolean removeBlacklistIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        return BlacklistManager.unblock(ip.trim());
    }

    public List<String> listBlacklistIps() {
        return BlacklistManager.getBlockedIps();
    }

    public Map<String, Map<String, Object>> listBlacklist() {
        Map<String, Map<String, Object>> out = new HashMap<>();
        for (String ip : listBlacklistIps()) {
            Map<String, Object> info = BlacklistManager.getBlockInfo(ip);
            out.put(ip, info == null ? Map.of() : info);
        }
        return out;
    }

    public boolean addKeyword(String keyword) {
        if (keyword == null || keyword.isBlank()) return false;
        RuntimeStorage.getKeywordStore().addKeyword(keyword, 1);
        return true;
    }

    public boolean removeKeyword(String keyword) {
        if (keyword == null || keyword.isBlank()) return false;
        RuntimeStorage.getKeywordStore().removeKeyword(keyword);
        return true;
    }

    public List<String> listKeywords(int limit) {
        return RuntimeStorage.getKeywordStore().getTopKeywords(Math.max(1, limit));
    }

    public List<String> listKeywords() {
        return listKeywords(100);
    }

    public boolean addGeoBlockedCountry(String countryCode) {
        if (countryCode == null || countryCode.isBlank()) return false;
        RuntimeStorage.getGeoBlockStore().addCountry(countryCode);
        return true;
    }

    public boolean removeGeoBlockedCountry(String countryCode) {
        if (countryCode == null || countryCode.isBlank()) return false;
        RuntimeStorage.getGeoBlockStore().removeCountry(countryCode);
        return true;
    }

    public Set<String> listGeoBlockedCountries() {
        return RuntimeStorage.getGeoBlockStore().getCountries();
    }

    public boolean addPathExemption(String path, String reason) {
        if (path == null || path.isBlank()) {
            return false;
        }
        String normalized = path.trim();
        return RuntimeStorage.getPathExemptionStore().addPath(normalized, reason)
                || RuntimeStorage.getPathExemptionStore().getPaths().contains(normalized);
    }

    public boolean removePathExemption(String path) {
        return RuntimeStorage.getPathExemptionStore().removePath(path);
    }

    public Set<String> listPathExemptions() {
        return RuntimeStorage.getPathExemptionStore().getPaths();
    }

    public Map<String, Object> stats() {
        Map<String, Object> out = new HashMap<>();
        out.put("blacklist", BlacklistManager.getStatistics());
        out.put("whitelist_ips", listWhitelistIps().size());
        out.put("keywords", listKeywords(100).size());
        out.put("geo_blocked_countries", listGeoBlockedCountries().size());
        out.put("path_exemptions", listPathExemptions().size());
        out.put("storage_path", dataPath);
        return out;
    }

    public Map<String, Object> showStats() {
        return stats();
    }

    public boolean exportConfig(String path) {
        if (path == null || path.isBlank()) return false;
        Map<String, Object> payload = new HashMap<>();
        payload.put("whitelist_ips", listWhitelistIps());
        payload.put("blacklist", listBlacklist());
        payload.put("keywords", listKeywords(1000));
        payload.put("geo_blocked_countries", listGeoBlockedCountries());
        payload.put("path_exemptions", listPathExemptions());
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(path))) {
            out.writeObject(payload);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public boolean importConfig(String path) {
        if (path == null || path.isBlank()) return false;
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(path))) {
            Object obj = in.readObject();
            if (!(obj instanceof Map<?, ?> map)) {
                return false;
            }

            resetAll();

            Object whitelist = map.get("whitelist_ips");
            if (whitelist instanceof Iterable<?> values) {
                for (Object value : values) {
                    if (value != null) addWhitelistIp(String.valueOf(value), "import");
                }
            }

            Object blacklist = map.get("blacklist");
            if (blacklist instanceof Map<?, ?> values) {
                for (Map.Entry<?, ?> entry : values.entrySet()) {
                    String ip = String.valueOf(entry.getKey());
                    String reason = "import";
                    Map<String, Object> ext = null;
                    if (entry.getValue() instanceof Map<?, ?> info) {
                        Object r = info.get("reason");
                        if (r != null) reason = String.valueOf(r);
                        Object eri = info.get("extended_request_info");
                        if (eri instanceof Map<?, ?> m) {
                            ext = new HashMap<>();
                            for (Map.Entry<?, ?> kv : m.entrySet()) {
                                if (kv.getKey() != null) {
                                    ext.put(String.valueOf(kv.getKey()), kv.getValue());
                                }
                            }
                        }
                    }
                    addToBlacklist(ip, reason, ext);
                }
            }

            Object keywords = map.get("keywords");
            if (keywords instanceof Iterable<?> values) {
                for (Object value : values) {
                    if (value != null) addKeyword(String.valueOf(value));
                }
            }

            Object geo = map.get("geo_blocked_countries");
            if (geo instanceof Iterable<?> values) {
                for (Object value : values) {
                    if (value != null) addGeoBlockedCountry(String.valueOf(value));
                }
            }

            Object paths = map.get("path_exemptions");
            if (paths instanceof Iterable<?> values) {
                for (Object value : values) {
                    if (value != null) addPathExemption(String.valueOf(value), "import");
                }
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public boolean resetAll() {
        return reset(false, false);
    }

    public boolean resetSelective(boolean blacklist, boolean exemptions, boolean keywords) {
        try {
            if (blacklist) {
                for (String ip : listBlacklistIps()) {
                    removeBlacklistIp(ip);
                }
            }
            if (exemptions) {
                for (String ip : listWhitelistIps()) {
                    removeWhitelistIp(ip);
                }
            }
            if (keywords) {
                for (String kw : listKeywords(10000)) {
                    removeKeyword(kw);
                }
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    public boolean reset(boolean blacklistOnly, boolean blacklistAndWhitelist) {
        try {
            if (blacklistOnly || blacklistAndWhitelist || !blacklistOnly) {
                for (String ip : listBlacklistIps()) {
                    removeBlacklistIp(ip);
                }
            }
            if (blacklistAndWhitelist || !blacklistOnly) {
                for (String ip : listWhitelistIps()) {
                    removeWhitelistIp(ip);
                }
            }
            if (!blacklistOnly && !blacklistAndWhitelist) {
                for (String kw : listKeywords(10000)) {
                    removeKeyword(kw);
                }
                for (String cc : listGeoBlockedCountries()) {
                    removeGeoBlockedCountry(cc);
                }
                for (String path : listPathExemptions()) {
                    removePathExemption(path);
                }
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}

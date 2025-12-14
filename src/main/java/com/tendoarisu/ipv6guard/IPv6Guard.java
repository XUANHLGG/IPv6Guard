package com.tendoarisu.ipv6guard;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class IPv6Guard extends JavaPlugin implements CommandExecutor, Listener, TabCompleter {

    private static class BanEntry {
        final UUID id;
        final String prefix;
        final String reason;
        final long time;
        final long expireTime; // 0 means permanent ban

        BanEntry(String prefix, String reason, long time) {
            this.id = UUID.randomUUID();
            this.prefix = prefix;
            this.reason = reason;
            this.time = time;
            this.expireTime = 0; // Permanent ban by default
        }
        
        BanEntry(String prefix, String reason, long time, long expireTime) {
            this.id = UUID.randomUUID();
            this.prefix = prefix;
            this.reason = reason;
            this.time = time;
            this.expireTime = expireTime;
        }
        
        BanEntry(UUID id, String prefix, String reason, long time) {
            this.id = id;
            this.prefix = prefix;
            this.reason = reason;
            this.time = time;
            this.expireTime = 0; // Permanent ban by default
        }
        
        BanEntry(UUID id, String prefix, String reason, long time, long expireTime) {
            this.id = id;
            this.prefix = prefix;
            this.reason = reason;
            this.time = time;
            this.expireTime = expireTime;
        }
    }

    // 使用CopyOnWriteArrayList解决并发修改问题
    private final List<BanEntry> bannedIPv6Ranges = new CopyOnWriteArrayList<>();
    // 按前缀长度分桶，使用TreeMap实现自动倒序排序
    private final TreeMap<Integer, List<BanEntry>> bansByPrefixLength = new TreeMap<>(Comparator.reverseOrder());
    
    // Multi-language support
    private FileConfiguration langConfig;
    private File langFile;
    private String defaultLang = "en"; // Default language
    private final List<String> supportedLangs = List.of("en", "zh"); // Supported languages
    
    // Safety configuration
    private boolean enableProxyGuard = false;
    private int sharedIpThreshold = 10;
    private int timeWindowSeconds = 60;
    private int forbidPrefixBelow = 32;
    
    // Proxy Guard: Map to track IPv6 /64 ranges to UUIDs with timestamps
    private final Map<String, Map<UUID, Long>> ipv6ToPlayers = new ConcurrentHashMap<>();

    @Override
    public void onEnable() {
        this.getCommand("ban6").setExecutor(this);
        this.getCommand("pardon6").setExecutor(this);
        this.getCommand("ban6").setTabCompleter(this);
        this.getCommand("pardon6").setTabCompleter(this);
        
        // Load safety configuration
        loadSafetyConfig();
        
        loadBans();
        loadLanguage();
        
        if (validateProxySupport()) {
            this.getServer().getPluginManager().registerEvents(this, this);
            getLogger().info(getLang("plugin.enabled"));
        } else {
            getLogger().severe(getLang("plugin.proxy_config_error"));
            getServer().getPluginManager().disablePlugin(this);
        }
    }
    
    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String label, String[] args) {
        List<String> completions = new ArrayList<>();
        
        if (command.getName().equalsIgnoreCase("ban6")) {
            if (args.length == 1) {
                // First argument: command options
                completions.add("list");
                completions.add("explain");
            } else if (args.length == 2) {
                if (args[0].equalsIgnoreCase("explain")) {
                    // Second argument for explain: IPv6 addresses/ranges
                    // Basic IPv6 suggestions
                    completions.add("2408:8207::/64");
                    completions.add("::1");
                    completions.add("fe80::/10");
                }
            }
        } else if (command.getName().equalsIgnoreCase("pardon6")) {
            if (args.length == 1) {
                // First argument: ban IDs or IPv6 addresses
                for (BanEntry ban : bannedIPv6Ranges) {
                    completions.add(ban.id.toString());
                    completions.add(ban.prefix);
                }
            }
        }
        
        return completions;
    }
    
    // Load safety configuration from config.yml
    private void loadSafetyConfig() {
        saveDefaultConfig();
        FileConfiguration config = getConfig();
        
        enableProxyGuard = config.getBoolean("safety.enable-proxy-guard", false);
        sharedIpThreshold = config.getInt("safety.shared-ip-threshold", 10);
        timeWindowSeconds = config.getInt("safety.time-window-seconds", 60);
        forbidPrefixBelow = config.getInt("safety.forbid-prefix-below", 32);
        
        if (enableProxyGuard) {
            getLogger().info(getLang("plugin.proxy_guard_enabled", sharedIpThreshold, timeWindowSeconds));
        }
    }

    @Override
    public void onDisable() {
        saveBans();
        getLogger().info(getLang("plugin.disabled"));
    }

    private boolean validateProxySupport() {
        boolean bungeeEnabled = getServer().spigot().getConfig().getBoolean("settings.bungeecord", false);
        boolean velocityEnabled = getServer().spigot().getConfig().getBoolean("settings.velocity-support.enabled", false);
        boolean velocityModernForwarding = getServer().spigot().getConfig().getBoolean("settings.velocity-support.modern", false);
        String velocitySecret = getServer().spigot().getConfig().getString("settings.velocity-support.secret", "");
        
        if (bungeeEnabled) {
            // BungeeCord with IP forwarding
            getLogger().info(getLang("plugin.bungee_forwarding_detected"));
            return true;
        } else if (velocityEnabled && velocityModernForwarding && !velocitySecret.isEmpty()) {
            // Velocity with modern forwarding and secret configured
            getLogger().info(getLang("plugin.velocity_forwarding_detected"));
            return true;
        } else if (velocityEnabled || bungeeEnabled) {
            // Invalid proxy configuration
            getLogger().severe(getLang("plugin.proxy_guard_title"));
            getLogger().severe(getLang("plugin.invalid_proxy_config"));
            getLogger().severe(getLang("plugin.velocity_config_hint"));
            getLogger().severe(getLang("plugin.bungee_config_hint"));
            getLogger().severe(getLang("plugin.proxy_guard_title"));
            return false;
        }
        
        // Standalone server
        return true;
    }
    
    // Multi-language methods
    private void loadLanguage() {
        // Load default language from config or use "en"
        String lang = getConfig().getString("language", defaultLang);
        if (!supportedLangs.contains(lang)) {
            lang = defaultLang;
        }
        
        // Save default language config if not exists
        saveDefaultConfig();
        
        // Load language file
        langFile = new File(getDataFolder(), "lang/" + lang + ".yml");
        if (!langFile.exists()) {
            // Create lang directory if not exists
            langFile.getParentFile().mkdirs();
            // Save default language file
            saveResource("lang/" + lang + ".yml", false);
        }
        
        langConfig = YamlConfiguration.loadConfiguration(langFile);
        
        // Load defaults from jar if missing
        InputStream defLangStream = getResource("lang/" + lang + ".yml");
        if (defLangStream != null) {
            YamlConfiguration defLangConfig = YamlConfiguration.loadConfiguration(new InputStreamReader(defLangStream));
            langConfig.setDefaults(defLangConfig);
        }
    }
    
    private String getLang(String path) {
        return langConfig.getString(path, "[Missing translation: " + path + "]");
    }
    
    private String getLang(String path, Object... args) {
        return String.format(getLang(path), args);
    }

    @EventHandler
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        InetAddress address = event.getAddress();
        if (!(address instanceof Inet6Address inet6)) {
            return;
        }
        
        // Allow forbidden IPv6 addresses to bypass ban check
        if (isForbiddenIPv6(inet6)) {
            return;
        }
        
        // Proxy Guard: Track IPv6 /64 range usage
        if (enableProxyGuard) {
            // Convert IPv6 to /64 network prefix
            String ipv6Network = normalizeIPv6Prefix(address, 64);
            UUID playerUuid = event.getUniqueId();
            long now = System.currentTimeMillis();
            
            // Clean up old entries first
            cleanupOldProxyGuardEntries();
            
            // Update the IPv6 /64 to players map
            Map<UUID, Long> playersMap = ipv6ToPlayers.computeIfAbsent(ipv6Network, k -> new ConcurrentHashMap<>());
            playersMap.put(playerUuid, now);
            
            // Check if the threshold is exceeded
            if (playersMap.size() >= sharedIpThreshold) {
                getLogger().severe(getLang("plugin.proxy_guard_title"));
                getLogger().severe(getLang("messages.proxy_guard_activated"));
                getLogger().severe(getLang("messages.proxy_guard_exceeded", ipv6Network));
                getLogger().severe(getLang("messages.proxy_guard_details", playersMap.size(), sharedIpThreshold));
                getLogger().severe(getLang("messages.proxy_guard_proxy_alert"));
                getLogger().severe(getLang("plugin.proxy_guard_title"));
                
                // Automatically ban the /64 range
                banIPv6Range(ipv6Network, getLang("messages.proxy_guard_ban_reason"), true, this.getServer().getConsoleSender(), 0);
                
                // Disallow current connection
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, getLang("messages.proxy_guard_kick"));
            }
        }

        // Check for expired bans first
        checkExpiredBans();

        // TreeMap已经按前缀长度降序排序，直接遍历即可
        for (Map.Entry<Integer, List<BanEntry>> entry : bansByPrefixLength.entrySet()) {
            List<BanEntry> bans = entry.getValue();
            for (BanEntry ban : bans) {
                if (isIPv6InRange(address, ban.prefix)) {
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, getLang("messages.kick_message", ban.reason));
                    getLogger().info(getLang("messages.banned_connection", address, ban.prefix));
                    return;
                }
            }
        }
    }
    
    // Check and remove expired bans
    private void checkExpiredBans() {
        long now = System.currentTimeMillis();
        List<BanEntry> expiredBans = new ArrayList<>();
        
        // Find expired bans
        for (BanEntry ban : bannedIPv6Ranges) {
            if (ban.expireTime > 0 && now > ban.expireTime) {
                expiredBans.add(ban);
            }
        }
        
        // Remove expired bans
        for (BanEntry ban : expiredBans) {
            bannedIPv6Ranges.remove(ban);
            
            // Remove from prefix length bucket
            int prefixLength = Integer.parseInt(ban.prefix.split("/")[1]);
            List<BanEntry> bans = bansByPrefixLength.get(prefixLength);
            if (bans != null) {
                bans.remove(ban);
                if (bans.isEmpty()) {
                    bansByPrefixLength.remove(prefixLength);
                }
            }
        }
        
        // Save changes if there were expired bans
        if (!expiredBans.isEmpty()) {
            saveBans();
        }
    }
    
    // Parse time string like "1d", "2h", "30m" to milliseconds
    private long parseTimeString(String timeStr) {
        long multiplier = 1;
        if (timeStr.endsWith("d")) {
            multiplier = 86400000; // 1 day in ms
            timeStr = timeStr.substring(0, timeStr.length() - 1);
        } else if (timeStr.endsWith("h")) {
            multiplier = 3600000; // 1 hour in ms
            timeStr = timeStr.substring(0, timeStr.length() - 1);
        } else if (timeStr.endsWith("m")) {
            multiplier = 60000; // 1 minute in ms
            timeStr = timeStr.substring(0, timeStr.length() - 1);
        } else if (timeStr.endsWith("s")) {
            multiplier = 1000; // 1 second in ms
            timeStr = timeStr.substring(0, timeStr.length() - 1);
        }
        
        try {
            long time = Long.parseLong(timeStr);
            return time * multiplier;
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    // Clean up old Proxy Guard entries outside the time window
    private void cleanupOldProxyGuardEntries() {
        long now = System.currentTimeMillis();
        long timeWindowMs = timeWindowSeconds * 1000;
        
        // Iterate through all IPv6 entries
        ipv6ToPlayers.entrySet().removeIf(entry -> {
            String ipv6Str = entry.getKey();
            Map<UUID, Long> playersMap = entry.getValue();
            
            // Remove old player entries
            playersMap.entrySet().removeIf(playerEntry -> {
                long entryTime = playerEntry.getValue();
                return now - entryTime > timeWindowMs;
            });
            
            // Remove the IPv6 entry if it has no players left
            return playersMap.isEmpty();
        });
    }
    
    // Check if an IPv6 address is forbidden
    private boolean isForbiddenIPv6(Inet6Address addr) {
        if (addr.isAnyLocalAddress()) return true;      // ::
        if (addr.isLoopbackAddress()) return true;      // ::1
        if (addr.isMulticastAddress()) return true;     // ff00::/8
        if (addr.isLinkLocalAddress()) return true;     // fe80::/10
        if (addr.isSiteLocalAddress()) return true;     // fec0::/10 (deprecated)

        byte[] b = addr.getAddress();

        // IPv4-mapped ::ffff:x.x.x.x
        if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 &&
            b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 &&
            b[8] == 0 && b[9] == 0 && (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF) {
            return true;
        }

        return false;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (command.getName().equalsIgnoreCase("ban6")) {
            return handleBan6Command(sender, args);
        } else if (command.getName().equalsIgnoreCase("pardon6")) {
            return handlePardon6Command(sender, args);
        }
        return false;
    }
    
    private boolean handleBan6Command(CommandSender sender, String[] args) {
        if (args.length < 1) {
            sender.sendMessage(getLang("commands.ban6.usage"));
            sender.sendMessage(getLang("commands.ban6.example1"));
            sender.sendMessage(getLang("commands.ban6.example2"));
            sender.sendMessage(getLang("commands.ban6.example3"));
            sender.sendMessage(getLang("commands.ban6.example4"));
            sender.sendMessage(getLang("commands.ban6.example5"));
            return false;
        }

        // Check for list command
        if (args[0].equalsIgnoreCase("list")) {
            showBanList(sender);
            return true;
        }
        
        // Check for explain command
        if (args[0].equalsIgnoreCase("explain")) {
            if (args.length < 2) {
                sender.sendMessage("§c" + getLang("commands.ban6.explain_usage"));
                sender.sendMessage("§c" + getLang("commands.ban6.explain_example"));
                return false;
            }
            explainIPv6Prefix(args[1], sender);
            return true;
        }

        String target = args[0];
        boolean force = args.length > 1 && args[args.length - 1].equalsIgnoreCase("-f");
        
        // Parse time parameter if present
        long expireTime = 0; // 0 means permanent ban
        String timeStr = null;
        for (int i = 1; i < args.length; i++) {
            if (args[i].matches("^[0-9]+[dhmss]?$") && !args[i].equalsIgnoreCase("-f")) {
                timeStr = args[i];
                expireTime = System.currentTimeMillis() + parseTimeString(timeStr);
                break;
            }
        }
        
        // Calculate reason end index
        int reasonEndIndex = force ? args.length - 1 : args.length;
        List<String> reasonParts = new ArrayList<>();
        for (int i = 1; i < reasonEndIndex; i++) {
            if (timeStr == null || !args[i].equals(timeStr)) {
                reasonParts.add(args[i]);
            }
        }
        String reason = reasonParts.isEmpty() ? getLang("commands.ban6.default_reason") : String.join(" ", reasonParts);
        
        if (target.contains("/")) {
            // This is a CIDR range
            if (banIPv6Range(target, reason, force, sender, expireTime)) {
                sender.sendMessage(getLang("commands.ban6.success_ban_range", target, reason));
            } else {
                sender.sendMessage(getLang("commands.ban6.failed_ban", target));
            }
        } else {
            // This is a single IPv6 address
            if (banIPv6Address(target, reason, sender, expireTime)) {
                sender.sendMessage(getLang("commands.ban6.success_ban_ip", target, reason));
            } else {
                sender.sendMessage(getLang("commands.ban6.failed_ban", target));
            }
        }

        return true;
    }
    
    // Show the ban list
    private void showBanList(CommandSender sender) {
        if (bannedIPv6Ranges.isEmpty()) {
            sender.sendMessage(getLang("commands.ban6.no_bans"));
            return;
        }
        
        sender.sendMessage("§6" + getLang("commands.ban6.ban_list_title"));
        int count = 0;
        for (BanEntry ban : bannedIPv6Ranges) {
            count++;
            String status = ban.expireTime > 0 ? "Temporary" : "Permanent";
            String expireInfo = ban.expireTime > 0 ? 
                " (Expires: " + new java.util.Date(ban.expireTime) + ")" : "";
            String[] parts = ban.prefix.split("/");
            int prefixLength = Integer.parseInt(parts[1]);
            
            sender.sendMessage("§7" + String.format(getLang("commands.ban6.ban_list_item"), count));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_uuid"), ban.id));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_prefix"), ban.prefix));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_length"), prefixLength));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_reason"), ban.reason));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_status"), status, expireInfo));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_banned_at"), new java.util.Date(ban.time)));
        }
        sender.sendMessage("§6" + String.format(getLang("commands.ban6.ban_list_total"), bannedIPv6Ranges.size()));
    }
    
    // Explain an IPv6 prefix
    private void explainIPv6Prefix(String prefix, CommandSender sender) {
        try {
            String[] parts;
            InetAddress inetAddress;
            int prefixLength;
            
            if (prefix.contains("/")) {
                // This is a CIDR range
                parts = prefix.split("/");
                inetAddress = InetAddress.getByName(parts[0]);
                prefixLength = Integer.parseInt(parts[1]);
            } else {
                // This is a single IPv6 address, treat as /128
                inetAddress = InetAddress.getByName(prefix);
                prefixLength = 128;
            }
            
            if (!(inetAddress instanceof Inet6Address)) {
                sender.sendMessage("§c" + getLang("commands.ban6.explain_error"));
                return;
            }
            
            // Basic information
            sender.sendMessage("§6" + getLang("commands.ban6.explain_title"));
            sender.sendMessage("§7" + String.format(getLang("commands.ban6.explain_prefix"), prefix));
            sender.sendMessage("§7" + String.format(getLang("commands.ban6.explain_length"), prefixLength));
            
            // Check if it's a forbidden IPv6
            if (isForbiddenIPv6((Inet6Address) inetAddress)) {
                sender.sendMessage("§c" + getLang("commands.ban6.explain_forbidden"));
                return;
            }
            
            // Classification
            String classification;
            String impact;
            String ispCommon;
            
            if (prefixLength == 128) {
                classification = "Single Address";
                impact = "Affects only this specific IPv6 address";
                ispCommon = "Common for individual devices";
            } else if (prefixLength >= 64) {
                classification = "/" + prefixLength + " Subnet";
                impact = "Affects a small number of addresses within a single network";
                ispCommon = "Commonly assigned by ISPs to residential networks";
            } else if (prefixLength >= 48) {
                classification = "ISP Customer Block";
                impact = "Affects multiple /64 subnets assigned to a single customer";
                ispCommon = "Assigned by ISPs to business customers";
            } else if (prefixLength >= 32) {
                classification = "Regional Allocation";
                impact = "Affects a large range of addresses in a region";
                ispCommon = "Rarely assigned to individual users";
            } else {
                classification = "Large Network Block";
                impact = "Affects an extremely large number of addresses";
                ispCommon = "Very rarely used in practice";
            }
            
            sender.sendMessage("§7" + String.format(getLang("commands.ban6.explain_classification"), classification));
            sender.sendMessage("§7" + String.format(getLang("commands.ban6.explain_impact"), impact));
            sender.sendMessage("§7" + String.format(getLang("commands.ban6.explain_isp_common"), ispCommon));
            
            // Safety warning
            if (prefixLength < 32) {
                sender.sendMessage("§c" + getLang("commands.ban6.explain_warning_large"));
                sender.sendMessage("§c" + getLang("commands.ban6.explain_warning_force"));
            } else if (prefixLength < 48) {
                sender.sendMessage("§e" + getLang("commands.ban6.explain_warning_medium"));
            }
            
        } catch (UnknownHostException | NumberFormatException e) {
            sender.sendMessage("§cError: Invalid IPv6 address or prefix format.");
            sender.sendMessage("§cExample: /ban6 explain 2408:8207::/64");
        }
    }
    
    private boolean handlePardon6Command(CommandSender sender, String[] args) {
        if (args.length < 1) {
            sender.sendMessage(getLang("commands.pardon6.usage"));
            sender.sendMessage(getLang("commands.pardon6.example1"));
            sender.sendMessage(getLang("commands.pardon6.example2"));
            sender.sendMessage("Example: /pardon6 <uuid>");
            return false;
        }

        String target = args[0];
        if (pardonIPv6(target)) {
            sender.sendMessage(getLang("commands.pardon6.success_pardon", target));
            return true;
        } else {
            sender.sendMessage(getLang("commands.pardon6.failed_pardon", target));
            return false;
        }
    }
    
    private boolean pardonIPv6(String target) {
        try {
            // Try to parse as UUID first
            try {
                UUID banId = UUID.fromString(target);
                return pardonByUUID(banId);
            } catch (IllegalArgumentException e) {
                // Not a UUID, try as IPv6 address or range
                return pardonByIPv6(target);
            }
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean pardonByUUID(UUID banId) {
        for (BanEntry ban : bannedIPv6Ranges) {
            if (ban.id.equals(banId)) {
                bannedIPv6Ranges.remove(ban);
                
                // Remove from prefix length bucket
                int prefixLength = Integer.parseInt(ban.prefix.split("/")[1]);
                List<BanEntry> bans = bansByPrefixLength.get(prefixLength);
                if (bans != null) {
                    bans.remove(ban);
                    if (bans.isEmpty()) {
                        bansByPrefixLength.remove(prefixLength);
                    }
                }
                
                saveBans();
                return true;
            }
        }
        return false;
    }
    
    private boolean pardonByIPv6(String target) {
        try {
            String normalizedPrefix;
            InetAddress inetAddress;
            int prefixLength;
            
            if (target.contains("/")) {
                // This is a CIDR range
                String[] parts = target.split("/");
                inetAddress = InetAddress.getByName(parts[0]);
                prefixLength = Integer.parseInt(parts[1]);
            } else {
                // This is a single IPv6 address
                inetAddress = InetAddress.getByName(target);
                prefixLength = 128;
            }
            
            // Check if it's a forbidden IPv6 address
            if (inetAddress instanceof Inet6Address inet6 && isForbiddenIPv6(inet6)) {
                // Skip forbidden IPv6 addresses to prevent configuration pollution
                return false;
            }
            
            normalizedPrefix = normalizeIPv6Prefix(inetAddress, prefixLength);
            
            // Remove from banned list
            for (BanEntry ban : bannedIPv6Ranges) {
                // Parse stored ban prefix to compare in normalized form
                String[] banParts = ban.prefix.split("/");
                InetAddress banAddr = InetAddress.getByName(banParts[0]);
                int banPrefixLength = Integer.parseInt(banParts[1]);
                String banNormalizedPrefix = normalizeIPv6Prefix(banAddr, banPrefixLength);
                
                if (banNormalizedPrefix.equals(normalizedPrefix)) {
                    bannedIPv6Ranges.remove(ban);
                    
                    // Remove from prefix length bucket
                    int banPrefix = Integer.parseInt(banNormalizedPrefix.split("/")[1]);
                    List<BanEntry> bans = bansByPrefixLength.get(banPrefix);
                    if (bans != null) {
                        bans.remove(ban);
                        if (bans.isEmpty()) {
                            bansByPrefixLength.remove(banPrefix);
                        }
                    }
                    
                    saveBans();
                    return true;
                }
            }
        } catch (UnknownHostException | NumberFormatException e) {
            // Invalid IPv6 address or range
        }
        
        return false;
    }

    private boolean banIPv6Address(String address, String reason, CommandSender sender, long expireTime) {
        try {
            InetAddress inetAddress = InetAddress.getByName(address);
            if (inetAddress instanceof Inet6Address inet6) {
                // Check if it's a forbidden IPv6 address
                if (isForbiddenIPv6(inet6)) {
                    sender.sendMessage("§cRefuse to ban special IPv6 address.");
                    return false;
                }
                
                // Add as /128 range
                String normalizedPrefix = normalizeIPv6Prefix(inetAddress, 128);
                
                // Check if already banned
                for (BanEntry ban : bannedIPv6Ranges) {
                    if (ban.prefix.equals(normalizedPrefix)) {
                        return false; // Already banned
                    }
                }
                
                addBanEntry(normalizedPrefix, reason, expireTime);
                saveBans();
                
                // Kick online players with this exact address
                for (Player player : getServer().getOnlinePlayers()) {
                    if (player.getAddress() != null && player.getAddress().getAddress().equals(inetAddress)) {
                        player.kickPlayer(getLang("messages.kick_message", reason));
                    }
                }
                
                return true;
            }
        } catch (UnknownHostException e) {
            return false;
        }
        return false;
    }

    private boolean banIPv6Range(String cidrRange, String reason, boolean force, CommandSender sender, long expireTime) {
        try {
            String[] parts = cidrRange.split("/");
            if (parts.length != 2) {
                return false;
            }

            InetAddress inetAddress = InetAddress.getByName(parts[0]);
            if (!(inetAddress instanceof Inet6Address inet6)) {
                return false;
            }

            // Check if it's a forbidden IPv6 address
            if (isForbiddenIPv6(inet6)) {
                sender.sendMessage("§cRefuse to ban special IPv6 prefix.");
                return false;
            }

            int prefixLength = Integer.parseInt(parts[1]);
            if (prefixLength < 0 || prefixLength > 128) {
                return false;
            }

            // Prevent /0 prefix matching
            if (prefixLength == 0) {
                sender.sendMessage("§cRefuse to ban /0 prefix, which would affect all IPv6 addresses.");
                return false;
            }

            // Warn about dangerous prefix lengths
            if (prefixLength < forbidPrefixBelow) {
                sender.sendMessage(getLang("commands.ban6.warning_prefix", prefixLength, getEstimatedHosts(prefixLength)));
                if (!force) {
                    sender.sendMessage(getLang("commands.ban6.require_force"));
                    return false;
                }
            }

            // Normalize prefix (clear host bits)
            String normalizedPrefix = normalizeIPv6Prefix(inetAddress, prefixLength);
            
            // Check if already banned
            for (BanEntry ban : bannedIPv6Ranges) {
                if (ban.prefix.equals(normalizedPrefix)) {
                    return false; // Already banned
                }
            }
            
            addBanEntry(normalizedPrefix, reason, expireTime);
            saveBans();
            
            // Check online players and kick if they match
            for (Player player : getServer().getOnlinePlayers()) {
                if (player.getAddress() != null && player.getAddress().getAddress() instanceof Inet6Address inet6Player) {
                    if (!isForbiddenIPv6(inet6Player) && isIPv6InRange(player.getAddress().getAddress(), normalizedPrefix)) {
                        player.kickPlayer(getLang("messages.kick_message", reason));
                    }
                }
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Normalize IPv6 prefix by clearing host bits - 修复顺序问题
    private String normalizeIPv6Prefix(InetAddress address, int prefixLength) {
        // Handle /0 case specifically
        if (prefixLength == 0) {
            return "::/0";
        }
        
        byte[] addrBytes = address.getAddress();
        byte[] networkBytes = addrBytes.clone();
        
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        
        // 先处理fullBytes那一字节的剩余位
        if (remainingBits > 0) {
            int mask = 0xFF << (8 - remainingBits);
            networkBytes[fullBytes] &= mask;
        }
        
        // 确定从哪个字节开始清零
        int clearFrom = remainingBits == 0 ? fullBytes : fullBytes + 1;
        // 清零后面的字节
        for (int i = clearFrom; i < 16; i++) {
            networkBytes[i] = 0;
        }
        
        try {
            return InetAddress.getByAddress(networkBytes).getHostAddress() + "/" + prefixLength;
        } catch (UnknownHostException e) {
            return address.getHostAddress() + "/" + prefixLength;
        }
    }

    private void addBanEntry(String prefix, String reason, long expireTime) {
        BanEntry banEntry = new BanEntry(prefix, reason, System.currentTimeMillis(), expireTime);
        bannedIPv6Ranges.add(banEntry);
        
        // Add to prefix length bucket
        int prefixLength = Integer.parseInt(prefix.split("/")[1]);
        bansByPrefixLength.computeIfAbsent(prefixLength, k -> new CopyOnWriteArrayList<>()).add(banEntry);
    }

    private boolean isIPv6InRange(InetAddress address, String cidrRange) {
        if (!(address instanceof Inet6Address)) {
            return false;
        }

        try {
            String[] parts = cidrRange.split("/");
            InetAddress networkAddress = InetAddress.getByName(parts[0]);
            int prefixLength = Integer.parseInt(parts[1]);
            
            // Prevent "one-click IPv6 server wipe" by never matching /0
            if (prefixLength == 0) {
                return false;
            }

            byte[] addrBytes = address.getAddress();
            byte[] networkBytes = networkAddress.getAddress();

            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            // Check full bytes
            for (int i = 0; i < fullBytes; i++) {
                if (addrBytes[i] != networkBytes[i]) {
                    return false;
                }
            }

            // Check remaining bits
            if (remainingBits > 0) {
                int mask = 0xFF << (8 - remainingBits);
                if ((addrBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask)) {
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void loadBans() {
        bannedIPv6Ranges.clear();
        bansByPrefixLength.clear();
        
        if (getConfig().contains("bans")) {
            List<String> banStrings = getConfig().getStringList("bans");
            for (String banStr : banStrings) {
                try {
                    String[] parts = banStr.split("\\|");
                    String prefix = null;
                    UUID id = null;
                    String reason = null;
                    long time = 0;
                    long expireTime = 0;
                    boolean isNewFormat = false;
                    boolean hasExpireTime = false;
                    
                    // Parse common fields based on format
                    if (parts.length == 4) {
                        // New format with UUID
                        id = UUID.fromString(parts[0]);
                        prefix = parts[1];
                        reason = parts[2];
                        time = Long.parseLong(parts[3]);
                        isNewFormat = true;
                    } else if (parts.length == 3) {
                        // Old format without UUID, migrate to new format
                        prefix = parts[0];
                        reason = parts[1];
                        time = Long.parseLong(parts[2]);
                    } else if (parts.length == 5) {
                        // Format with UUID and expire time
                        id = UUID.fromString(parts[0]);
                        prefix = parts[1];
                        reason = parts[2];
                        time = Long.parseLong(parts[3]);
                        expireTime = Long.parseLong(parts[4]);
                        isNewFormat = true;
                        hasExpireTime = true;
                        
                        // Check if ban has expired
                        if (expireTime > 0 && System.currentTimeMillis() > expireTime) {
                            continue; // Skip expired bans
                        }
                    }
                    
                    if (prefix == null) {
                        continue;
                    }
                    
                    // Check if this is a forbidden IPv6 address/range
                    String[] prefixParts = prefix.split("/");
                    InetAddress addr = InetAddress.getByName(prefixParts[0]);
                    if (addr instanceof Inet6Address inet6 && isForbiddenIPv6(inet6)) {
                        // Skip forbidden IPv6 addresses to prevent configuration pollution
                        getLogger().warning("Skipping forbidden IPv6 ban entry: " + prefix);
                        continue;
                    }
                    
                    // Create and add ban entry based on format
                    BanEntry banEntry;
                    if (hasExpireTime && isNewFormat) {
                        banEntry = new BanEntry(id, prefix, reason, time, expireTime);
                    } else if (isNewFormat) {
                        banEntry = new BanEntry(id, prefix, reason, time);
                    } else {
                        banEntry = new BanEntry(prefix, reason, time);
                    }
                    
                    bannedIPv6Ranges.add(banEntry);
                    
                    // Add to prefix length bucket
                    int prefixLength = Integer.parseInt(prefix.split("/")[1]);
                    bansByPrefixLength.computeIfAbsent(prefixLength, k -> new CopyOnWriteArrayList<>()).add(banEntry);
                } catch (Exception e) {
                    getLogger().warning("Failed to parse ban entry: " + banStr);
                }
            }
        }
        
        // Clean up empty entries
        bansByPrefixLength.entrySet().removeIf(e -> e.getValue().isEmpty());
    }

    private void saveBans() {
        List<String> banStrings = new ArrayList<>();
        for (BanEntry ban : bannedIPv6Ranges) {
            banStrings.add(ban.id + "|" + ban.prefix + "|" + ban.reason + "|" + ban.time + "|" + ban.expireTime);
        }
        getConfig().set("bans", banStrings);
        saveConfig();
    }

    // Get estimated host description for a prefix length
    private String getEstimatedHosts(int prefixLength) {
        if (prefixLength == 128) {
            return "1 address";
        } else if (prefixLength >= 64) {
            return "1 subnet (/64, typical residential LAN)";
        } else if (prefixLength >= 48) {
            return "ISP customer block (/48)";
        } else if (prefixLength >= 32) {
            return "regional allocation";
        } else {
            return "extremely large (dangerous)";
        }
    }
}

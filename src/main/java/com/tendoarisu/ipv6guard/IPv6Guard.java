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
import java.text.SimpleDateFormat;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class IPv6Guard extends JavaPlugin implements CommandExecutor, Listener, TabCompleter {

    private static class BanEntry {
        final String prefix;
        final String reason;
        final long time;
        final long expireTime; // 0 means permanent ban

        BanEntry(String prefix, String reason, long time) {
            this.prefix = prefix;
            this.reason = reason;
            this.time = time;
            this.expireTime = 0; // Permanent ban by default
        }
        
        BanEntry(String prefix, String reason, long time, long expireTime) {
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
        
        // Ensure complete default configuration is loaded
        saveDefaultConfig();
        
        // Load and save default configuration to ensure all options are present
        getConfig().options().copyDefaults(true);
        saveConfig();
        
        // Load safety configuration
        loadSafetyConfig();
        
        loadBans();
        loadLanguage();
        
        if (validateProxySupport()) {
            this.getServer().getPluginManager().registerEvents(this, this);
            getLogger().info(getLang("plugin.enabled"));
            
            // Schedule a task to check for expired bans every minute
            getServer().getScheduler().runTaskTimer(this, this::checkExpiredBans, 20L * 60, 20L * 60); // 20 ticks = 1 second, so 20*60 = 60 seconds
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
                String arg = args[0].toLowerCase();
                
                // Check if input starts with list or reload, then complete it
                if (arg.startsWith("list")) {
                    completions.add("list");
                }
                if (arg.startsWith("reload")) {
                    completions.add("reload");
                }
                
                // If no partial match and not starting to type an IP, show all options
                if (completions.isEmpty() && !isIPStart(arg)) {
                    completions.add("list");
                    completions.add("reload");
                }
            }
        } else if (command.getName().equalsIgnoreCase("pardon6")) {
            if (args.length == 1) {
                // Only show banned IPs, no UUIDs
                for (BanEntry ban : bannedIPv6Ranges) {
                    completions.add(ban.prefix);
                }
            }
        }
        
        return completions;
    }
    
    // Check if a string looks like it's starting to be an IP (contains colon or slash)
    private boolean isIPStart(String input) {
        return input.contains(":") || input.contains("/") || input.matches(".*[0-9a-fA-F].*:");
    }
    
    // Load safety configuration from config.yml
    private void loadSafetyConfig() {
        FileConfiguration config = getConfig();
        
        // Set default values if not present
        config.addDefault("language", "en");
        config.addDefault("safety.enable-proxy-guard", false);
        config.addDefault("safety.shared-ip-threshold", 10);
        config.addDefault("safety.time-window-seconds", 60);
        config.addDefault("safety.forbid-prefix-below", 32);
        
        // Load values
        enableProxyGuard = config.getBoolean("safety.enable-proxy-guard", false);
        sharedIpThreshold = config.getInt("safety.shared-ip-threshold", 10);
        timeWindowSeconds = config.getInt("safety.time-window-seconds", 60);
        forbidPrefixBelow = config.getInt("safety.forbid-prefix-below", 32);
        
        if (enableProxyGuard) {
            getLogger().info(getLang("plugin.proxy_guard_enabled", sharedIpThreshold, timeWindowSeconds));
        }
    }
    
    // Reload all plugin configurations
    private void reloadPluginConfig() {
        // Reload main configuration
        reloadConfig();
        
        // Reload safety configuration
        loadSafetyConfig();
        
        // Reload language files
        loadLanguage();
        
        // Reload bans from file
        loadBans();
        
        getLogger().info("IPv6Guard configuration reloaded successfully.");
    }

    @Override
    public void onDisable() {
        saveBans();
        // Check if langConfig is initialized before using it
        if (langConfig != null) {
            getLogger().info(getLang("plugin.disabled"));
        } else {
            getLogger().info("IPv6Guard plugin has been disabled.");
        }
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
        
        // Create lang directory if not exists
        File langDir = new File(getDataFolder(), "lang");
        if (!langDir.exists()) {
            langDir.mkdirs();
        }
        
        // Generate all supported language files if they don't exist
        for (String supportedLang : supportedLangs) {
            File supportedLangFile = new File(langDir, supportedLang + ".yml");
            if (!supportedLangFile.exists()) {
                // Save default language file
                saveResource("lang/" + supportedLang + ".yml", false);
            } else {
                // Always update language files with latest defaults when reloading
                try {
                    // Merge with latest defaults
                    InputStream defLangStream = getResource("lang/" + supportedLang + ".yml");
                    if (defLangStream != null) {
                        YamlConfiguration defLangConfig = YamlConfiguration.loadConfiguration(new InputStreamReader(defLangStream));
                        YamlConfiguration existingConfig = YamlConfiguration.loadConfiguration(supportedLangFile);
                        
                        // Set defaults and copy missing keys
                        existingConfig.setDefaults(defLangConfig);
                        existingConfig.options().copyDefaults(true);
                        existingConfig.save(supportedLangFile);
                    }
                } catch (IOException e) {
                    getLogger().severe("Failed to update language file: " + e.getMessage());
                }
            }
        }
        
        // Load current language file
        langFile = new File(langDir, lang + ".yml");
        langConfig = YamlConfiguration.loadConfiguration(langFile);
        
        // Load defaults from jar to ensure all keys are available
        InputStream defLangStream = getResource("lang/" + lang + ".yml");
        if (defLangStream != null) {
            YamlConfiguration defLangConfig = YamlConfiguration.loadConfiguration(new InputStreamReader(defLangStream));
            langConfig.setDefaults(defLangConfig);
            langConfig.options().copyDefaults(true);
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
            // Don't send usage again, Bukkit already sends it from plugin.yml
            sender.sendMessage(getLang("commands.ban6.example1"));
            sender.sendMessage(getLang("commands.ban6.example2"));
            sender.sendMessage(getLang("commands.ban6.example3"));
            sender.sendMessage(getLang("commands.ban6.example4"));
            sender.sendMessage(getLang("commands.ban6.example6"));
            return false;
        }

        // Check for list command
        if (args[0].equalsIgnoreCase("list")) {
            showBanList(sender);
            return true;
        }
        
        // Check for reload command
        if (args[0].equalsIgnoreCase("reload")) {
            // Reload configuration
            reloadPluginConfig();
            sender.sendMessage("§a" + getLang("commands.ban6.success_reload"));
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
            }
        } else {
            // This is a single IPv6 address
            if (banIPv6Address(target, reason, sender, expireTime)) {
                sender.sendMessage(getLang("commands.ban6.success_ban_ip", target, reason));
            }
        }

        // Don't send failed message if we already sent a specific message (like already banned)
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
            // Use multi-language status
            String status = ban.expireTime > 0 ? getLang("commands.ban6.status_temporary") : getLang("commands.ban6.status_permanent");
            
            // Format time using simple format for consistency
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String expireInfo = ban.expireTime > 0 ? 
                " (" + getLang("commands.ban6.expires") + ": " + sdf.format(new java.util.Date(ban.expireTime)) + ")" : "";
            
            String[] parts = ban.prefix.split("/");
            int prefixLength = Integer.parseInt(parts[1]);
            
            sender.sendMessage("§7" + String.format(getLang("commands.ban6.ban_list_item"), count));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_prefix"), ban.prefix));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_length"), prefixLength));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_reason"), ban.reason));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_status"), status, expireInfo));
            sender.sendMessage("   §7" + String.format(getLang("commands.ban6.ban_list_banned_at"), sdf.format(new java.util.Date(ban.time))));
        }
        sender.sendMessage("§6" + String.format(getLang("commands.ban6.ban_list_total"), bannedIPv6Ranges.size()));
    }
    
    private boolean handlePardon6Command(CommandSender sender, String[] args) {
        if (args.length < 1) {
            // Don't send usage again, Bukkit already sends it from plugin.yml
            sender.sendMessage(getLang("commands.pardon6.example1"));
            sender.sendMessage(getLang("commands.pardon6.example2"));
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
            // Only try as IPv6 address or range, no UUID support
            return pardonByIPv6(target);
        } catch (Exception e) {
            return false;
        }
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
        // Basic IPv6 address validation to prevent server lag
        if (address == null || address.isEmpty() || !isValidIPv6Format(address)) {
            return false;
        }
        
        try {
            InetAddress inetAddress = InetAddress.getByName(address);
            if (inetAddress instanceof Inet6Address inet6) {
                // Check if it's a forbidden IPv6 address
                if (isForbiddenIPv6(inet6)) {
                    sender.sendMessage("§c" + getLang("commands.ban6.refuse_special_ip"));
                    return false;
                }
                
                // Add as /128 range
                String normalizedPrefix = normalizeIPv6Prefix(inetAddress, 128);
                
                // Check if already banned
                for (BanEntry ban : bannedIPv6Ranges) {
                    if (ban.prefix.equals(normalizedPrefix)) {
                        sender.sendMessage("§c" + getLang("messages.already_banned", normalizedPrefix));
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
        // Basic CIDR range validation to prevent server lag
        if (cidrRange == null || cidrRange.isEmpty() || !cidrRange.contains("/") || !isValidIPv6Format(cidrRange.split("/")[0])) {
            return false;
        }
        
        try {
            String[] parts = cidrRange.split("/");
            if (parts.length != 2) {
                return false;
            }

            // Validate prefix length before parsing
            try {
                int prefixLength = Integer.parseInt(parts[1]);
                if (prefixLength < 0 || prefixLength > 128) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }

            InetAddress inetAddress = InetAddress.getByName(parts[0]);
            if (!(inetAddress instanceof Inet6Address inet6)) {
                return false;
            }

            // Check if it's a forbidden IPv6 address
            if (isForbiddenIPv6(inet6)) {
                sender.sendMessage("§c" + getLang("commands.ban6.refuse_special_prefix"));
                return false;
            }

            int prefixLength = Integer.parseInt(parts[1]);

            // Prevent /0 prefix matching
            if (prefixLength == 0) {
                sender.sendMessage("§c" + getLang("commands.ban6.refuse_zero_prefix"));
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
                    sender.sendMessage("§c" + getLang("messages.already_banned", normalizedPrefix));
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
    
    // Basic IPv6 format validation to prevent server lag from malformed input
    private boolean isValidIPv6Format(String ip) {
        // Simple regex for IPv6 validation - prevents obviously invalid input
        // This is a basic check to avoid expensive DNS lookups or parsing
        return ip.matches("^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$" + 
                         "|^::1$" + 
                         "|^::" + 
                         "|^([0-9a-fA-F]{1,4}:){1,7}:$" + 
                         "|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$" + 
                         "|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$" + 
                         "|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$" + 
                         "|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$" + 
                         "|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$" + 
                         "|^([0-9a-fA-F]{1,4}:)(:[0-9a-fA-F]{1,4}){1,6}$" + 
                         "|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$" + 
                         "|^fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}$");
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
                    String reason = null;
                    long time = 0;
                    long expireTime = 0;
                    
                    // Parse fields - support multiple formats but ignore UUIDs
                    if (parts.length >= 3) {
                        // Determine if this is a format with UUID (ignore UUID field)
                        int prefixIndex = 0;
                        if (parts[0].matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
                            // Has UUID, skip it
                            prefixIndex = 1;
                        }
                        
                        // Parse core fields
                        prefix = parts[prefixIndex];
                        reason = parts[prefixIndex + 1];
                        time = Long.parseLong(parts[prefixIndex + 2]);
                        
                        // Check for expire time (if present)
                        if (parts.length >= prefixIndex + 4) {
                            expireTime = Long.parseLong(parts[prefixIndex + 3]);
                            // Check if ban has expired
                            if (expireTime > 0 && System.currentTimeMillis() > expireTime) {
                                continue; // Skip expired bans
                            }
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
                    
                    // Create and add ban entry
                    BanEntry banEntry = new BanEntry(prefix, reason, time, expireTime);
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
            // Save without UUID - simplified format
            banStrings.add(ban.prefix + "|" + ban.reason + "|" + ban.time + "|" + ban.expireTime);
        }
        getConfig().set("bans", banStrings);
        saveConfig();
    }

    // Get estimated host description for a prefix length
    private String getEstimatedHosts(int prefixLength) {
        if (prefixLength == 128) {
            return "1";
        }
        
        int bits = 128 - prefixLength;
        
        // Calculate exact number of addresses
        java.math.BigInteger hostCount;
        if (bits <= 63) {
            // For numbers that fit in long, use bit shift
            hostCount = java.math.BigInteger.valueOf(1L << bits);
        } else {
            // For very large numbers, calculate using BigInteger shift
            hostCount = java.math.BigInteger.ONE.shiftLeft(bits);
        }
        
        // Format with commas every three digits
        java.text.DecimalFormat formatter = new java.text.DecimalFormat("#,###");
        return formatter.format(hostCount);
    }
}

# IPv6Guard

IPv6Guard 是一个面向 Minecraft 服务器的 IPv6 访问控制插件，支持 **精确 IPv6 地址封禁** 与 **CIDR 前缀级封禁**，并正确兼容 **BungeeCord / Velocity** IP 转发环境。本插件专注于解决原生 Minecraft 无法可靠管理 IPv6 地址的问题。
> 本插件及其源代码由 LLM（大型语言模型）辅助生成，仅供学习、研究和服务器管理使用。  
> 使用时请务必仔细检查配置和封禁规则，避免误封大量用户或关键网络段。  
> 对生产环境操作请先在测试服务器验证安全性。  

---

# ✨ 特性

- ✅ 支持封禁单个 IPv6 地址（/128）  
- ✅ 支持封禁 IPv6 CIDR 前缀（如 /64、/48）  
- ✅ IPv6 前缀归一化（符合 RFC）  
- ✅ 精确优先匹配（长前缀优先于短前缀）  
- ✅ 在线玩家即时踢出  
- ✅ 并发安全，适用于高并发服务器  
- ✅ 支持 BungeeCord / Velocity（Modern Forwarding）  
- ✅ 多语言支持（EN / ZH）  
- ⚠️ 防误操作机制（危险前缀需使用 `-f`）  
- 🔒 代理防护：可启用共享 IP 检测，防止短时间内大量同 IP 登录  
- ⏱ 可配置时间窗口和共享 IP 阈值  
- 📝 保存封禁记录，支持 UUID / IPv6 地址 / 前缀解除封禁  
- 💾 自动加载/保存封禁列表  

---

# 📦 安装

1. 将 `IPv6Guard.jar` 放入 `plugins/` 目录  
2. 启动服务器生成配置文件  
3. （如使用代理）确认：
   - ✅ BungeeCord：已启用 IP Forwarding  
   - ✅ Velocity：启用 Modern Forwarding 并配置 secret  
4. 重启服务器

---

# 🧩 命令

## 封禁 IPv6 地址或前缀

```
/ban6 <ipv6-address> [reason]
/ban6 <ipv6-prefix>/<length> [reason]
/ban6 <ipv6-prefix>/<length> [reason] -f
```

示例：

```
/ban6 2001:db8::1 测试封禁
/ban6 240e:abcd::/64 滥用行为
/ban6 ::/32 危险操作 -f
```

> ⚠️ 当前缀长度小于配置阈值（默认 /32）时，必须使用 `-f` 强制执行。

## 解除 IPv6 封禁（支持 UUID 或前缀）

```
/pardon6 <uuid>
/pardon6 <ipv6-address>
/pardon6 <ipv6-prefix>/<length>
```

## 查看封禁列表

```
/ban6 list
```

- 列出当前所有 IPv6 封禁条目，包括 UUID、前缀、封禁原因和时间  
- 可用于快速核查封禁状态

## 解释 IPv6 地址对应封禁条目

```
/ban6 explain <ipv6-address>
```

- 显示指定 IPv6 地址是否匹配某条封禁记录  
- 包括匹配的前缀、原因和封禁时间  
- 有助于调试封禁规则和前缀优先级

---

# ⚙️ 配置示例

```yaml
language: en

safety:
  enable-proxy-guard: false
  shared-ip-threshold: 10
  time-window-seconds: 60
  forbid-prefix-below: 32
```

> `enable-proxy-guard`：启用共享 IP 防护  
> `shared-ip-threshold`：时间窗口内允许的同 IP 登录次数  
> `time-window-seconds`：共享 IP 统计时间窗口  
> `forbid-prefix-below`：封禁前缀低于该值需使用 `-f`

---

# 🌐 代理支持说明

IPv6Guard 仅在 IP 转发配置正确时运行：

```
✅ BungeeCord：启用 IP Forwarding
✅ Velocity：启用 Modern Forwarding 并设置 secret
❌ Legacy / 未配置转发：插件将拒绝启动
```

> 这是为了避免误封代理 IP。

---

# ⚠️ 注意事项

- 不建议封禁 `::/0` 或极大前缀  
  ```
  /64 通常代表一个家庭网络
  /48 通常代表一个 ISP 客户
  ```  
- IPv6 封禁影响范围远大于 IPv4，请谨慎操作

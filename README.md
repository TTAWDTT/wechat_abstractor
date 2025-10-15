# WeChat Abstractor

基于 Django 的微信聊天记录提取工具。系统会遍历用户提供的消息文件目录，按照可配置过滤条件（聊天对象、消息类型、时间范围、条数限制等）整理消息内容，并以网页形式展示与预览。

## 功能特性

### 核心功能
- ✅ **真实微信数据库支持**: 完全兼容微信MSG表格式 (StrTalker, IsSender, CreateTime等)
- ✅ **多格式解析**: JSON、CSV、XML、HTML、SQLite/DB、TXT/LOG 等常见聊天备份格式
- ✅ **会话识别**: 自动识别单人会话、群聊(`@chatroom`)、公众号(`gh_`)
- ✅ **智能过滤**: 按聊天对象、消息类型、时间范围、数量筛选
- ✅ **多媒体支持**: 图片、视频、音频、文件、链接、名片、通话等8种类型
- ✅ **会话视图**: 按对象分组,按日期二级分组,展示完整对话流
- ✅ **实时统计**: 高频联系人 Top10、消息类型分布、按天统计、失败文件追踪
- ✅ **多种导出**: TXT文本导出、网页预览、JSON数据导出
- ✅ **可扩展架构**: 服务层设计,轻松添加新解析器

### 消息类型支持
| 类型 | 微信代码 | 显示内容 | 元数据 |
|------|---------|---------|--------|
| 文本 | 1 | 原文 | - |
| 图片 | 3 | 缩略图 | url, name, preview |
| 语音 | 34 | 播放器 | url, duration, transcript |
| 视频 | 43 | 封面+播放 | url, name, duration, preview |
| 文件 | 49/6 | 下载链接 | url, name, size, extension |
| 链接 | 49/5 | 卡片预览 | url, title, description, cover |
| 名片 | 42 | 联系信息 | name, account, phone |
| 通话 | 50 | 状态信息 | status, duration, direction |

## 快速开始

### 环境要求
- Python 3.11+
- pip / venv
- **Windows + 微信客户端** (可选,用于自动密钥发现)

### 依赖说明
- `pycryptodome >= 3.20`: SQLCipher数据库解密(AES-256-CBC)
- `psutil >= 5.9`: Windows进程扫描(自动发现密钥)

### 安装步骤
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate  # 当前项目无需数据库也可跳过
python manage.py runserver
```

浏览器访问 `http://127.0.0.1:8000/`，按页面提示填写消息文件目录并提交。

## 目录结构
```
wechat_abstractor/
├── chat_extractor/              # 核心应用
│   ├── services/               # 聊天记录解析服务
│   ├── templates/chat_extractor
│   └── tests/                  # 单元测试与样例数据
├── wechat_abstractor/          # Django 项目配置
├── manage.py
├── requirements.txt
└── README.md
```

## 运行测试
```powershell
# 运行所有测试
python manage.py test

# 仅测试 SQLCipher 功能
python manage.py test chat_extractor.tests.test_sqlcipher -v 2

# 仅测试提取服务
python manage.py test chat_extractor.tests.test_extraction_service -v 2
```

## SQLCipher 加密支持 🔐

### 加密数据库自动解密
真实的微信数据库(如 `MSG0.db`, `MicroMsg.db`, `Media.db`)通常使用 **SQLCipher** 加密。本系统支持三种解密方式:

#### 1️⃣ 自动密钥发现 (推荐 - Windows)
```powershell
# 确保微信客户端正在运行
# 系统会自动扫描 WeChat.exe / WeChatWin.dll 内存
# 在上传页面点击自动发现的密钥芯片即可使用
```

**工作原理:**
- 扫描 `WeChat.exe` 进程加载的 `WeChatWin.dll` 模块
- 搜索设备标识符(android/iphone/ipad/OHOS)及其前后特定偏移位置
- 提取 32 字节密钥并验证能否解密 `Media.db`
- 验证通过后在页面展示可点击的密钥芯片

**系统要求:**
- ✅ Windows 操作系统
- ✅ 微信客户端正在运行
- ✅ 已安装 `psutil` 依赖

#### 2️⃣ 手动输入密钥
```powershell
# 从其他工具(如 wechatDataBackup)获取 64 位十六进制密钥
# 示例: a1b2c3d4e5f67890...  (64字符)
```
在上传表单的 **"SQLCipher 密钥"** 字段粘贴密钥即可。

#### 3️⃣ 明文数据库
如果数据库未加密,系统自动识别并直接解析(无需提供密钥)。

### 错误诊断

| 错误信息 | 原因 | 解决方案 |
|---------|------|---------|
| `SQLCipher database but no decryption key provided` | 加密数据库但未提供密钥 | 启动微信客户端或手动输入密钥 |
| `file is not a database` | 密钥错误或文件损坏 | 检查密钥格式(64位十六进制)或重新导出数据库 |
| `Missing pycryptodome dependency` | 未安装加密库 | `pip install pycryptodome>=3.20` |
| `Cannot detect keys on non-Windows` | 非Windows平台 | 使用手动输入密钥方式 |

### 技术细节
- **加密算法**: PBKDF2-HMAC-SHA1 (64000 iterations) + AES-256-CBC
- **密钥格式**: 64 位十六进制字符串 (32 字节)
- **验证机制**: 每个数据页包含 HMAC-SHA1 校验,确保密钥正确性
- **缓存策略**: 解密后的数据库缓存至 `%TEMP%\wechat_abstractor\decrypted_db\` (基于 SHA1 命名)

### 性能优化建议
```python
# 大型数据库(>100MB)首次解密耗时 5-30 秒
# 后续访问直接读取缓存,几乎无延迟

# 批量处理时建议:
# 1. 确保同一批文件使用相同密钥
# 2. 预热缓存:先解密 Media.db (较小)验证密钥
# 3. 使用 include_subdirectories=False 限制扫描范围
```

## 数据库格式支持

### 微信真实数据库 (MSG表)
系统自动识别并支持以下字段:
```sql
CREATE TABLE MSG (
    localId INTEGER PRIMARY KEY,
    MsgSvrID INTEGER,
    Type INTEGER,              -- 消息类型代码
    SubType INTEGER,           -- 子类型
    IsSender INTEGER,          -- 0=接收 1=发送
    CreateTime INTEGER,        -- Unix时间戳
    StrTalker TEXT,           -- 会话对象(微信ID或群ID)
    StrContent TEXT,          -- 消息内容
    CompressContent BLOB,     -- 压缩内容
    BytesExtra BLOB           -- 额外数据(XML)
)
```

### 标准格式 (兼容模式)
也支持通用命名:
- `talker` / `Talker` / `StrTalker`
- `sender` / `Sender`
- `createTime` / `CreateTime` / `timestamp`
- `isSend` / `IsSend` / `is_send`

## 测试说明

```powershell
# 运行所有测试
python manage.py test

# 运行特定测试
python manage.py test chat_extractor.tests.test_extraction_service

# 详细输出
python manage.py test -v 2
```

测试数据位于 `chat_extractor/tests/data/`:
- `sample.json`: JSON格式示例
- `sample.txt`: 文本格式示例  
- `wechat_msg.db`: 微信数据库格式示例

## 使用技巧

### 1. 处理大文件
```python
# 设置合理的limit避免内存溢出
limit=1000

# 只扫描指定目录
include_subdirectories=False

# 使用类型和联系人过滤
message_types=["text"]
contacts=["特定联系人"]
```

### 2. 群聊识别
系统自动识别 `xxxxx@chatroom` 格式的群ID,可在元数据中查看:
```python
if message.metadata.get("is_chatroom") == "true":
    print(f"这是群聊消息: {message.conversation}")
```

### 3. 多媒体访问
```python
for message in results:
    meta = message.display_meta
    if meta.get("kind") == "image":
        print(f"图片URL: {meta['url']}")
        print(f"文件名: {meta['name']}")
```

## 性能与安全

- ✅ 流式解析,内存友好
- ✅ 只读数据库连接
- ✅ HTML内容自动转义
- ✅ SQL注入防护
- ✅ 文件路径验证

## 下一步规划

### 高优先级
- [ ] 联系人名称映射 (微信ID → 昵称/备注)
- [ ] 群聊成员列表解析
- [ ] CSV/Excel报表导出

### 中优先级
- [ ] 消息全文搜索
- [ ] 时间线可视化
- [ ] 表情包资源管理

查看完整功能说明: [FEATURES.md](FEATURES.md)

欢迎提交 Issue 或 PR，一起完善项目!

# 微信聊天记录提取工具 - 完整功能说明

## 最新更新 (2025-10-15)

### ✅ 完成的核心功能

#### 1. 真实微信数据库格式支持

完全兼容 `wechatDataBackup` 项目的数据库格式:

- **MSG 表支持**: 支持微信真实数据库的 `MSG` 表结构
- **字段映射**: 
  - `StrTalker` → 会话对象 (talker/conversation)
  - `IsSender` → 消息方向 (0=接收, 1=发送)
  - `CreateTime` → 时间戳 (Unix timestamp)
  - `Type`/`SubType` → 消息类型
  - `StrContent` → 消息内容
  - `BytesExtra` → 额外数据 (XML格式)
  - `CompressContent` → 压缩内容

- **兼容模式**: 自动检测并适配多种字段命名格式
  - 标准格式: `talker`, `sender`, `createTime`
  - 微信格式: `StrTalker`, `IsSender`, `CreateTime`
  - 大小写变体: 自动识别

#### 2. 会话对象识别与提取

**会话类型识别**:
- ✅ 单人会话: `wxid_xxxxx`
- ✅ 群聊会话: `xxxxx@chatroom`
- ✅ 公众号: `gh_xxxxx`
- ✅ 系统消息: 特殊标识

**会话信息提取**:
```python
message.talker       # 会话对象ID (微信ID或群ID)
message.sender       # 消息发送人
message.conversation # 会话显示名称
message.direction    # incoming/outgoing/unknown
```

**群聊支持**:
- 自动识别 `@chatroom` 后缀
- 元数据中标记 `is_chatroom: true`
- 支持群成员发言人识别

#### 3. 多媒体消息完整支持

**8种消息类型**:
1. **文本** (type=1): 纯文本消息
2. **图片** (type=3): 图片URL、预览图、文件名
3. **语音** (type=34): 音频文件、时长、转写文本
4. **视频** (type=43): 视频URL、时长、预览图
5. **文件** (type=6/subType=6): 文件名、大小、扩展名
6. **链接** (type=49/subType=5): URL、标题、描述、封面
7. **名片** (type=42): 姓名、微信号、电话
8. **通话** (type=50): 状态、时长、方向

**元数据结构** (`display_meta`):
```json
{
  "kind": "image",
  "url": "https://...",
  "name": "photo.jpg",
  "preview": "https://..."
}
```

#### 4. 消息类型归一化

**类型代码映射** (参考微信协议):
```python
1  → text        # 文本消息
3  → image       # 图片
34 → voice       # 语音
37 → friend_request  # 好友请求
42 → contact_card    # 名片
43 → video       # 视频
47 → sticker     # 表情
48 → location    # 位置
49 → app/link/file   # 应用类消息(根据subType细分)
50 → call        # 通话
10000 → system   # 系统消息
10002 → recall   # 撤回消息
```

**子类型识别** (type=49时):
```python
3  → link      # 网页链接
4  → music     # 音乐
5  → link      # 卡片链接
6  → file      # 文件
8  → product   # 商品
33 → applet    # 小程序
```

#### 5. 前端多媒体渲染

**JavaScript函数 `renderMediaContent()`**:
- 图片: 缩略图展示,点击查看原图
- 视频: 播放按钮 + 时长显示
- 音频: HTML5播放器 + 转写文本
- 文件: 下载按钮 + 文件信息
- 链接: 卡片预览 + 封面图
- 名片: 结构化显示联系信息
- 通话: 状态 + 时长 + 方向

#### 6. 会话统计与分析

**统计指标**:
- 总消息数 / 匹配消息数
- 扫描文件数 / 成功解析数
- 时间范围 (最早 → 最晚)
- 高频联系人 Top 10
- 消息类型分布
- 按天消息统计

**会话分组**:
- 按会话对象自动分组
- 按时间排序 (最新在前)
- 每个会话限制显示数量
- 支持按日期二级分组

#### 7. 数据解析器

**支持格式**:
- ✅ **SQLite/DB** (.db, .sqlite, .msg)
  - 真实微信MSG表
  - 标准聊天数据库
  - 自适应字段映射
  
- ✅ **JSON** (.json)
  - 标准JSON数组
  - 包装对象 `{messages: [...]}`
  
- ✅ **XML** (.xml)
  - 微信消息导出格式
  - 支持嵌套标签
  
- ✅ **HTML** (.html, .htm)
  - 网页备份格式
  - 自动提取文本
  
- ✅ **CSV** (.csv)
  - 表格数据
  - 自动列名映射
  
- ✅ **TXT/LOG** (.txt, .log)
  - 纯文本日志
  - 格式: `时间 - 对象 (发送人): 内容`

### 📊 数据流程

```
原始数据文件
    ↓
解析器识别 (Parser.can_parse)
    ↓
字段提取 (Parser.parse)
    ↓
消息对象构建 (Message.__post_init__)
    ├── 规范化 talker/sender
    ├── 识别 conversation
    ├── 推断 direction
    ├── 归一化 message_type
    └── 构建 display_meta
    ↓
过滤与统计 (ExtractionService)
    ├── 联系人过滤
    ├── 类型过滤
    ├── 时间范围过滤
    └── 统计聚合
    ↓
会话分组 (grouped_threads)
    ├── 按 conversation 分组
    ├── 按时间排序
    └── 按日期二级分组
    ↓
前端展示
    ├── 表格视图 (所有消息)
    └── 会话视图 (分组对话)
```

### 🔧 关键配置

**支持的文件扩展名**:
```python
SUPPORTED_EXTENSIONS = {
    ".json", ".txt", ".log", ".csv", 
    ".db", ".sqlite", ".msg",
    ".xml", ".html", ".htm"
}
```

**数据库表候选名**:
```python
TABLE_CANDIDATES = ("MSG", "message", "Message", "ChatMsg")
```

**时区设置**:
```python
DEFAULT_TIMEZONE = timezone.utc
```

### 📝 使用示例

#### 1. 基本使用

```python
from chat_extractor.services import ExtractionService
from chat_extractor.forms import ParsedFilters
from pathlib import Path

service = ExtractionService()
filters = ParsedFilters(
    base_dir=Path("./data"),
    contacts=["Zhang San"],  # 筛选特定联系人
    limit=100,
    start_time=None,
    end_time=None,
    message_types=["text", "image"],  # 只看文本和图片
    include_subdirectories=True
)

result = service.extract(filters)
print(f"找到 {result.stats.total_messages} 条消息")
for thread in result.grouped_threads:
    print(f"{thread.name}: {thread.count} 条消息")
```

#### 2. 访问多媒体元数据

```python
for message in result.messages:
    if message.message_type == "image":
        meta = message.display_meta
        print(f"图片: {meta.get('name')}")
        print(f"URL: {meta.get('url')}")
        print(f"预览: {meta.get('preview')}")
```

#### 3. 导出数据

```python
# Web界面: 点击"导出为 TXT"按钮
# 或使用 views.export_text()
```

### 🧪 测试覆盖

**已通过的测试**:
- ✅ 基本消息提取
- ✅ 联系人过滤
- ✅ 时间范围过滤
- ✅ 高频联系人排序
- ✅ 图片消息元数据
- ✅ 微信数据库格式解析
- ✅ 会话对象提取
- ✅ TXT导出功能

**测试数据**:
- `sample.json`: JSON格式样例
- `sample.txt`: 文本格式样例
- `wechat_msg.db`: 微信数据库格式样例

### 🚀 性能优化

**已实现**:
- 流式解析 (Iterator pattern)
- 只读数据库连接 (`mode=ro`)
- 懒加载元数据构建
- 限制返回条数 (limit)
- 会话分组缓存

**建议**:
- 大文件建议设置 `limit` 限制
- 使用 `include_subdirectories=False` 减少扫描
- 指定 `contacts` 和 `message_types` 过滤

### 🔐 安全性

**已实现**:
- HTML内容转义 (`escapeHtml()`)
- SQL注入防护 (参数化查询)
- 文件路径验证
- 只读数据库访问

### 📦 依赖项

```txt
Django>=5.0
```

无需额外依赖!所有解析都使用Python标准库。

### 🎯 下一步规划

#### 高优先级
- [ ] 联系人名称映射 (微信ID → 昵称/备注)
- [ ] 群聊成员列表解析
- [ ] 消息撤回追踪
- [ ] @ 提及识别

#### 中优先级
- [ ] CSV/Excel导出
- [ ] 消息搜索功能
- [ ] 时间线可视化
- [ ] 表情包下载

#### 低优先级
- [ ] 消息加密解密
- [ ] 图片/视频下载
- [ ] 导出HTML格式
- [ ] 多语言支持

### 🐛 已知问题

1. **群聊显示**: 当前显示群ID(`xxxxx@chatroom`),需要映射表才能显示群名称
2. **联系人名称**: 显示微信ID,需要Contact表关联才能显示昵称/备注
3. **文件路径**: 媒体文件的本地路径可能无效(需要真实文件系统)

### 💡 技术亮点

1. **适配层设计**: 统一的Parser接口,轻松扩展新格式
2. **消息归一化**: 复杂的type/subType映射为简单的8种类型
3. **元数据结构化**: display_meta提供前端友好的JSON结构
4. **字段自适应**: 支持多种命名约定(talker/Talker/StrTalker)
5. **群聊识别**: 自动检测`@chatroom`后缀
6. **方向推断**: 智能从多种字段推断消息方向
7. **HTML安全**: 所有用户输入都经过转义
8. **测试驱动**: 完整的单元测试覆盖

### 📞 技术支持

如有问题,请提交 Issue 或参考:
- 源代码: `chat_extractor/services/extractor.py`
- 测试用例: `chat_extractor/tests/test_extraction_service.py`
- 前端模板: `chat_extractor/templates/chat_extractor/index.html`

---

**版本**: 1.0.0  
**最后更新**: 2025-10-15  
**作者**: WeChat Abstractor Team

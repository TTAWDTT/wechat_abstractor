# WeChat Abstractor

基于 Django 的微信聊天记录提取工具。系统会遍历用户提供的消息文件目录，按照可配置过滤条件（聊天对象、消息类型、时间范围、条数限制等）整理消息内容，并以网页形式展示与预览。

## 功能特性
- 支持 JSON、CSV、SQLite/DB、TXT/LOG 等常见聊天备份格式
- 可按聊天对象、消息类型、时间范围、数量筛选
- 会话视图聚合展示人与人之间的往来细节
- 实时统计（高频联系人、消息类型、按天计数、失败文件）
- 支持 TXT 文本导出、预览前 50 条消息
- 提供可复用的服务层，便于扩展其它解析器

## 快速开始

### 环境要求
- Python 3.11+
- pip / venv

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
python manage.py test
```

## 下一步规划
- [ ] 增加对真实 WeChat MSG 数据库的字段自适应映射
- [ ] 支持导出 CSV/Excel 报表
- [ ] 增强前端交互与可视化过滤

欢迎提交 Issue 或 PR，一起完善项目

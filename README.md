# **CGI.JS**
一个让你不仅能在本地直接运行，而且能通过 FCGI 接口作为服务器后端的项目。

[![Stars](https://img.shields.io/github/stars/Ah-Yuanah/CGI.JS)](https://github.com/Ah-Yuanah/CGI.JS)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows-blue)

> ⭐ 喜欢这个项目欢迎 Star & Watch，感谢支持！

### **简介**
CGI.JS(CJS)将 FastCGI 与 QuickJS-NG 结合，提供现代化的 JS 执行环境。

### **核心特性**
- 支持 `.cjs` 脚本直接执行
- 支持作为后端接收网络请求处理
- 支持模块化环境
- 支持 JS/C 扩展

### **快速上手**
##### **环境要求**
- 操作系统：Windows 7 及以上版本
- 开发工具：Visual Studio 2022+ 或支持 C/C++ 最新标准与 MSVC 扩展的编译器

##### **安装使用**
1. 使用 Visual Studio 打开 `.sln` 文件
2. 编译生成可执行文件
3. 直接运行 `.cjs` 脚本或作为 FCGI 后端启动

```bash
cjs.exe script.cjs
```

##### **相关文档**
- [CAPI 头文件](./include/cjsapi.h)

##### **贡献指南**
我们欢迎各种形式的贡献，包括但不限于：
- 提交 bug 报告与修复方案
- 提出新功能建议
- 提交代码 PR
- 完善项目文档/代码等

### **许可证**
本项目采用 MIT 许可证开源，详情参见 [LICENSE](./LICENSE) 文件。

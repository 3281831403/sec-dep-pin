依赖锁定文件被改了一行，构建出来的镜像里多装了一个同名包：解析只读名称与版本，来源与哈希丢失；名称规范化只转小写，下划线与连字符被当成不同包；来源校验用前缀比较，镜像站前缀被放行；哈希校验只比对第一个算法，其余被忽略；哈希比较用普通等号；求解只取第一个匹配版本，冲突不报错；差异比对只报缺失，多出的包被忽略；差异比对不区分被改与被删；策略校验不检查是否校验哈希；批量校验复用求解结果，后一个清单命中前一个清单的依赖。deps/lock.py 是核心，tests/test_lock.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

    pytest tests -q

当前基线必须是 15 failed 且 0 error，失败原因全部为 NotImplementedError；修复 10 个缺陷后应为 15 passed。查看测试收集结果：

    pytest tests --collect-only -q

只需 pytest，不需要安装本项目，conftest 已处理 src 路径。全程离线、确定性、无随机。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 目录与 src 布局

    sec-dep-pin/
      README.md
      pyproject.toml
      tests/conftest.py
      src/deps/__init__.py
      src/deps/lock.py
      tests/test_lock.py

这是 src 布局：包位于 src/deps，测试通过 tests/conftest.py 把 src 加入 sys.path 后导入 deps.lock，不需要构建或安装。

## 约束与当前状态

- tests/test_lock.py 不可修改，测试就是验收契约。
- 只允许修改 src/deps/lock.py，并保留恰好 8 个桩函数。
- 只用标准库 hashlib、re、json、urllib.parse 与 pytest；离线、无随机。
- 8 个函数当前全部 raise NotImplementedError，docstring 写明哈希覆盖、版本精确、容差 0。
- 15 个测试当前全红：前 10 个分别对应 10 个缺陷，后 5 个覆盖合规清单、多出包、哈希不符、来源不符、批量独立。
- 修复顺序：按题面列出的 1 到 10 逐个修，不要改测试或跳过测试。
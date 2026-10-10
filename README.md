# nuxt-authz

> 声明式角色权限引擎

## 核心价值

游客/用户/管理员三类角色，按表粒度控制读写权限，支持强制字段注入与字段剥离，遵循 fail-closed 安全原则。

## 安装

```bash
npm install nuxt-authz
```

## 快速示例

```js
import { createAuthz } from 'nuxt-authz'

const authz = createAuthz({
  publicRead: ['site_settings', 'categories'],
  publishedOnly: { articles: 'articles' },
  owned: { profiles: 'owner_id' },
  publicInsert: ['messages'],
  authedInsert: ['comments', 'articles'],
  adminOnly: ['analytics_events'],
})

// 读权限
const scope = authz.readScope('articles', currentUser)
if (!scope.allowed) throw new Error(scope.error)
// scope.where  → SQL 片段数组
// scope.params → 绑定值

// 写权限
const w = authz.writeScope('articles', 'insert', currentUser)
if (!w.allowed) throw new Error(w.error)
// w.forced → 服务端强制注入的字段 { author_id: 123, status: 'pending' }
// w.strip  → 需要从 payload 中剥离的字段 ['id']
```

## API

### `createAuthz(opts)`

返回权限引擎实例 `{ isAdminUser, readScope, writeScope, ownerWhere }`。

| 方法 | 说明 |
| --- | --- |
| `isAdminUser(user)` | 判断是否管理员 |
| `readScope(table, user)` | 计算读权限，返回 `allowed/where/params/error` |
| `writeScope(table, action, user)` | 计算写权限，返回 `allowed/forced/strip/error` |
| `ownerWhere(table, userId)` | 生成 owner 过滤条件 |

## 安全原则

- **fail-closed**：未知表默认拒绝，避免遗漏配置导致的越权
- **强制字段服务端注入**：`forced` 字段由服务端写入，防止客户端篡改越权
- **非管理员限制**：不能自行发布、置顶或篡改计数类字段

## License

MIT

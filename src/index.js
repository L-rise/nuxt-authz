/**
 * nuxt-authz — 声明式角色权限引擎
 * --------------------------------------------------------------------------
 * 三个角色：游客（未登录）、用户（登录）、管理员（role=admin）
 * 按表粒度控制读写权限，支持强制字段注入（如 owner_id）和字段剥离（如 password_hash），
 * fail-closed 安全原则：未知表默认拒绝。
 *
 * 用法：
 *   import { createAuthz } from 'nuxt-authz'
 *   const authz = createAuthz({
 *     publicRead: ['site_settings', 'categories'],
 *     publishedOnly: { articles: 'articles' },
 *     owned: { profiles: 'owner_id' },
 *     publicInsert: ['messages'],
 *     authedInsert: ['comments', 'articles'],
 *     adminOnly: ['analytics_events'],
 *   })
 *
 *   // 读权限
 *   const scope = authz.readScope('articles', user)
 *   if (!scope.allowed) return reject(scope.error)
 *
 *   // 写权限
 *   const w = authz.writeScope('articles', 'insert', user)
 *   if (!w.allowed) return reject(w.error)
 *   // w.forced → 服务端强制注入的字段
 *   // w.strip  → 需要从 payload 中剥离的字段
 */

/**
 * 创建权限引擎实例
 * @param {Object} opts 规则配置
 * @param {string[]} opts.adminOnly - 仅管理员可访问的表
 * @param {string[]} opts.publicRead - 公开可读的表
 * @param {Object} opts.publishedOnly - 有发布状态的表（{ tableName: 'statusColumn' }）
 * @param {string[]} opts.publicInsert - 匿名可写入的表
 * @param {string[]} opts.authedInsert - 登录后可写入的表
 * @param {Object} opts.owned - 带 owner_id 归属的表（{ tableName: 'ownerColumn' }）
 */
export function createAuthz(opts) {
  opts = opts || {}

  const ADMIN_ONLY = opts.adminOnly || []
  const PUBLIC_READ = opts.publicRead || []
  const PUBLISHED_ONLY = opts.publishedOnly || {}
  const PUBLIC_INSERT = opts.publicInsert || []
  const AUTHED_INSERT = opts.authedInsert || []
  const OWNED = opts.owned || {}

  const isAdmin = (user) => !!(user && user.role === 'admin')
  const uid = (user) => (user && user.id != null ? user.id : null)

  /**
   * 判断用户是否为管理员
   */
  function isAdminUser(user) {
    return isAdmin(user)
  }

  /**
   * 读权限：返回额外的强制过滤条件（SQL 片段 + 绑定值）
   * @returns {{ allowed: boolean, where?: string[], params?: any[], error?: string }}
   */
  function readScope(table, user) {
    if (isAdmin(user)) return { allowed: true, where: [], params: [] }

    if (PUBLIC_READ.includes(table)) return { allowed: true, where: [], params: [] }

    if (PUBLISHED_ONLY[table]) {
      const me = uid(user)
      if (me != null) {
        return {
          allowed: true,
          where: ['(t."status" = ? OR t."author_id" = ? OR t."owner_id" = ?)'],
          params: ['published', me, me]
        }
      }
      return { allowed: true, where: ['t."status" = ?'], params: ['published'] }
    }

    if (OWNED[table]) {
      const me = uid(user)
      if (me == null) return { allowed: false, error: '需要登录' }
      return { allowed: true, where: [`t."${OWNED[table]}" = ?`], params: [me] }
    }

    if (ADMIN_ONLY.includes(table)) return { allowed: false, error: '需要管理员权限' }

    /* 未知表：fail-closed */
    return { allowed: false, error: '无权限读取该数据表' }
  }

  /**
   * 写权限：返回需要强制注入/剥离的字段
   * @returns {{ allowed: boolean, forced?: object, strip?: string[], error?: string }}
   */
  function writeScope(table, action, user) {
    const admin = isAdmin(user)
    const me = uid(user)

    if (action === 'upsert' && !admin) {
      return { allowed: false, error: '需要管理员权限' }
    }

    if (action === 'insert' || action === 'upsert') {
      if (admin) return { allowed: true }
      if (PUBLIC_INSERT.includes(table)) return { allowed: true, strip: ['id'] }
      if (AUTHED_INSERT.includes(table)) {
        if (me == null) return { allowed: false, error: '需要登录后才能提交' }
        const forced = {}
        if (OWNED[table]) forced[OWNED[table]] = me
        if (table === 'articles') {
          forced.author_id = me
          forced.status = 'pending'
        }
        return { allowed: true, forced, strip: ['id'] }
      }
      return { allowed: false, error: '需要管理员权限' }
    }

    if (action === 'update' || action === 'delete') {
      if (admin) return { allowed: true }
      if (me == null) return { allowed: false, error: '需要登录' }
      if (AUTHED_INSERT.includes(table) || OWNED[table]) {
        return { allowed: true, strip: ['id'] }
      }
      return { allowed: false, error: '需要管理员权限' }
    }

    return { allowed: false, error: '不支持的操作' }
  }

  /**
   * 非管理员的细分归属校验：update/delete 必须带上「只影响自己那行」的条件。
   * 返回要追加到 WHERE 的片段（不返回就拒绝）。
   */
  function ownerWhere(table, user) {
    if (isAdmin(user)) return null
    const me = uid(user)
    if (me == null) return null
    if (OWNED[table]) return { where: `t."${OWNED[table]}" = ?`, params: [me] }
    if (table === 'articles') return { where: 't."author_id" = ?', params: [me] }
    return null
  }

  return { isAdminUser, readScope, writeScope, ownerWhere }
}

export default { createAuthz }

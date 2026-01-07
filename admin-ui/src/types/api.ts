// 凭据状态响应
export interface CredentialsStatusResponse {
  total: number
  available: number
  currentId: number
  credentials: CredentialStatusItem[]
}

// 单个凭据状态
export interface CredentialStatusItem {
  id: number
  priority: number
  disabled: boolean
  failureCount: number
  isCurrent: boolean
  expiresAt: string | null
  authMethod: string | null
  hasProfileArn: boolean

  // ===== 统计（可持久化） =====
  callsTotal: number
  callsOk: number
  callsErr: number
  inputTokensTotal: number
  outputTokensTotal: number
  lastCallAt: string | null
  lastSuccessAt: string | null
  lastErrorAt: string | null
  lastError: string | null
}

// 余额响应
export interface BalanceResponse {
  id: number
  subscriptionTitle: string | null
  currentUsage: number
  usageLimit: number
  remaining: number
  usagePercentage: number
  nextResetAt: number | null
}

// 成功响应
export interface SuccessResponse {
  success: boolean
  message: string
}

// ===== 统计（可持久化） =====

export interface StatsBucket {
  // 按日：YYYY-MM-DD；按模型：model id
  key: string
  callsTotal: number
  callsOk: number
  callsErr: number
  inputTokensTotal: number
  outputTokensTotal: number
  lastCallAt: string | null
  lastSuccessAt: string | null
  lastErrorAt: string | null
  lastError: string | null
}

export interface CredentialStatsResponse {
  id: number
  callsTotal: number
  callsOk: number
  callsErr: number
  inputTokensTotal: number
  outputTokensTotal: number
  lastCallAt: string | null
  lastSuccessAt: string | null
  lastErrorAt: string | null
  lastError: string | null
  byDay: StatsBucket[]
  byModel: StatsBucket[]
}

// 错误响应
export interface AdminErrorResponse {
  error: {
    type: string
    message: string
  }
}

// 请求类型
export interface SetDisabledRequest {
  disabled: boolean
}

export interface SetPriorityRequest {
  priority: number
}

// 添加凭据请求
export interface AddCredentialRequest {
  refreshToken: string
  authMethod?: 'social' | 'idc' | 'builder-id'
  clientId?: string
  clientSecret?: string
  priority?: number
}

// 添加凭据响应
export interface AddCredentialResponse {
  success: boolean
  message: string
  credentialId: number
}

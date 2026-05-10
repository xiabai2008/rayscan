import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { login, logout, getCurrentUser, refreshToken } from '@/api/auth'
import { setToken, getToken, removeToken, setRefreshToken, getRefreshToken, removeRefreshToken } from '@/utils/auth'

export const useAuthStore = defineStore('auth', () => {
  // 状态
  const user = ref(null)
  const token = ref(getToken())
  const refresh_token = ref(getRefreshToken())

  // 计算属性
  const isAuthenticated = computed(() => !!token.value)
  const isAdmin = computed(() => user.value?.is_superuser || false)

  // 登录
  const loginUser = async (credentials) => {
    try {
      const response = await login(credentials)
      const { access_token, refresh_token: new_refresh_token } = response.data

      // 保存token
      token.value = access_token
      refresh_token.value = new_refresh_token
      setToken(access_token)
      setRefreshToken(new_refresh_token)

      // 获取用户信息
      await fetchUserInfo()

      return { success: true }
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || '登录失败' }
    }
  }

  // 登出
  const logoutUser = async () => {
    try {
      if (token.value) {
        await logout(token.value)
      }
    } catch (error) {
      console.error('登出失败:', error)
    } finally {
      // 清除本地存储
      user.value = null
      token.value = null
      refresh_token.value = null
      removeToken()
      removeRefreshToken()
    }
  }

  // 获取用户信息
  const fetchUserInfo = async () => {
    try {
      if (!token.value) {
        throw new Error('未找到token')
      }

      const response = await getCurrentUser()
      user.value = response.data
      return { success: true }
    } catch (error) {
      console.error('获取用户信息失败:', error)
      // token可能已过期，尝试刷新
      if (error.response?.status === 401) {
        return await refreshAuthToken()
      }
      return { success: false, error: error.response?.data?.detail || '获取用户信息失败' }
    }
  }

  // 刷新token
  const refreshAuthToken = async () => {
    try {
      if (!refresh_token.value) {
        throw new Error('未找到刷新token')
      }

      const response = await refreshToken(refresh_token.value)
      const { access_token, refresh_token: new_refresh_token } = response.data

      // 保存新token
      token.value = access_token
      refresh_token.value = new_refresh_token
      setToken(access_token)
      setRefreshToken(new_refresh_token)

      // 重新获取用户信息
      await fetchUserInfo()

      return { success: true }
    } catch (error) {
      console.error('刷新token失败:', error)
      // 刷新失败，清除token
      user.value = null
      token.value = null
      refresh_token.value = null
      removeToken()
      removeRefreshToken()
      return { success: false, error: '会话已过期，请重新登录' }
    }
  }

  // 恢复认证状态
  const restoreAuth = async () => {
    if (token.value) {
      // 验证token是否有效
      try {
        await fetchUserInfo()
        return { success: true }
      } catch (error) {
        // token无效，尝试刷新
        return await refreshAuthToken()
      }
    }
    return { success: false }
  }

  // 更新用户信息
  const updateUserInfo = async (userData) => {
    try {
      // 这里应该调用更新用户信息的API
      // 暂时直接更新本地数据
      user.value = { ...user.value, ...userData }
      return { success: true }
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || '更新用户信息失败' }
    }
  }

  // 修改密码
  const changePassword = async (passwordData) => {
    try {
      // 这里应该调用修改密码的API
      return { success: true }
    } catch (error) {
      return { success: false, error: error.response?.data?.detail || '修改密码失败' }
    }
  }

  return {
    // 状态
    user,
    token,
    refresh_token,

    // 计算属性
    isAuthenticated,
    isAdmin,

    // 方法
    loginUser,
    logoutUser,
    fetchUserInfo,
    refreshAuthToken,
    restoreAuth,
    updateUserInfo,
    changePassword
  }
})
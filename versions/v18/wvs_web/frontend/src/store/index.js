import { createStore } from 'vuex'
import auth from './modules/auth'
import scans from './modules/scans'
import vulnerabilities from './modules/vulnerabilities'
import config from './modules/config'
import notifications from './modules/notifications'

const store = createStore({
  modules: {
    auth,
    scans,
    vulnerabilities,
    config,
    notifications
  },
  state: {
    isLoading: false,
    error: null,
    theme: localStorage.getItem('theme') || 'light'
  },
  mutations: {
    SET_LOADING(state, isLoading) {
      state.isLoading = isLoading
    },
    SET_ERROR(state, error) {
      state.error = error
    },
    CLEAR_ERROR(state) {
      state.error = null
    },
    SET_THEME(state, theme) {
      state.theme = theme
      localStorage.setItem('theme', theme)
      document.documentElement.setAttribute('data-theme', theme)
    }
  },
  actions: {
    setLoading({ commit }, isLoading) {
      commit('SET_LOADING', isLoading)
    },
    setError({ commit }, error) {
      commit('SET_ERROR', error)
    },
    clearError({ commit }) {
      commit('CLEAR_ERROR')
    },
    toggleTheme({ commit, state }) {
      const newTheme = state.theme === 'light' ? 'dark' : 'light'
      commit('SET_THEME', newTheme)
    }
  },
  getters: {
    isLoading: state => state.isLoading,
    error: state => state.error,
    theme: state => state.theme
  }
})

// 初始化主题
store.dispatch('initTheme')

export default store
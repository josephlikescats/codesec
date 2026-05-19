import axios from 'axios'

const localBackendHost = 'http://127.0.0.1:8000'
const isSameOriginBackend = window.location.port === '8000' || window.location.host.startsWith('127.0.0.1:8000')
const baseURL = isSameOriginBackend ? '' : localBackendHost

axios.defaults.baseURL = baseURL
axios.defaults.headers.common['Content-Type'] = 'application/json'

export default axios

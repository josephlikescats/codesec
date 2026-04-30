import { useState, useCallback, useRef } from 'react'
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Alert,
  CircularProgress,
  Divider,
  Tabs,
  Tab,
  Paper,
  IconButton
} from '@mui/material'
import {
  Code as CodeIcon,
  CloudUpload as UploadIcon,
  Download as DownloadIcon,
  Security as SecurityIcon
} from '@mui/icons-material'
import axios from 'axios'
import FileUpload from '../components/FileUpload'

interface Finding {
  id: string
  category: string
  severity: string
  title: string
  description: string
  code_snippet?: string
  line_number: number
  cwe_id: string
}

interface TabPanelProps {
  children?: React.ReactNode
  index: number
  value: number
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  )
}

export default function ScanPage() {
  const [tab, setTab] = useState(0)
  const [code, setCode] = useState('')
  const [language, setLanguage] = useState('python')
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [results, setResults] = useState<Finding[]>([])
  const [error, setError] = useState('')
  const [scanTime, setScanTime] = useState(0)
  const [linesScanned, setLinesScanned] = useState(0)
  const progressRef = useRef<NodeJS.Timeout | null>(null)

  const startProgress = () => {
    setProgress(0)
    progressRef.current = setInterval(() => {
      setProgress(prev => Math.min(prev + 5, 95))
    }, 150)
  }

  const stopProgress = () => {
    if (progressRef.current) {
      clearInterval(progressRef.current)
      progressRef.current = null
    }
    setProgress(100)
    setTimeout(() => setProgress(0), 500)
  }

  const handleScan = async () => {
    if (!code.trim()) {
      setError('Please enter code to scan')
      return
    }

    setLoading(true)
    setError('')
    setResults([])
    startProgress()

    try {
      const response = await axios.post('/api/v1/scan', {
        code,
        language
      })

      setResults(response.data.findings)
      setScanTime(response.data.scan_time_ms)
      setLinesScanned(response.data.lines_scanned)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Scan failed. Please try again.')
    } finally {
      setLoading(false)
      stopProgress()
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error'
      case 'high': return 'warning'
      case 'medium': return 'info'
      case 'low': return 'success'
      default: return 'default'
    }
  }

  const getSeverityCount = (severity: string) => {
    return results.filter(f => f.severity === severity).length
  }

  const exportResults = () => {
    const data = {
      scan_date: new Date().toISOString(),
      language,
      lines_scanned: linesScanned,
      scan_time_ms: scanTime,
      summary: {
        total: results.length,
        critical: getSeverityCount('critical'),
        high: getSeverityCount('high'),
        medium: getSeverityCount('medium'),
        low: getSeverityCount('low')
      },
      findings: results
    }
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `security-scan-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
        <SecurityIcon color="primary" />
        Scan Code
      </Typography>

      {/* Tab Selection */}
      <Paper sx={{ mb: 3 }}>
        <Tabs 
          value={tab} 
          onChange={(_, v) => setTab(v)}
          variant="fullWidth"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab icon={<CodeIcon />} label="Paste Code" iconPosition="start" />
          <Tab icon={<UploadIcon />} label="Upload Files" iconPosition="start" />
        </Tabs>
      </Paper>

      {/* Code Input Tab */}
      <TabPanel value={tab} index={0}>
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>Code Input</Typography>
            
            <FormControl sx={{ minWidth: 200, mb: 2 }}>
              <InputLabel>Language</InputLabel>
              <Select
                value={language}
                label="Language"
                onChange={(e) => setLanguage(e.target.value)}
              >
                <MenuItem value="python">Python</MenuItem>
                <MenuItem value="javascript">JavaScript</MenuItem>
                <MenuItem value="typescript">TypeScript</MenuItem>
                <MenuItem value="java">Java</MenuItem>
                <MenuItem value="go">Go</MenuItem>
                <MenuItem value="rust">Rust</MenuItem>
              </Select>
            </FormControl>

            <TextField
              fullWidth
              multiline
              rows={15}
              placeholder="Paste your code here to scan for vulnerabilities..."
              value={code}
              onChange={(e) => setCode(e.target.value)}
              sx={{ mb: 2 }}
            />

            <Box display="flex" alignItems="center" gap={2}>
              <Button
                variant="contained"
                size="large"
                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : undefined}
                onClick={handleScan}
                disabled={loading || !code.trim()}
                sx={{ 
                  background: 'linear-gradient(90deg, #6366f1 0%, #8b5cf6 100%)',
                  px: 4
                }}
              >
                {loading ? 'Scanning...' : 'Run Security Scan'}
              </Button>

              {loading && progress > 0 && (
                <Box sx={{ flex: 1, maxWidth: 200 }}>
                  <CircularProgress variant="determinate" value={progress} size={36} />
                </Box>
              )}
            </Box>
          </CardContent>
        </Card>
      </TabPanel>

      {/* File Upload Tab */}
      <TabPanel value={tab} index={1}>
        <FileUpload />
      </TabPanel>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Results Display */}
      {results.length > 0 && (
        <Card>
          <CardContent>
            {/* Summary Cards */}
            <Box display="flex" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
              <Typography variant="h6">
                Scan Results ({results.length} findings)
              </Typography>
              <Box display="flex" gap={1}>
                <Chip label={`${scanTime.toFixed(0)}ms`} size="small" color="primary" variant="outlined" />
                <Chip label={`${linesScanned} lines`} size="small" variant="outlined" />
                <IconButton size="small" onClick={exportResults} color="primary">
                  <DownloadIcon />
                </IconButton>
              </Box>
            </Box>

            {/* Severity Summary */}
            <Box display="flex" gap={2} flexWrap="wrap" sx={{ mb: 3 }}>
              <Paper sx={{ p: 2, minWidth: 80, textAlign: 'center', bgcolor: 'error.light' }}>
                <Typography variant="h4" color="error.contrastText">
                  {getSeverityCount('critical')}
                </Typography>
                <Typography variant="caption" color="error.contrastText">Critical</Typography>
              </Paper>
              <Paper sx={{ p: 2, minWidth: 80, textAlign: 'center', bgcolor: 'warning.light' }}>
                <Typography variant="h4" color="warning.contrastText">
                  {getSeverityCount('high')}
                </Typography>
                <Typography variant="caption" color="warning.contrastText">High</Typography>
              </Paper>
              <Paper sx={{ p: 2, minWidth: 80, textAlign: 'center', bgcolor: 'info.light' }}>
                <Typography variant="h4" color="info.contrastText">
                  {getSeverityCount('medium')}
                </Typography>
                <Typography variant="caption" color="info.contrastText">Medium</Typography>
              </Paper>
              <Paper sx={{ p: 2, minWidth: 80, textAlign: 'center', bgcolor: 'success.light' }}>
                <Typography variant="h4" color="success.contrastText">
                  {getSeverityCount('low')}
                </Typography>
                <Typography variant="caption" color="success.contrastText">Low</Typography>
              </Paper>
            </Box>

            <Divider sx={{ mb: 2 }} />

            {/* Findings List */}
            {results.map((finding, index) => (
              <Box 
                key={index}
                sx={{ 
                  p: 2, 
                  mb: 2, 
                  borderRadius: 2,
                  border: '1px solid',
                  borderColor: 'divider',
                  backgroundColor: 'background.paper'
                }}
              >
                <Box display="flex" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
                  <Typography variant="subtitle1" fontWeight={600}>
                    {finding.title}
                  </Typography>
                  <Chip 
                    label={finding.severity} 
                    color={getSeverityColor(finding.severity) as any}
                    size="small"
                  />
                </Box>
                
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {finding.description}
                </Typography>

                {/* Code Snippet Display */}
                {finding.code_snippet && (
                  <Box
                    sx={{
                      p: 1.5,
                      mt: 1,
                      mb: 1,
                      borderRadius: 1,
                      bgcolor: 'grey.900',
                      fontFamily: 'monospace',
                      fontSize: '0.75rem',
                      overflow: 'auto'
                    }}
                  >
                    <Typography 
                      component="pre" 
                      sx={{ 
                        color: 'grey.300', 
                        fontFamily: 'monospace',
                        fontSize: '0.75rem',
                        whiteSpace: 'pre-wrap',
                        m: 0
                      }}
                    >
                      {finding.code_snippet}
                    </Typography>
                  </Box>
                )}
                
                <Box display="flex" gap={2} flexWrap="wrap">
                  <Chip label={`Line ${finding.line_number}`} size="small" variant="outlined" />
                  <Chip label={finding.cwe_id || 'N/A'} size="small" variant="outlined" />
                  <Chip label={finding.category} size="small" variant="outlined" />
                </Box>
              </Box>
            ))}

            {results.length === 0 && !loading && (
              <Alert severity="success">
                No vulnerabilities found! Your code passes all security checks.
              </Alert>
            )}
          </CardContent>
        </Card>
      )}
    </Box>
  )
}
import { useState, useRef } from 'react'
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
  Security as SecurityIcon,
  GitHub as GitHubIcon
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
  confidence?: number
  remediation?: string
  references?: string[]
  source?: string
}

interface RemediationSuggestion {
  id: string
  vulnerability_id: string
  title: string
  description: string
  fixed_code: string
  explanation: string
  confidence: number
}

interface GeneratedTest {
  id: string
  vulnerability_id: string
  name: string
  description: string
  test_code: string
}

interface GitHubScanResult {
  owner: string
  repo: string
  url: string
  language: string
  files_count: number
  total_lines: number
  files_scanned: number
  total_findings: number
  scan_time_ms: number
  languages: Record<string, number>
  sensitive_files: string[]
  findings_by_severity: Record<string, number>
  findings_by_file: Array<{
    path: string
    language: string
    findings_count: number
    findings: Array<{
      id: string
      category: string
      severity: string
      title: string
      line_number?: number
      source?: string
      description?: string
    }>
  }>
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
  const [suggestions, setSuggestions] = useState<RemediationSuggestion[]>([])
  const [generatedTests, setGeneratedTests] = useState<GeneratedTest[]>([])
  const [error, setError] = useState('')
  const [scanTime, setScanTime] = useState(0)
  const [linesScanned, setLinesScanned] = useState(0)
  const [repoUrl, setRepoUrl] = useState('')
  const [repoScanLoading, setRepoScanLoading] = useState(false)
  const [repoScanError, setRepoScanError] = useState('')
  const [repoScanResult, setRepoScanResult] = useState<GitHubScanResult | null>(null)
  const progressRef = useRef<ReturnType<typeof setInterval> | null>(null)

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
    setSuggestions([])
    setGeneratedTests([])
    startProgress()

    try {
      const response = await axios.post('/api/v1/scan', {
        code,
        language
      })

      const findings = response.data.findings || []
      setResults(findings)
      setScanTime(response.data.scan_time_ms)
      setLinesScanned(response.data.lines_scanned)

      if (findings.length > 0) {
        const [fixResponse, testResponse] = await Promise.all([
          axios.post('/api/v1/fix/suggest', { findings }),
          axios.post('/api/v1/tests/generate', { findings, language })
        ])

        setSuggestions(fixResponse.data.suggestions || [])
        setGeneratedTests(testResponse.data.tests || [])
      }
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

  const getSuggestion = (findingId: string) => {
    return suggestions.find(suggestion => suggestion.vulnerability_id === findingId)
  }

  const getGeneratedTest = (findingId: string) => {
    return generatedTests.find(test => test.vulnerability_id === findingId)
  }

  const parseRepoUrl = (url: string): { owner: string; repo: string } | null => {
    const normalized = url.trim().replace(/\/$/, '')

    if (!normalized) {
      return null
    }

    const githubUrlMatch = normalized.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)(?:\/.*)?$/i)
    if (githubUrlMatch) {
      return { owner: githubUrlMatch[1], repo: githubUrlMatch[2] }
    }

    const ownerRepoMatch = normalized.match(/^([\w-]+)\/([\w.-]+)$/)
    if (ownerRepoMatch) {
      return { owner: ownerRepoMatch[1], repo: ownerRepoMatch[2] }
    }

    return null
  }

  const handleRepoScan = async () => {
    const parsed = parseRepoUrl(repoUrl)
    if (!parsed) {
      setRepoScanError('Enter a valid GitHub repository URL or owner/repo format.')
      return
    }

    setRepoScanLoading(true)
    setRepoScanError('')
    setRepoScanResult(null)

    try {
      const response = await axios.post('/api/v1/scan/github', {
        owner: parsed.owner,
        repo: parsed.repo
      })

      setRepoScanResult(response.data)
    } catch (err: any) {
      setRepoScanError(err.response?.data?.detail || 'Repository scan failed. Please try again.')
    } finally {
      setRepoScanLoading(false)
    }
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
          <Tab icon={<GitHubIcon />} label="GitHub Repo" iconPosition="start" />
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

      {/* GitHub Repo Scan Tab */}
      <TabPanel value={tab} index={2}>
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>GitHub Repository Scan</Typography>

            <TextField
              fullWidth
              label="GitHub repository URL or owner/repo"
              placeholder="https://github.com/owner/repo or owner/repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              sx={{ mb: 2 }}
            />

            <Box display="flex" gap={2} flexWrap="wrap">
              <Button
                variant="contained"
                size="large"
                startIcon={repoScanLoading ? <CircularProgress size={20} color="inherit" /> : <GitHubIcon />}
                onClick={handleRepoScan}
                disabled={repoScanLoading || !repoUrl.trim()}
                sx={{
                  background: 'linear-gradient(90deg, #0f172a 0%, #1d4ed8 100%)',
                  px: 4
                }}
              >
                {repoScanLoading ? 'Scanning repository...' : 'Scan GitHub Repo'}
              </Button>
            </Box>
          </CardContent>
        </Card>

        {repoScanError && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {repoScanError}
          </Alert>
        )}

        {repoScanResult && (
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Repository Scan Result
              </Typography>

              <Box display="grid" gridTemplateColumns="repeat(auto-fit, minmax(220px, 1fr))" gap={2} sx={{ mb: 3 }}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2">Repository</Typography>
                  <Typography>{repoScanResult.owner}/{repoScanResult.repo}</Typography>
                  <Typography variant="caption" component="a" href={repoScanResult.url} target="_blank" rel="noopener noreferrer" sx={{ display: 'block', mt: 1 }}>
                    View on GitHub
                  </Typography>
                </Paper>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2">Primary Language</Typography>
                  <Typography>{repoScanResult.language}</Typography>
                </Paper>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2">Files Scanned</Typography>
                  <Typography>{repoScanResult.files_scanned}/{repoScanResult.files_count}</Typography>
                </Paper>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2">Findings</Typography>
                  <Typography>{repoScanResult.total_findings}</Typography>
                </Paper>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2">Scan Time</Typography>
                  <Typography>{repoScanResult.scan_time_ms.toFixed(0)} ms</Typography>
                </Paper>
              </Box>

              <Box display="flex" gap={2} flexWrap="wrap" sx={{ mb: 3 }}>
                {Object.entries(repoScanResult.findings_by_severity).map(([severity, count]) => (
                  <Paper key={severity} sx={{ p: 2, minWidth: 120, textAlign: 'center' }}>
                    <Typography variant="h5" fontWeight={600}>{count}</Typography>
                    <Typography variant="caption" sx={{ textTransform: 'capitalize' }}>{severity}</Typography>
                  </Paper>
                ))}
              </Box>

              {repoScanResult.sensitive_files.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>Sensitive files detected</Typography>
                  <Box display="flex" gap={1} flexWrap="wrap">
                    {repoScanResult.sensitive_files.map((file) => (
                      <Chip key={file} label={file} size="small" />
                    ))}
                  </Box>
                </Box>
              )}

              <Divider sx={{ mb: 2 }} />

              {repoScanResult.findings_by_file.length > 0 ? (
                repoScanResult.findings_by_file.map((fileResult, index) => (
                  <Box key={index} sx={{ mb: 3 }}>
                    <Typography variant="subtitle1" sx={{ mb: 1 }}>{fileResult.path}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      {fileResult.findings_count} findings in {fileResult.language}
                    </Typography>
                    {fileResult.findings.map((finding) => (
                      <Paper key={finding.id} sx={{ p: 2, mb: 1, borderRadius: 1, bgcolor: 'grey.50' }}>
                        <Typography variant="subtitle2" sx={{ mb: 1 }}>{finding.title}</Typography>
                        <Box display="flex" gap={1} flexWrap="wrap">
                          <Chip label={`Severity: ${finding.severity}`} size="small" />
                          <Chip label={`Category: ${finding.category}`} size="small" />
                          {finding.line_number && <Chip label={`Line ${finding.line_number}`} size="small" />}
                          {finding.source && (
                            <Chip
                              label={finding.source === 'ml' ? 'ML detected' : finding.source === 'pattern' ? 'Rule-based' : finding.source}
                              size="small"
                              variant="outlined"
                            />
                          )}
                        </Box>
                      </Paper>
                    ))}
                  </Box>
                ))
              ) : (
                <Alert severity="success">No code-level findings were found in this repository scan.</Alert>
              )}
            </CardContent>
          </Card>
        )}
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
                  {typeof finding.confidence === 'number' && (
                    <Chip label={`${Math.round(finding.confidence * 100)}% confidence`} size="small" variant="outlined" />
                  )}
                  {finding.source && (
                    <Chip
                      label={finding.source === 'ml' ? 'ML detected' : finding.source === 'pattern' ? 'Rule-based' : finding.source}
                      size="small"
                      variant="outlined"
                      color={finding.source === 'ml' ? 'primary' : 'default'}
                    />
                  )}
                </Box>

                {finding.remediation && (
                  <Paper sx={{ p: 2, mt: 2, bgcolor: '#f0fdf4', border: '1px solid', borderColor: 'success.light' }}>
                    <Typography variant="subtitle2" color="success.dark" gutterBottom>
                      Recommended Remediation
                    </Typography>
                    <Typography component="pre" sx={{ m: 0, whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                      {finding.remediation}
                    </Typography>
                  </Paper>
                )}

                {getSuggestion(finding.id) && (
                  <Paper sx={{ p: 2, mt: 2, bgcolor: '#eff6ff', border: '1px solid', borderColor: 'primary.light' }}>
                    <Typography variant="subtitle2" color="primary.dark" gutterBottom>
                      Fix Suggestion: {getSuggestion(finding.id)?.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      {getSuggestion(finding.id)?.explanation}
                    </Typography>
                    <Typography component="pre" sx={{ m: 0, p: 1.5, borderRadius: 1, bgcolor: 'grey.900', color: 'grey.200', whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.75rem', overflow: 'auto' }}>
                      {getSuggestion(finding.id)?.fixed_code}
                    </Typography>
                  </Paper>
                )}

                {getGeneratedTest(finding.id) && (
                  <Paper sx={{ p: 2, mt: 2, bgcolor: 'background.default' }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Generated Security Test: {getGeneratedTest(finding.id)?.name}
                    </Typography>
                    <Typography component="pre" sx={{ m: 0, p: 1.5, borderRadius: 1, bgcolor: 'grey.900', color: 'grey.200', whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.75rem', overflow: 'auto', maxHeight: 260 }}>
                      {getGeneratedTest(finding.id)?.test_code}
                    </Typography>
                  </Paper>
                )}

                {finding.references && finding.references.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="caption" color="text.secondary">
                      References: {finding.references.join(', ')}
                    </Typography>
                  </Box>
                )}
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

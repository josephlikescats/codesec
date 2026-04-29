import { useState } from 'react'
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
  Divider
} from '@mui/material'
import axios from 'axios'

interface Finding {
  id: string
  category: string
  severity: string
  title: string
  description: string
  line_number: number
  cwe_id: string
}

export default function ScanPage() {
  const [code, setCode] = useState('')
  const [language, setLanguage] = useState('python')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<Finding[]>([])
  const [error, setError] = useState('')
  const [scanTime, setScanTime] = useState(0)

  const handleScan = async () => {
    if (!code.trim()) {
      setError('Please enter code to scan')
      return
    }

    setLoading(true)
    setError('')
    setResults([])

    try {
      const response = await axios.post('/api/v1/scan', {
        code,
        language
      })

      setResults(response.data.findings)
      setScanTime(response.data.scan_time_ms)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Scan failed. Please try again.')
    } finally {
      setLoading(false)
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

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Scan Code
      </Typography>

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
        </CardContent>
      </Card>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {results.length > 0 && (
        <Card>
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
              <Typography variant="h6">
                Scan Results ({results.length} findings)
              </Typography>
              <Chip label={`Scan time: ${scanTime.toFixed(2)}ms`} color="primary" />
            </Box>

            <Divider sx={{ mb: 2 }} />

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
                
                <Box display="flex" gap={2}>
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
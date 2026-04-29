import { useState } from 'react'
import {
  Box,
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  TextField,
  InputAdornment,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Pagination
} from '@mui/material'

// Mock findings data
const mockFindings = [
  { id: '1', category: 'injection', severity: 'critical', title: 'SQL Injection', file: 'auth.py', line: 45, cwe: 'CWE-89', date: '2024-01-29' },
  { id: '2', category: 'xss', severity: 'high', title: 'Cross-Site Scripting', file: 'templates/user.html', line: 23, cwe: 'CWE-79', date: '2024-01-29' },
  { id: '3', category: 'sensitive_data', severity: 'high', title: 'Hardcoded Secret', file: 'config.py', line: 12, cwe: 'CWE-798', date: '2024-01-28' },
  { id: '4', category: 'injection', severity: 'medium', title: 'Command Injection', file: 'utils.py', line: 78, cwe: 'CWE-78', date: '2024-01-28' },
  { id: '5', category: 'deserialization', severity: 'critical', title: 'Insecure Deserialization', file: 'api.py', line: 34, cwe: 'CWE-502', date: '2024-01-27' },
  { id: '6', category: 'broken_access', severity: 'medium', title: 'Path Traversal', file: 'file_handler.py', line: 56, cwe: 'CWE-22', date: '2024-01-27' },
  { id: '7', category: 'xss', severity: 'low', title: 'Reflected XSS', file: 'forms.py', line: 89, cwe: 'CWE-79', date: '2024-01-26' },
  { id: '8', category: 'sensitive_data', severity: 'medium', title: 'Weak Cryptography', file: 'crypto.py', line: 45, cwe: 'CWE-327', date: '2024-01-26' },
]

export default function FindingsPage() {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [page, setPage] = useState(1)

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error'
      case 'high': return 'warning'
      case 'medium': return 'info'
      case 'low': return 'success'
      default: return 'default'
    }
  }

  const filteredFindings = mockFindings.filter(finding => {
    const matchesSearch = finding.title.toLowerCase().includes(search.toLowerCase()) ||
                         finding.file.toLowerCase().includes(search.toLowerCase())
    const matchesSeverity = severityFilter === 'all' || finding.severity === severityFilter
    const matchesCategory = categoryFilter === 'all' || finding.category === categoryFilter
    return matchesSearch && matchesSeverity && matchesCategory
  })

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Vulnerability Findings
      </Typography>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" gap={2} flexWrap="wrap">
            <TextField
              placeholder="Search findings..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    Search
                  </InputAdornment>
                ),
              }}
              sx={{ minWidth: 250 }}
            />

            <FormControl sx={{ minWidth: 150 }}>
              <InputLabel>Severity</InputLabel>
              <Select
                value={severityFilter}
                label="Severity"
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <MenuItem value="all">All</MenuItem>
                <MenuItem value="critical">Critical</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
              </Select>
            </FormControl>

            <FormControl sx={{ minWidth: 150 }}>
              <InputLabel>Category</InputLabel>
              <Select
                value={categoryFilter}
                label="Category"
                onChange={(e) => setCategoryFilter(e.target.value)}
              >
                <MenuItem value="all">All</MenuItem>
                <MenuItem value="injection">Injection</MenuItem>
                <MenuItem value="xss">XSS</MenuItem>
                <MenuItem value="sensitive_data">Sensitive Data</MenuItem>
                <MenuItem value="deserialization">Deserialization</MenuItem>
                <MenuItem value="broken_access">Broken Access</MenuItem>
              </Select>
            </FormControl>
          </Box>
        </CardContent>
      </Card>

      {/* Findings Table */}
      <Card>
        <CardContent>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>File</TableCell>
                  <TableCell>Line</TableCell>
                  <TableCell>CWE</TableCell>
                  <TableCell>Date</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredFindings.map((finding) => (
                  <TableRow key={finding.id}>
                    <TableCell>
                      <Chip 
                        label={finding.severity}
                        color={getSeverityColor(finding.severity) as any}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{finding.title}</TableCell>
                    <TableCell>{finding.file}</TableCell>
                    <TableCell>{finding.line}</TableCell>
                    <TableCell>
                      <Chip 
                        label={finding.cwe} 
                        size="small" 
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>{finding.date}</TableCell>
                    <TableCell>
                      <Button size="small">View</Button>
                      <Button size="small">Fix</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Box display="flex" justifyContent="center" sx={{ mt: 2 }}>
            <Pagination 
              count={Math.ceil(filteredFindings.length / 5)} 
              page={page}
              onChange={(_, p) => setPage(p)}
            />
          </Box>
        </CardContent>
      </Card>
    </Box>
  )
}
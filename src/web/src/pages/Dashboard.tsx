import { useState, useEffect } from 'react'
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper
} from '@mui/material'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

// Mock data
const recentScans = [
  { id: 1, file: 'auth.py', date: '2024-01-29', issues: 3, status: 'completed' },
  { id: 2, file: 'user_service.py', date: '2024-01-29', issues: 1, status: 'completed' },
  { id: 3, file: 'api_handler.py', date: '2024-01-28', issues: 5, status: 'completed' },
  { id: 4, file: 'database.py', date: '2024-01-28', issues: 0, status: 'completed' },
]

const severityData = [
  { name: 'Critical', value: 12, color: '#ef4444' },
  { name: 'High', value: 28, color: '#f59e0b' },
  { name: 'Medium', value: 45, color: '#3b82f6' },
  { name: 'Low', value: 15, color: '#22c55e' },
]

const categoryData = [
  { name: 'Injection', count: 25 },
  { name: 'XSS', count: 18 },
  { name: 'Auth', count: 15 },
  { name: 'Secrets', count: 12 },
  { name: 'Config', count: 8 },
]

const stats = {
  totalScans: 156,
  vulnerabilitiesFound: 100,
  testsGenerated: 45,
  fixesApplied: 32,
  avgScanTime: '2.3s',
  accuracy: '87%'
}

export default function Dashboard() {
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Simulate loading
    const timer = setTimeout(() => setLoading(false), 1000)
    return () => clearTimeout(timer)
  }, [])

  if (loading) {
    return <LinearProgress />
  }

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Security Dashboard
      </Typography>

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={2}>
          <Card sx={{ background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="subtitle2" sx={{ opacity: 0.8 }}>Total Scans</Typography>
                  <Typography variant="h4">{stats.totalScans}</Typography>
                </Box>
                <Typography variant="h5" sx={{ opacity: 0.5 }}>S</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={2}>
          <Card sx={{ background: 'linear-gradient(135deg, #ef4444 0%, #f97316 100%)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="subtitle2" sx={{ opacity: 0.8 }}>Vulnerabilities</Typography>
                  <Typography variant="h4">{stats.vulnerabilitiesFound}</Typography>
                </Box>
                <Typography variant="h5" sx={{ opacity: 0.5 }}>V</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={2}>
          <Card sx={{ background: 'linear-gradient(135deg, #22c55e 0%, #10b981 100%)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="subtitle2" sx={{ opacity: 0.8 }}>Tests Generated</Typography>
                  <Typography variant="h4">{stats.testsGenerated}</Typography>
                </Box>
                <Typography variant="h5" sx={{ opacity: 0.5 }}>T</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={2}>
          <Card sx={{ background: 'linear-gradient(135deg, #3b82f6 0%, #0ea5e9 100%)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="subtitle2" sx={{ opacity: 0.8 }}>Fixes Applied</Typography>
                  <Typography variant="h4">{stats.fixesApplied}</Typography>
                </Box>
                <Typography variant="h5" sx={{ opacity: 0.5 }}>F</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={2}>
          <Card sx={{ background: 'linear-gradient(135deg, #8b5cf6 0%, #a855f7 100%)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="subtitle2" sx={{ opacity: 0.8 }}>Avg Scan Time</Typography>
                  <Typography variant="h4">{stats.avgScanTime}</Typography>
                </Box>
                <Typography variant="h5" sx={{ opacity: 0.5 }}>A</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={2}>
          <Card sx={{ background: 'linear-gradient(135deg, #ec4899 0%, #f43f5e 100%)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="subtitle2" sx={{ opacity: 0.8 }}>Accuracy</Typography>
                  <Typography variant="h4">{stats.accuracy}</Typography>
                </Box>
                <Typography variant="h5" sx={{ opacity: 0.5 }}>%</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Charts */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Vulnerabilities by Category</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={categoryData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="name" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #374151' }}
                    labelStyle={{ color: '#fff' }}
                  />
                  <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>By Severity</Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #374151' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <Box display="flex" flexWrap="wrap" gap={1} justifyContent="center">
                {severityData.map((item) => (
                  <Chip 
                    key={item.name}
                    label={`${item.name}: ${item.value}`}
                    size="small"
                    sx={{ backgroundColor: item.color, color: '#fff' }}
                  />
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Scans Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>Recent Scans</Typography>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>File</TableCell>
                  <TableCell>Date</TableCell>
                  <TableCell>Issues</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {recentScans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell>{scan.file}</TableCell>
                    <TableCell>{scan.date}</TableCell>
                    <TableCell>
                      <Chip 
                        label={scan.issues} 
                        color={scan.issues > 0 ? 'error' : 'success'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={scan.status}
                        color="success"
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Button size="small">View</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    </Box>
  )
}
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useState } from 'react'
import {
  Box,
  AppBar,
  Toolbar,
  Typography,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Snackbar,
  Alert,
  CircularProgress,
  Button
} from '@mui/material'
import axios from '../api/client'

const drawerWidth = 240

const menuItems = [
  { text: 'Dashboard', path: '/' },
  { text: 'Scan Code', path: '/scan' },
  { text: 'Findings', path: '/findings' },
  { text: 'Settings', path: '/settings' },
]

export default function Layout() {
  const navigate = useNavigate()
  const location = useLocation()

  const [quickOpen, setQuickOpen] = useState(false)
  const [owner, setOwner] = useState('octocat')
  const [repo, setRepo] = useState('Hello-World')
  const [scanning, setScanning] = useState(false)
  const [snackOpen, setSnackOpen] = useState(false)
  const [snackMsg, setSnackMsg] = useState('')

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar 
        position="fixed" 
        sx={{ 
          zIndex: (theme) => theme.zIndex.drawer + 1,
          background: 'linear-gradient(90deg, #1e293b 0%, #0f172a 100%)',
          borderBottom: '1px solid rgba(99, 102, 241, 0.2)'
        }}
      >
          <Toolbar>
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1, fontWeight: 700 }}>
            CodeSec
            <Typography component="span" sx={{ ml: 2, fontWeight: 400, opacity: 0.7, fontSize: '0.85rem' }}>
              DevSecOps Scanner
            </Typography>
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <IconButton color="inherit" onClick={() => setQuickOpen(true)} aria-label="Quick scan">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L12 12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M5 12h14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
            </IconButton>
          </Box>
        </Toolbar>

        <Dialog open={quickOpen} onClose={() => setQuickOpen(false)}>
          <DialogTitle>Quick GitHub Scan</DialogTitle>
          <DialogContent>
            <TextField
              label="Owner"
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              fullWidth
              sx={{ mb: 2 }}
            />
            <TextField
              label="Repository"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              fullWidth
            />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setQuickOpen(false)} color="inherit">Cancel</Button>
            <Button
              variant="contained"
              onClick={async () => {
                try {
                  setScanning(true)
                  const response = await axios.post('/api/v1/scan/github', { owner, repo })
                  const data = response.data
                  setSnackMsg(`Scan complete: ${data.total_findings} findings in ${data.files_scanned} files`)
                  setSnackOpen(true)
                } catch (error: any) {
                  setSnackMsg(`Scan failed: ${error.response?.data?.detail || error.message}`)
                  setSnackOpen(true)
                } finally {
                  setScanning(false)
                  setQuickOpen(false)
                }
              }}
              sx={{ px: 3 }}
              disabled={scanning}
            >
              {scanning ? <CircularProgress size={18} color="inherit" /> : 'Start Scan'}
            </Button>
          </DialogActions>
        </Dialog>

        <Snackbar open={snackOpen} autoHideDuration={6000} onClose={() => setSnackOpen(false)}>
          <Alert onClose={() => setSnackOpen(false)} severity="info" sx={{ width: '100%' }}>
            {snackMsg}
          </Alert>
        </Snackbar>
      </AppBar>
      
      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
            background: '#1e293b',
            borderRight: '1px solid rgba(99, 102, 241, 0.1)'
          },
        }}
      >
        <Toolbar />
        <Box sx={{ overflow: 'auto', mt: 2 }}>
          <List>
            {menuItems.map((item) => (
              <ListItem key={item.text} disablePadding>
                <ListItemButton 
                  selected={location.pathname === item.path}
                  onClick={() => navigate(item.path)}
                  sx={{
                    mx: 1,
                    borderRadius: 2,
                    mb: 0.5,
                    '&.Mui-selected': {
                      backgroundColor: 'rgba(99, 102, 241, 0.15)',
                      '&:hover': {
                        backgroundColor: 'rgba(99, 102, 241, 0.2)',
                      },
                    },
                  }}
                >
                  <ListItemText 
                    primary={item.text}
                    primaryTypographyProps={{
                      fontWeight: location.pathname === item.path ? 600 : 400
                    }}
                  />
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>
      
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          ml: `${drawerWidth}px`,
          mt: 8,
          backgroundColor: '#0f172a',
          minHeight: '100vh'
        }}
      >
        <Outlet />
      </Box>
    </Box>
  )
}

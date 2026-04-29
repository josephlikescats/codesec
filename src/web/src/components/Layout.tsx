import { Outlet, useNavigate, useLocation } from 'react-router-dom'
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
  useTheme
} from '@mui/material'

const drawerWidth = 240

const menuItems = [
  { text: 'Dashboard', path: '/' },
  { text: 'Scan Code', path: '/scan' },
  { text: 'Findings', path: '/findings' },
  { text: 'Settings', path: '/settings' },
]

export default function Layout() {
  const theme = useTheme()
  const navigate = useNavigate()
  const location = useLocation()

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
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            SecureCode AI
          </Typography>
        </Toolbar>
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
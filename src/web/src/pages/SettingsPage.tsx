import { useState } from 'react'
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Switch,
  FormControlLabel,
  Alert,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Grid
} from '@mui/material'

export default function SettingsPage() {
  const [saved, setSaved] = useState(false)
  
  const [settings, setSettings] = useState({
    apiUrl: 'http://localhost:8000',
    modelPath: 'models/securecode-v1',
    modelDevice: 'cpu',
    maxLength: 512,
    enableTestGeneration: true,
    enableRemediation: true,
    enableXAI: true,
    enableContinuousLearning: false,
    logLevel: 'INFO',
    githubToken: '',
    nvdApiKey: ''
  })

  const handleSave = () => {
    // In production, this would save to backend
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3, fontWeight: 600 }}>
        Settings
      </Typography>

      {saved && (
        <Alert severity="success" sx={{ mb: 3 }}>
          Settings saved successfully!
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* API Configuration */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                API Configuration
              </Typography>
              
              <TextField
                fullWidth
                label="API URL"
                value={settings.apiUrl}
                onChange={(e) => setSettings({...settings, apiUrl: e.target.value})}
                sx={{ mb: 2 }}
              />
              
              <TextField
                fullWidth
                label="Model Path"
                value={settings.modelPath}
                onChange={(e) => setSettings({...settings, modelPath: e.target.value})}
                sx={{ mb: 2 }}
              />
              
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Device</InputLabel>
                <Select
                  value={settings.modelDevice}
                  label="Device"
                  onChange={(e) => setSettings({...settings, modelDevice: e.target.value})}
                >
                  <MenuItem value="cpu">CPU</MenuItem>
                  <MenuItem value="cuda">CUDA (GPU)</MenuItem>
                </Select>
              </FormControl>
              
              <TextField
                fullWidth
                label="Max Token Length"
                type="number"
                value={settings.maxLength}
                onChange={(e) => setSettings({...settings, maxLength: parseInt(e.target.value)})}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Feature Flags */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Feature Flags
              </Typography>
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.enableTestGeneration}
                    onChange={(e) => setSettings({...settings, enableTestGeneration: e.target.checked})}
                  />
                }
                label="Enable Test Generation"
                sx={{ mb: 1, display: 'block' }}
              />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.enableRemediation}
                    onChange={(e) => setSettings({...settings, enableRemediation: e.target.checked})}
                  />
                }
                label="Enable Remediation Suggestions"
                sx={{ mb: 1, display: 'block' }}
              />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.enableXAI}
                    onChange={(e) => setSettings({...settings, enableXAI: e.target.checked})}
                  />
                }
                label="Enable Explainable AI"
                sx={{ mb: 1, display: 'block' }}
              />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={settings.enableContinuousLearning}
                    onChange={(e) => setSettings({...settings, enableContinuousLearning: e.target.checked})}
                  />
                }
                label="Enable Continuous Learning"
                sx={{ mb: 1, display: 'block' }}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* API Keys */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                API Keys
              </Typography>
              
              <TextField
                fullWidth
                label="GitHub Token"
                type="password"
                value={settings.githubToken}
                onChange={(e) => setSettings({...settings, githubToken: e.target.value})}
                helperText="Token for GitHub API access"
                sx={{ mb: 2 }}
              />
              
              <TextField
                fullWidth
                label="NVD API Key"
                type="password"
                value={settings.nvdApiKey}
                onChange={(e) => setSettings({...settings, nvdApiKey: e.target.value})}
                helperText="API key for National Vulnerability Database"
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Logging */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Logging
              </Typography>
              
              <FormControl fullWidth>
                <InputLabel>Log Level</InputLabel>
                <Select
                  value={settings.logLevel}
                  label="Log Level"
                  onChange={(e) => setSettings({...settings, logLevel: e.target.value})}
                >
                  <MenuItem value="DEBUG">Debug</MenuItem>
                  <MenuItem value="INFO">Info</MenuItem>
                  <MenuItem value="WARNING">Warning</MenuItem>
                  <MenuItem value="ERROR">Error</MenuItem>
                </Select>
              </FormControl>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
        <Button
          variant="contained"
          onClick={handleSave}
          sx={{ 
            background: 'linear-gradient(90deg, #6366f1 0%, #8b5cf6 100%)',
            px: 4
          }}
        >
          Save Settings
        </Button>
      </Box>
    </Box>
  )
}
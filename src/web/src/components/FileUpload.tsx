import { useState, useCallback } from 'react'
import {
  Box,
  Typography,
  Paper,
  LinearProgress,
  Chip,
  IconButton,
  Collapse
} from '@mui/material'
import {
  CloudUpload as UploadIcon,
  InsertDriveFile as FileIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon
} from '@mui/icons-material'
import axios from 'axios'

interface UploadedFile {
  name: string
  size: number
  content?: string
}

interface FileUploadProps {
  onScanComplete?: (results: any) => void
}

export default function FileUpload({ onScanComplete }: FileUploadProps) {
  const [files, setFiles] = useState<UploadedFile[]>([])
  const [isDragging, setIsDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [results, setResults] = useState<any>(null)
  const [expanded, setExpanded] = useState(true)

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    
    const droppedFiles = Array.from(e.dataTransfer.files).map(file => ({
      name: file.name,
      size: file.size
    }))
    
    setFiles(prev => [...prev, ...droppedFiles])
  }, [])

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files).map(file => ({
        name: file.name,
        size: file.size
      }))
      setFiles(prev => [...prev, ...selectedFiles])
    }
  }, [])

  const removeFile = useCallback((index: number) => {
    setFiles(prev => prev.filter((_, i) => i !== index))
  }, [])

  const clearFiles = useCallback(() => {
    setFiles([])
    setResults(null)
  }, [])

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const handleScan = async () => {
    if (files.length === 0) return

    setUploading(true)
    setProgress(0)
    setResults(null)

    try {
      // Create FormData with files
      const formData = new FormData()
      
      // Get actual file objects from the input
      const fileInput = document.getElementById('file-input') as HTMLInputElement
      if (fileInput?.files) {
        Array.from(fileInput.files).forEach(file => {
          formData.append('files', file)
        })
      }

      // Simulate progress
      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 10, 90))
      }, 200)

      const response = await axios.post('/api/v1/scan/project', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      clearInterval(progressInterval)
      setProgress(100)
      setResults(response.data)
      
      if (onScanComplete) {
        onScanComplete(response.data)
      }
    } catch (err: any) {
      console.error('Scan failed:', err)
    } finally {
      setUploading(false)
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
      {/* Drop Zone */}
      <Paper
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        sx={{
          p: 4,
          textAlign: 'center',
          border: '2px dashed',
          borderColor: isDragging ? 'primary.main' : 'divider',
          backgroundColor: isDragging ? 'action.hover' : 'background.paper',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
          '&:hover': {
            borderColor: 'primary.main',
            backgroundColor: 'action.hover'
          }
        }}
        onClick={() => document.getElementById('file-input')?.click()}
      >
        <input
          type="file"
          id="file-input"
          multiple
          directory=""
          webkitdirectory=""
          onChange={handleFileSelect}
          style={{ display: 'none' }}
        />
        
        <UploadIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
        
        <Typography variant="h6" gutterBottom>
          Drop project files here
        </Typography>
        
        <Typography variant="body2" color="text.secondary">
          or click to browse • Supports multiple files and folders
        </Typography>
      </Paper>

      {/* File List */}
      {files.length > 0 && (
        <Box sx={{ mt: 2 }}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
            <Typography variant="subtitle2" color="text.secondary">
              {files.length} file(s) selected
            </Typography>
            <Box>
              <IconButton size="small" onClick={() => setExpanded(!expanded)}>
                {expanded ? <CollapseIcon /> : <ExpandIcon />}
              </IconButton>
              <IconButton size="small" onClick={clearFiles}>
                <DeleteIcon />
              </IconButton>
            </Box>
          </Box>

          <Collapse in={expanded}>
            <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
              {files.map((file, index) => (
                <Box
                  key={index}
                  display="flex"
                  alignItems="center"
                  justifyContent="space-between"
                  sx={{
                    p: 1,
                    mb: 0.5,
                    borderRadius: 1,
                    backgroundColor: 'background.default'
                  }}
                >
                  <Box display="flex" alignItems="center" gap={1}>
                    <FileIcon fontSize="small" color="action" />
                    <Typography variant="body2">{file.name}</Typography>
                  </Box>
                  <Chip label={formatFileSize(file.size)} size="small" variant="outlined" />
                </Box>
              ))}
            </Box>
          </Collapse>

          {/* Scan Button */}
          <Box sx={{ mt: 2, display: 'flex', gap: 2, alignItems: 'center' }}>
            <Box
              component="button"
              onClick={handleScan}
              disabled={uploading}
              sx={{
                px: 3,
                py: 1.5,
                border: 'none',
                borderRadius: 1,
                background: 'linear-gradient(90deg, #6366f1 0%, #8b5cf6 100%)',
                color: 'white',
                cursor: uploading ? 'not-allowed' : 'pointer',
                fontWeight: 600,
                opacity: uploading ? 0.7 : 1,
                transition: 'all 0.2s ease'
              }}
            >
              {uploading ? 'Scanning...' : `Scan ${files.length} File(s)`}
            </Box>

            {uploading && (
              <Box sx={{ flex: 1 }}>
                <LinearProgress variant="determinate" value={progress} />
              </Box>
            )}
          </Box>
        </Box>
      )}

      {/* Results Summary */}
      {results && (
        <Box sx={{ mt: 3 }}>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Scan Results</Typography>
            <Chip 
              label={`${results.scan_time_ms?.toFixed(0) || 0}ms`} 
              size="small" 
              color="primary" 
            />
          </Box>

          {/* Summary Cards */}
          <Box display="flex" gap={2} flexWrap="wrap" mb={3}>
            <Paper sx={{ p: 2, minWidth: 100, textAlign: 'center' }}>
              <Typography variant="h4" color="error.main">
                {results.by_severity?.critical || 0}
              </Typography>
              <Typography variant="caption" color="text.secondary">Critical</Typography>
            </Paper>
            <Paper sx={{ p: 2, minWidth: 100, textAlign: 'center' }}>
              <Typography variant="h4" color="warning.main">
                {results.by_severity?.high || 0}
              </Typography>
              <Typography variant="caption" color="text.secondary">High</Typography>
            </Paper>
            <Paper sx={{ p: 2, minWidth: 100, textAlign: 'center' }}>
              <Typography variant="h4" color="info.main">
                {results.by_severity?.medium || 0}
              </Typography>
              <Typography variant="caption" color="text.secondary">Medium</Typography>
            </Paper>
            <Paper sx={{ p: 2, minWidth: 100, textAlign: 'center' }}>
              <Typography variant="h4" color="success.main">
                {results.by_severity?.low || 0}
              </Typography>
              <Typography variant="caption" color="text.secondary">Low</Typography>
            </Paper>
          </Box>

          {/* File Results */}
          <Typography variant="subtitle2" gutterBottom>
            Files Scanned ({results.total_files})
          </Typography>
          
          {results.results?.map((fileResult: any, index: number) => (
            <Paper
              key={index}
              sx={{
                p: 2,
                mb: 1,
                borderLeft: '4px solid',
                borderLeftColor: fileResult.has_issues ? 'warning.main' : 'success.main'
              }}
            >
              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Box display="flex" alignItems="center" gap={1}>
                  <FileIcon fontSize="small" />
                  <Typography variant="body2" fontWeight={500}>
                    {fileResult.file_name}
                  </Typography>
                </Box>
                <Box display="flex" gap={1}>
                  <Chip 
                    label={fileResult.language} 
                    size="small" 
                    variant="outlined" 
                  />
                  <Chip 
                    label={`${fileResult.findings?.length || 0} findings`}
                    size="small"
                    color={fileResult.has_issues ? 'warning' : 'success'}
                  />
                </Box>
              </Box>
            </Paper>
          ))}
        </Box>
      )}
    </Box>
  )
}
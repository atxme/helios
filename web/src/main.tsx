import CssBaseline from '@mui/material/CssBaseline'
import { ThemeProvider } from '@mui/material/styles'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { heliosTheme } from './theme'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/*
      `defaultMode="system"` is only the starting point: the mode an operator
      picks is persisted by MUI, and index.html replays it before first paint.
    */}
    <ThemeProvider theme={heliosTheme} defaultMode="system">
      <CssBaseline />
      <App />
    </ThemeProvider>
  </StrictMode>,
)

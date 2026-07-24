import React from 'react'
import ReactDOM from 'react-dom/client'
import CssBaseline from '@mui/material/CssBaseline'
import { StyledEngineProvider, ThemeProvider } from '@mui/material/styles'
import App from './App'
import './index.css'
import { lockShell } from './shell'
import { orionTheme } from './theme'

// Avant le premier rendu : le menu contextuel de WebView2 existe dès que la
// page existe, indépendamment de React.
lockShell(window)

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <StyledEngineProvider injectFirst>
      <ThemeProvider theme={orionTheme}>
        <CssBaseline />
        <App />
      </ThemeProvider>
    </StyledEngineProvider>
  </React.StrictMode>,
)

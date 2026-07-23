import { createTheme } from '@mui/material/styles'

const SYSTEM_FONT =
  'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
const MONO_FONT =
  '"Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, ui-monospace, monospace'

/**
 * Socle Material Design d’Orion.
 *
 * Les couleurs de posture restent pilotées par `components/state.ts` : elles
 * portent un sens de sécurité et ne doivent pas être remplacées par une simple
 * couleur décorative du thème.
 */
export const orionTheme = createTheme({
  cssVariables: true,
  palette: {
    mode: 'dark',
    primary: {
      main: '#22d3ee',
      light: '#67e8f9',
      dark: '#0891b2',
      contrastText: '#031318',
    },
    secondary: {
      main: '#e879f9',
    },
    success: {
      main: '#28e4a0',
    },
    warning: {
      main: '#ffb347',
    },
    error: {
      main: '#ff5757',
    },
    background: {
      default: '#03060f',
      paper: '#0c1426',
    },
    text: {
      primary: '#e6edf6',
      secondary: '#94a3b8',
    },
    divider: 'rgba(148, 163, 184, 0.14)',
  },
  shape: {
    borderRadius: 14,
  },
  typography: {
    fontFamily: SYSTEM_FONT,
    button: {
      fontWeight: 650,
      letterSpacing: '0.01em',
      textTransform: 'none',
    },
    overline: {
      fontSize: '0.625rem',
      fontWeight: 700,
      letterSpacing: '0.16em',
      lineHeight: 1.5,
    },
    caption: {
      lineHeight: 1.5,
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        'html, body, #root': {
          height: '100%',
        },
        body: {
          margin: 0,
          background:
            'radial-gradient(900px 520px at 50% -12%, rgba(34, 211, 238, 0.11), transparent 62%), #03060f',
          color: '#e6edf6',
          WebkitFontSmoothing: 'antialiased',
          textRendering: 'optimizeLegibility',
        },
        'button, input, textarea, select': {
          font: 'inherit',
        },
        'code, pre, kbd, samp': {
          fontFamily: MONO_FONT,
        },
        '::selection': {
          backgroundColor: 'rgba(34, 211, 238, 0.28)',
        },
        '::-webkit-scrollbar': {
          width: 8,
          height: 8,
        },
        '::-webkit-scrollbar-thumb': {
          backgroundColor: 'rgba(148, 163, 184, 0.3)',
          border: '2px solid transparent',
          borderRadius: 8,
          backgroundClip: 'padding-box',
        },
        '::-webkit-scrollbar-thumb:hover': {
          backgroundColor: 'rgba(34, 211, 238, 0.48)',
        },
        '@media (prefers-reduced-motion: reduce)': {
          '*, *::before, *::after': {
            scrollBehavior: 'auto !important',
            animationDuration: '0.01ms !important',
            animationIterationCount: '1 !important',
            transitionDuration: '0.01ms !important',
          },
        },
      },
    },
    MuiButton: {
      defaultProps: {
        disableElevation: true,
      },
      styleOverrides: {
        root: {
          minHeight: 40,
          borderRadius: 10,
          '&.Mui-focusVisible': {
            outline: '3px solid rgba(34, 211, 238, 0.32)',
            outlineOffset: 2,
          },
        },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          '&.Mui-focusVisible': {
            outline: '3px solid rgba(34, 211, 238, 0.32)',
            outlineOffset: 2,
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: '1px solid rgba(56, 189, 248, 0.16)',
        },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          minHeight: 44,
          minWidth: 0,
          borderRadius: 10,
          textTransform: 'none',
          '&.Mui-focusVisible': {
            outline: '3px solid rgba(34, 211, 238, 0.32)',
            outlineOffset: -3,
          },
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        indicator: {
          height: 3,
          borderRadius: '3px 3px 0 0',
        },
      },
    },
    MuiTooltip: {
      defaultProps: {
        arrow: true,
        enterDelay: 500,
      },
    },
  },
})

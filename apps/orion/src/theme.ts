import { createTheme } from '@mui/material/styles'

const SYSTEM_FONT =
  'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
const MONO_FONT =
  '"Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, ui-monospace, monospace'

/**
 * Orion's visual base — "ink & pine".
 *
 * Stance: **color is rare, therefore it means something**. Orion has only
 * one message to convey — is the traffic protected — and `components/state.ts`
 * encodes that answer with a color. An interface that also colors its
 * headers, tabs, and accents drowns that signal among decorations.
 *
 * Hence a paper background, ink typography, and pine green reserved for two
 * uses: the primary action and the protected state. Everything else is
 * neutral.
 *
 * Corollary: state colors are NOT derived from this theme. They live in
 * `state.ts` because they carry a security meaning, not an aesthetic intent.
 */

/** Paper background — cold white, deliberately not cream. */
export const PAPER = '#FBFCFB'
/** Primary text: a green-tinted black, which ties the type to the brand. */
export const INK = '#10231C'
/** Secondary text. */
export const GRAPHITE = '#5A6B65'
/** Tertiary text — never carries critical information. */
export const SLATE = '#8A9691'
/** Rules and separators. */
export const RULE = '#E2E8E5'
/** The amber of a row to do. */
export const DUE_BORDER = '#B45309'
export const DUE_BACKGROUND = '#FFFBEB'
/** The brand's green: primary action and protected state, nothing else. */
export const PINE = '#0B6B4E'
/**
 * Vivid green — **graphics only**. It doesn't hold the AA ratio on paper,
 * so it never states: it illuminates (orb, chips, curves, rails).
 */
export const EMERALD = '#12B981'
/** The interface's only tinted surface. */
export const MINT = '#E3F6EE'
/**
 * Emission's accent — the one hue outside the green family.
 *
 * Reserved for the speedtest, and there for a single job: the run measures the
 * same quantity twice, once in each direction, and the two figures are read
 * side by side. Told apart by two shades of the same green, they were compared
 * by their labels rather than seen apart — the reason the screen showed the
 * uplink where the downlink belonged for as long as it took to read.
 *
 * It is not a second brand colour: nothing outside the direction pair may use
 * it, and the protected state stays `PINE`.
 */
export const VIOLET = '#6D28D9'

/**
 * Shared gutter, in MUI spacing units (2 = 16 px).
 *
 * Header, navigation, and content all align to it. A view that chose its own
 * value would shift its text on tab change — the most visible defect of a
 * multi-view UI, and the easiest to let slip.
 */
export const GUTTER = 2

export const orionTheme = createTheme({
  cssVariables: true,
  palette: {
    mode: 'light',
    primary: {
      main: PINE,
      light: EMERALD,
      dark: '#075139',
      contrastText: '#FFFFFF',
    },
    success: { main: PINE },
    warning: { main: '#A16207' },
    error: { main: '#9B2C2C' },
    info: { main: '#2F5D8A' },
    background: {
      default: PAPER,
      paper: '#FFFFFF',
    },
    text: {
      primary: INK,
      secondary: GRAPHITE,
      disabled: SLATE,
    },
    divider: RULE,
  },
  shape: {
    borderRadius: 10,
  },
  typography: {
    fontFamily: SYSTEM_FONT,
    button: {
      fontWeight: 650,
      letterSpacing: '0.01em',
      textTransform: 'none',
    },
    // The "instrument" voice: narrow monospace capitals, widely spaced. It
    // labels data, never states it.
    overline: {
      fontFamily: MONO_FONT,
      fontSize: '0.625rem',
      fontWeight: 600,
      letterSpacing: '0.18em',
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
          // No view scrolls: the window is sized to fit its content.
          overflow: 'hidden',
        },
        body: {
          margin: 0,
          backgroundColor: PAPER,
          color: INK,
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
          backgroundColor: 'rgba(18, 185, 129, 0.24)',
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
          borderRadius: 8,
          '&.Mui-focusVisible': {
            outline: `3px solid ${PINE}44`,
            outlineOffset: 2,
          },
        },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          '&.Mui-focusVisible': {
            outline: `3px solid ${PINE}44`,
            outlineOffset: 2,
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          border: `1px solid ${RULE}`,
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

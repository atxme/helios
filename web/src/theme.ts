import { createTheme } from '@mui/material/styles'
import '@fontsource-variable/space-grotesk'
import '@fontsource-variable/jetbrains-mono'

/**
 * Helios' visual base — light product register.
 *
 * Two earlier attempts were rejected, and both failed the same way: they
 * dressed a console in an *atmosphere*. The first tinted everything warm cream
 * until no two surfaces could be told apart; the second painted an indigo
 * night with gold and jade, which read as a theme rather than as a tool.
 *
 * This one is deliberately ordinary in its structure and confident in its
 * color: a cool light page, white cards with a real edge and a soft shadow,
 * black text. Nothing is tinted for mood. Color appears only where it carries
 * a category or a state, and where it appears it is **saturated** — the
 * failure mode to avoid is not "too colorful", it is "washed out".
 *
 * Three families, and they never borrow from one another:
 *
 * - **Action** (`primary`, indigo) — buttons, focus, the selected destination.
 *   One color for "you can do something here", used everywhere and nowhere
 *   else.
 * - **Crypto** (`tertiary`, violet) — the post-quantum axis: negotiation
 *   floors, occupied PSK slots, ML-KEM. "This peer is protected by ML-KEM" is
 *   not the same claim as "traffic is flowing", so it is not the same color.
 * - **State** (`palette.state`) — the security fact: emerald, blue, slate,
 *   red, amber. `state.ts` owns the meaning, this file only owns the pigment.
 *
 * The sun stays on the mark. Helios' orange is the brand's signature and it is
 * spent there, not smeared over the interface — which is exactly what the
 * first two attempts did wrong.
 */

const DISPLAY_FONT =
  '"Space Grotesk Variable", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif'
const MONO_FONT = '"JetBrains Mono Variable", "Cascadia Code", Consolas, ui-monospace, monospace'

/** Emphasized easing — leaves fast, settles slowly. For meaning, not hovers. */
export const EMPHASIZED = 'cubic-bezier(0.2, 0, 0, 1)'

/** Shared gutter, in MUI spacing units (3 = 24 px). */
export const GUTTER = 3

/** Corner radius of a content card. */
export const CARD_RADIUS = 14

/** Width of the navigation rail, labels included. */
export const RAIL_WIDTH = 92

/** Helios' orange. The mark's color, and nothing else's. */
export const SUN = '#F97316'

declare module '@mui/material/styles' {
  /**
   * Tells TypeScript that this theme is built with CSS variables, which is
   * what puts `theme.vars` and `theme.colorSchemes` on the `Theme` type.
   */
  interface CssThemeVariables {
    enabled: true
  }

  /** One tonal triplet: the accent, the surface it tints, the ink on it. */
  interface StateTone {
    main: string
    container: string
    onContainer: string
  }

  /**
   * Every accent gets a container pair. MUI's palette stops at
   * main/light/dark, and without the pair a tinted surface has to be
   * improvised out of translucent overlays — which lose contrast in exactly
   * one of the two schemes.
   */
  interface PaletteColor {
    container: string
    onContainer: string
  }

  interface SimplePaletteColorOptions {
    container?: string
    onContainer?: string
  }

  /**
   * Keys mirror `TunnelState`, so a new daemon state cannot be rendered
   * without choosing its pigment here.
   */
  interface StatePalette {
    up: StateTone
    connecting: StateTone
    down: StateTone
    failed: StateTone
    captivePortal: StateTone
  }

  interface Palette {
    state: StatePalette
    /** Violet: the post-quantum axis. Never a state, never an action. */
    tertiary: { main: string; container: string; onContainer: string }
    /** Surfaces, from the page up to the most raised panel. */
    surfaceContainer: {
      lowest: string
      low: string
      main: string
      high: string
      highest: string
    }
    /** The card shadow, which differs per scheme: dark schemes barely cast. */
    cardShadow: string
  }

  interface PaletteOptions {
    state?: StatePalette
    tertiary?: Palette['tertiary']
    surfaceContainer?: Palette['surfaceContainer']
    cardShadow?: string
  }
}

const LIGHT_STATE = {
  up: { main: '#059669', container: '#D1FAE5', onContainer: '#064E3B' },
  connecting: { main: '#2563EB', container: '#DBEAFE', onContainer: '#1E3A8A' },
  down: { main: '#64748B', container: '#F1F5F9', onContainer: '#334155' },
  failed: { main: '#DC2626', container: '#FEE2E2', onContainer: '#7F1D1D' },
  captivePortal: { main: '#D97706', container: '#FEF3C7', onContainer: '#78350F' },
} as const

const DARK_STATE = {
  up: { main: '#34D399', container: '#064E3B', onContainer: '#A7F3D0' },
  connecting: { main: '#60A5FA', container: '#1E3A8A', onContainer: '#DBEAFE' },
  down: { main: '#94A3B8', container: '#1E293B', onContainer: '#E2E8F0' },
  failed: { main: '#F87171', container: '#7F1D1D', onContainer: '#FEE2E2' },
  captivePortal: { main: '#FBBF24', container: '#78350F', onContainer: '#FEF3C7' },
} as const

export const heliosTheme = createTheme({
  cssVariables: { colorSchemeSelector: 'data' },
  colorSchemes: {
    light: {
      palette: {
        mode: 'light',
        primary: {
          main: '#4F46E5',
          light: '#6366F1',
          dark: '#4338CA',
          contrastText: '#FFFFFF',
          container: '#E8E9FE',
          onContainer: '#2E2585',
        },
        secondary: {
          main: '#C2410C',
          light: '#EA580C',
          dark: '#9A3412',
          contrastText: '#FFFFFF',
          container: '#FFEDD5',
          onContainer: '#7C2D12',
        },
        tertiary: { main: '#7C3AED', container: '#EDE9FE', onContainer: '#4C1D95' },
        success: { main: '#059669', contrastText: '#FFFFFF', container: '#D1FAE5', onContainer: '#064E3B' },
        warning: { main: '#B45309', contrastText: '#FFFFFF', container: '#FEF3C7', onContainer: '#78350F' },
        error: { main: '#DC2626', contrastText: '#FFFFFF', container: '#FEE2E2', onContainer: '#7F1D1D' },
        info: { main: '#2563EB', contrastText: '#FFFFFF', container: '#DBEAFE', onContainer: '#1E3A8A' },
        background: {
          default: '#F6F7F9',
          paper: '#FFFFFF',
        },
        text: {
          primary: '#101828',
          secondary: '#667085',
          disabled: '#98A2B3',
        },
        divider: '#E4E7EC',
        state: LIGHT_STATE,
        surfaceContainer: {
          lowest: '#FFFFFF',
          low: '#FFFFFF',
          main: '#F9FAFB',
          high: '#F2F4F7',
          highest: '#EAECF0',
        },
        cardShadow: '0 1px 2px rgba(16, 24, 40, 0.05), 0 1px 3px rgba(16, 24, 40, 0.04)',
      },
    },
    dark: {
      palette: {
        mode: 'dark',
        primary: {
          main: '#818CF8',
          light: '#A5B4FC',
          dark: '#6366F1',
          contrastText: '#1E1B4B',
          container: '#312E81',
          onContainer: '#E0E7FF',
        },
        secondary: {
          main: '#FB923C',
          light: '#FDBA74',
          dark: '#EA580C',
          contrastText: '#431407',
          container: '#7C2D12',
          onContainer: '#FFEDD5',
        },
        tertiary: { main: '#A78BFA', container: '#4C1D95', onContainer: '#EDE9FE' },
        success: { main: '#34D399', contrastText: '#064E3B', container: '#064E3B', onContainer: '#A7F3D0' },
        warning: { main: '#FBBF24', contrastText: '#78350F', container: '#78350F', onContainer: '#FEF3C7' },
        error: { main: '#F87171', contrastText: '#7F1D1D', container: '#7F1D1D', onContainer: '#FEE2E2' },
        info: { main: '#60A5FA', contrastText: '#1E3A8A', container: '#1E3A8A', onContainer: '#DBEAFE' },
        background: {
          default: '#0B0C0E',
          paper: '#16181C',
        },
        text: {
          primary: '#F2F4F7',
          secondary: '#98A2B3',
          disabled: '#667085',
        },
        divider: '#2A2E35',
        state: DARK_STATE,
        surfaceContainer: {
          lowest: '#0B0C0E',
          low: '#16181C',
          main: '#1B1E23',
          high: '#22262C',
          highest: '#2C3138',
        },
        cardShadow: 'none',
      },
    },
  },
  shape: {
    borderRadius: 10,
  },
  typography: {
    fontFamily: DISPLAY_FONT,
    h1: { fontSize: '2.25rem', fontWeight: 600, lineHeight: 1.18, letterSpacing: '-0.025em' },
    h2: { fontSize: '1.75rem', fontWeight: 600, lineHeight: 1.22, letterSpacing: '-0.022em' },
    // The heading of a view.
    h3: { fontSize: '1.5rem', fontWeight: 600, lineHeight: 1.25, letterSpacing: '-0.02em' },
    // The headline of a hero panel.
    h4: { fontSize: '1.3125rem', fontWeight: 600, lineHeight: 1.25, letterSpacing: '-0.018em' },
    h5: { fontSize: '1.0625rem', fontWeight: 600, lineHeight: 1.35, letterSpacing: '-0.012em' },
    // The title of a card.
    h6: { fontSize: '0.9375rem', fontWeight: 600, lineHeight: 1.4, letterSpacing: '-0.008em' },
    body1: { fontSize: '0.9375rem', lineHeight: 1.55 },
    body2: { fontSize: '0.8125rem', lineHeight: 1.55 },
    button: {
      fontSize: '0.8125rem',
      fontWeight: 600,
      letterSpacing: '0.005em',
      textTransform: 'none',
    },
    caption: { fontSize: '0.75rem', lineHeight: 1.45 },
    // The "instrument" voice: monospace capitals. It labels data, never states it.
    overline: {
      fontFamily: MONO_FONT,
      fontSize: '0.6875rem',
      fontWeight: 600,
      letterSpacing: '0.1em',
      lineHeight: 1.5,
      textTransform: 'uppercase',
    },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        'html, body, #root': { height: '100%' },
        body: {
          margin: 0,
          WebkitFontSmoothing: 'antialiased',
          textRendering: 'optimizeLegibility',
        },
        'button, input, textarea, select': { font: 'inherit' },
        'code, pre, kbd, samp': { fontFamily: MONO_FONT },
        code: {
          fontSize: '0.875em',
          padding: '0.12em 0.38em',
          borderRadius: 5,
          backgroundColor: 'var(--mui-palette-surfaceContainer-highest)',
          color: 'var(--mui-palette-text-primary)',
        },
        '*::-webkit-scrollbar': { width: 10, height: 10 },
        '*::-webkit-scrollbar-track': { background: 'transparent' },
        '*::-webkit-scrollbar-thumb': {
          borderRadius: 8,
          border: '3px solid transparent',
          backgroundClip: 'content-box',
          backgroundColor: 'var(--mui-palette-divider)',
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
    MuiPaper: {
      defaultProps: { elevation: 0 },
      styleOverrides: { root: { backgroundImage: 'none' } },
    },
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: {
        root: {
          borderRadius: 8,
          minHeight: 38,
          paddingInline: 16,
          '&.Mui-focusVisible': {
            outline: '2px solid var(--mui-palette-primary-main)',
            outlineOffset: 2,
          },
        },
        sizeSmall: { minHeight: 32, paddingInline: 12 },
        outlined: { borderColor: 'var(--mui-palette-divider)' },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          '&.Mui-focusVisible': {
            outline: '2px solid var(--mui-palette-primary-main)',
            outlineOffset: 2,
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { borderRadius: 6, fontWeight: 600, height: 24 },
        label: { paddingInline: 8, fontSize: '0.75rem' },
      },
    },
    MuiTooltip: {
      defaultProps: { arrow: true, enterDelay: 400 },
      styleOverrides: {
        tooltip: {
          fontSize: '0.75rem',
          lineHeight: 1.45,
          padding: '8px 12px',
          maxWidth: 320,
          backgroundColor: '#101828',
          color: '#FFFFFF',
        },
        arrow: { color: '#101828' },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: { borderRadius: 8, backgroundColor: 'var(--mui-palette-surfaceContainer-lowest)' },
      },
    },
    MuiLinearProgress: {
      styleOverrides: { root: { borderRadius: 999, height: 6 } },
    },
    MuiSkeleton: {
      styleOverrides: { root: { backgroundColor: 'var(--mui-palette-surfaceContainer-high)' } },
    },
    MuiDialog: {
      styleOverrides: { paper: { borderRadius: 14, backgroundImage: 'none' } },
    },
  },
})

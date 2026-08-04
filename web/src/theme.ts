import { createTheme } from '@mui/material/styles'
import '@fontsource-variable/space-grotesk'
import '@fontsource-variable/jetbrains-mono'

/**
 * Helios' visual base — solar observatory.
 *
 * Direction: this project's own vernacular is astronomical. The gateway is
 * Helios, the client is Orion, the mark is a solar disk crossed by an orbital
 * trajectory. So the console is dressed as **mission control**: an indigo
 * night, instrument panels raised out of it, and the sun's own spectrum —
 * gold, flare orange — carrying the brand.
 *
 * This replaces a first attempt built on Orion's doctrine, "color is rare,
 * therefore it means something". That doctrine is right for Orion, which has
 * one thing to say. Helios has forty readings on screen at once, and a palette
 * that spends nothing on them produces no hierarchy at all: three surface
 * levels within three percent of each other, and every panel the same warm
 * beige. Here color is **structural**. It separates surfaces, groups readings,
 * and only then states security facts.
 *
 * Three families, and they never borrow from one another:
 *
 * - **Brand** (`primary` gold, `secondary` flare) — the sun. Navigation,
 *   primary actions, focus. It decorates and it orients.
 * - **Crypto** (`tertiary`, plasma violet) — everything post-quantum:
 *   negotiation floors, occupied PSK slots, ML-KEM. Its own axis, because
 *   "this peer is protected by ML-KEM" is not the same claim as "traffic is
 *   flowing right now".
 * - **State** (`palette.state`) — the security fact. Jade, sky, slate, rose,
 *   amber. `state.ts` owns the meaning; this file only owns the pigment.
 *
 * The navigation rail keeps its night colors in **both** schemes. It is the
 * one fixed instrument in the interface, it carries the mark, and holding it
 * constant is what gives the light scheme a spine instead of leaving it a pale
 * field of panels.
 */

const DISPLAY_FONT =
  '"Space Grotesk Variable", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif'
const MONO_FONT = '"JetBrains Mono Variable", "Cascadia Code", Consolas, ui-monospace, monospace'

/**
 * MD3 emphasized easing — leaves fast, settles slowly. Reserved for what
 * changes meaning (state transitions, the rail indicator), never for hovers.
 */
export const EMPHASIZED = 'cubic-bezier(0.2, 0, 0, 1)'

/** Shared gutter, in MUI spacing units (3 = 24 px). */
export const GUTTER = 3

/** Corner radius of a content card. */
export const CARD_RADIUS = 18

/** Width of the navigation rail, labels included. */
export const RAIL_WIDTH = 92

declare module '@mui/material/styles' {
  /**
   * Tells TypeScript that this theme is built with CSS variables, which is
   * what puts `theme.vars` and `theme.colorSchemes` on the `Theme` type.
   * Without it `cssVariables` still works at runtime and the types silently
   * pretend there is a single scheme.
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
   * MD3 gives every accent a container pair. MUI's palette stops at
   * main/light/dark, so the pair is added here — without it a tinted surface
   * has to be improvised out of translucent overlays, which stack badly and
   * lose contrast in exactly one of the two schemes.
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

  /** The night spine — identical in both schemes, on purpose. */
  interface RailPalette {
    bg: string
    border: string
    text: string
    textActive: string
    indicator: string
  }

  interface Palette {
    state: StatePalette
    rail: RailPalette
    /** Plasma violet: the post-quantum axis. Never a state, never a brand. */
    tertiary: { main: string; container: string; onContainer: string }
    /** Elevation expressed as tone: the ladder every surface sits on. */
    surfaceContainer: {
      lowest: string
      low: string
      main: string
      high: string
      highest: string
    }
  }

  interface PaletteOptions {
    state?: StatePalette
    rail?: RailPalette
    tertiary?: Palette['tertiary']
    surfaceContainer?: Palette['surfaceContainer']
  }
}

/**
 * The rail's night, held constant across schemes.
 *
 * A rail that follows the light scheme disappears into the page, and the
 * console loses the one element that says which product this is before a word
 * is read.
 */
const RAIL: import('@mui/material/styles').RailPalette = {
  bg: '#080C18',
  border: '#1C2740',
  text: '#8C9DC4',
  textActive: '#FFC24B',
  indicator: '#2C2209',
}

const DARK_STATE = {
  up: { main: '#2BD48A', container: '#05331F', onContainer: '#A5F3D0' },
  connecting: { main: '#4FC3F7', container: '#08283C', onContainer: '#BFE7FB' },
  down: { main: '#8494B8', container: '#161E32', onContainer: '#C3CFE6' },
  failed: { main: '#FF5C7A', container: '#3D0D1A', onContainer: '#FFC9D3' },
  captivePortal: { main: '#FFA53D', container: '#3D2405', onContainer: '#FFD9AC' },
} as const

const LIGHT_STATE = {
  up: { main: '#067A4E', container: '#C7F2DF', onContainer: '#00301C' },
  connecting: { main: '#0369A1', container: '#D2EBFB', onContainer: '#002438' },
  down: { main: '#5A6B90', container: '#E2E8F5', onContainer: '#1B2540' },
  failed: { main: '#C62A46', container: '#FFD9E0', onContainer: '#40000D' },
  captivePortal: { main: '#A15C00', container: '#FFE1BC', onContainer: '#2E1900' },
} as const

export const heliosTheme = createTheme({
  cssVariables: { colorSchemeSelector: 'data' },
  colorSchemes: {
    dark: {
      palette: {
        mode: 'dark',
        primary: {
          main: '#FFC24B',
          light: '#FFD98A',
          dark: '#C4900F',
          contrastText: '#2A1B00',
          container: '#4A3208',
          onContainer: '#FFDFA0',
        },
        secondary: {
          main: '#FF8A4C',
          light: '#FFAE83',
          dark: '#C25A22',
          contrastText: '#3A1503',
          container: '#4D2510',
          onContainer: '#FFD3BC',
        },
        tertiary: { main: '#A48BFF', container: '#2E2461', onContainer: '#DDD2FF' },
        success: { main: '#2BD48A', contrastText: '#00301C', container: '#05331F', onContainer: '#A5F3D0' },
        warning: { main: '#FFA53D', contrastText: '#3D2405', container: '#3D2405', onContainer: '#FFD9AC' },
        error: { main: '#FF5C7A', contrastText: '#3D0D1A', container: '#3D0D1A', onContainer: '#FFC9D3' },
        info: { main: '#4FC3F7', contrastText: '#08283C', container: '#08283C', onContainer: '#BFE7FB' },
        background: {
          default: '#0A0E1C',
          paper: '#101728',
        },
        text: {
          primary: '#E8EEFF',
          secondary: '#9FB0D4',
          disabled: '#6B7CA3',
        },
        divider: '#27324F',
        state: DARK_STATE,
        rail: RAIL,
        surfaceContainer: {
          lowest: '#060911',
          low: '#101728',
          main: '#16203A',
          high: '#1D2949',
          highest: '#253258',
        },
      },
    },
    light: {
      palette: {
        mode: 'light',
        primary: {
          main: '#A96A00',
          light: '#D08A10',
          dark: '#7A4C00',
          contrastText: '#FFFFFF',
          container: '#FFE1A8',
          onContainer: '#3A2400',
        },
        secondary: {
          main: '#C2410C',
          light: '#E4632B',
          dark: '#8F2F06',
          contrastText: '#FFFFFF',
          container: '#FFDCC7',
          onContainer: '#431407',
        },
        tertiary: { main: '#5B45D6', container: '#E4DDFF', onContainer: '#1E1060' },
        success: { main: '#067A4E', contrastText: '#FFFFFF', container: '#C7F2DF', onContainer: '#00301C' },
        warning: { main: '#A15C00', contrastText: '#FFFFFF', container: '#FFE1BC', onContainer: '#2E1900' },
        error: { main: '#C62A46', contrastText: '#FFFFFF', container: '#FFD9E0', onContainer: '#40000D' },
        info: { main: '#0369A1', contrastText: '#FFFFFF', container: '#D2EBFB', onContainer: '#002438' },
        background: {
          default: '#EDF1FA',
          paper: '#FFFFFF',
        },
        text: {
          primary: '#0C1426',
          secondary: '#4C5B7D',
          disabled: '#8593B3',
        },
        divider: '#D3DCEF',
        state: LIGHT_STATE,
        rail: RAIL,
        surfaceContainer: {
          lowest: '#FFFFFF',
          low: '#FFFFFF',
          main: '#F4F7FD',
          high: '#E9EFFA',
          highest: '#DDE6F7',
        },
      },
    },
  },
  shape: {
    borderRadius: 12,
  },
  typography: {
    fontFamily: DISPLAY_FONT,
    h1: { fontSize: '2.5rem', fontWeight: 600, lineHeight: 1.15, letterSpacing: '-0.025em' },
    h2: { fontSize: '2rem', fontWeight: 600, lineHeight: 1.2, letterSpacing: '-0.022em' },
    // The heading of a view.
    h3: { fontSize: '1.6875rem', fontWeight: 600, lineHeight: 1.2, letterSpacing: '-0.02em' },
    // The headline of a hero panel.
    h4: { fontSize: '1.5rem', fontWeight: 600, lineHeight: 1.2, letterSpacing: '-0.018em' },
    h5: { fontSize: '1.125rem', fontWeight: 600, lineHeight: 1.35, letterSpacing: '-0.01em' },
    // The title of a card.
    h6: { fontSize: '0.9375rem', fontWeight: 600, lineHeight: 1.4, letterSpacing: '-0.005em' },
    body1: { fontSize: '0.9375rem', lineHeight: 1.55 },
    body2: { fontSize: '0.8125rem', lineHeight: 1.55 },
    button: {
      fontSize: '0.8125rem',
      fontWeight: 600,
      letterSpacing: '0.01em',
      textTransform: 'none',
    },
    caption: { fontSize: '0.75rem', lineHeight: 1.45 },
    // The "instrument" voice: monospace capitals, widely spaced. It labels
    // data, it never states it.
    overline: {
      fontFamily: MONO_FONT,
      fontSize: '0.6875rem',
      fontWeight: 600,
      letterSpacing: '0.13em',
      lineHeight: 1.5,
      textTransform: 'uppercase',
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
          WebkitFontSmoothing: 'antialiased',
          textRendering: 'optimizeLegibility',
        },
        'button, input, textarea, select': {
          font: 'inherit',
        },
        'code, pre, kbd, samp': {
          fontFamily: MONO_FONT,
        },
        // Inline code runs through this interface's prose constantly — file
        // names, commands, ports. It needs to be picked out of a sentence
        // without breaking the line's rhythm, hence a tint, not a border.
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
      styleOverrides: {
        root: { backgroundImage: 'none' },
      },
    },
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: {
        root: {
          borderRadius: 999,
          minHeight: 40,
          paddingInline: 20,
          '&.Mui-focusVisible': {
            outline: '2px solid var(--mui-palette-primary-main)',
            outlineOffset: 2,
          },
        },
        sizeSmall: { minHeight: 32, paddingInline: 14 },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          '&.Mui-focusVisible': {
            outline: '2px solid var(--mui-palette-primary-main)',
            outlineOffset: 2,
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { borderRadius: 7, fontWeight: 600 },
        label: { paddingInline: 9 },
      },
    },
    MuiTooltip: {
      defaultProps: { arrow: true, enterDelay: 400 },
      styleOverrides: {
        tooltip: {
          fontSize: '0.75rem',
          lineHeight: 1.45,
          padding: '8px 12px',
          maxWidth: 340,
          backgroundColor: 'var(--mui-palette-surfaceContainer-highest)',
          color: 'var(--mui-palette-text-primary)',
          border: '1px solid var(--mui-palette-divider)',
        },
        arrow: { color: 'var(--mui-palette-surfaceContainer-highest)' },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          backgroundColor: 'var(--mui-palette-surfaceContainer-main)',
        },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: { borderRadius: 999, height: 6 },
      },
    },
    MuiSkeleton: {
      styleOverrides: {
        root: { backgroundColor: 'var(--mui-palette-surfaceContainer-high)' },
      },
    },
  },
})

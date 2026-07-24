import { createTheme } from '@mui/material/styles'

const SYSTEM_FONT =
  'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
const MONO_FONT =
  '"Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, ui-monospace, monospace'

/**
 * Socle visuel d’Orion — « encre & pin ».
 *
 * Parti pris : **la couleur est rare, donc elle signifie**. Orion n’a qu’un seul
 * message à faire passer — le trafic est-il protégé — et `components/state.ts`
 * encode cette réponse par une couleur. Une interface qui colore aussi ses
 * en-têtes, ses onglets et ses accents noie ce signal parmi les décorations.
 *
 * D’où un fond papier, une typographie encre, et le vert pin réservé à deux
 * emplois : l’action principale et l’état protégé. Tout le reste est neutre.
 *
 * Corollaire : les couleurs d’état ne sont PAS dérivées de ce thème. Elles
 * vivent dans `state.ts` parce qu’elles portent un sens de sécurité, pas une
 * intention esthétique.
 */

/** Fond papier — blanc froid, délibérément pas crème. */
export const PAPER = '#FBFCFB'
/** Texte principal : un noir teinté vert, qui rattache la typo à la marque. */
export const INK = '#10231C'
/** Texte secondaire. */
export const GRAPHITE = '#5A6B65'
/** Texte tertiaire — jamais porteur d’information critique. */
export const SLATE = '#8A9691'
/** Filets et séparateurs. */
export const RULE = '#E2E8E5'
/** Le vert de la marque : action principale et état protégé, rien d’autre. */
export const PINE = '#0B6B4E'
/**
 * Vert vif — **graphiques seulement**. Il ne tient pas le ratio AA sur papier,
 * donc il n’énonce jamais : il éclaire (orbe, pastilles, courbes, liserés).
 */
export const EMERALD = '#12B981'
/** Seule surface teintée de l’interface. */
export const MINT = '#E3F6EE'

/**
 * Gouttière commune, en unités d’espacement MUI (2 = 16 px).
 *
 * En-tête, navigation et contenu s’alignent tous dessus. Une vue qui choisirait
 * sa propre valeur décalerait son texte au changement d’onglet — le défaut le
 * plus visible d’une IHM à plusieurs vues, et le plus facile à laisser filer.
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
    // La voix « instrument » : capitales étroites en chasse fixe, très espacées.
    // Elle sert à étiqueter les données, jamais à les énoncer.
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
          // Aucune vue ne défile : la fenêtre est dimensionnée pour son contenu.
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

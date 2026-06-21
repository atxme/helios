import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import { useMemo, useRef } from 'react'
import * as THREE from 'three'

// ─── Palette + direction artistique par thème ────────────────────────────────
// Sombre = espace profond néon (blending additif + bloom).
// Clair  = ciel diurne, réseau dessiné à l'encre saturée (blending normal, pas
//          de bloom) → lisible et élégant. Le soleil reste ambre : ADN Helios.
type Pal = {
  bg: string
  node: string; flux: string; line: string
  sun: string; corona: string; sunGlow: number
  ring: string; ringOpacity: number
  wire: string; wireOpacity: number
  stars: number; starColor: string
  bloom: number; useBloom: boolean
  blending: THREE.Blending
  lineOpacity: number; nodeRadius: number
  fogNear: number; fogFar: number
}

const PALETTE: Record<'dark' | 'light', Pal> = {
  dark: {
    bg: '#03060f',
    node: '#22d3ee', flux: '#e879f9', line: '#22d3ee',
    sun: '#ffc233', corona: '#f59e0b', sunGlow: 0.6,
    ring: '#fcd34d', ringOpacity: 0.6,
    wire: '#22d3ee', wireOpacity: 0.05,
    stars: 1500, starColor: '#cfe0ff',
    bloom: 1.2, useBloom: true,
    blending: THREE.AdditiveBlending,
    lineOpacity: 0.3, nodeRadius: 0.1,
    fogNear: 18, fogFar: 72,
  },
  light: {
    bg: '#dce7fa',
    node: '#0e7490', flux: '#9333ea', line: '#0f766e',
    sun: '#f59e0b', corona: '#fb923c', sunGlow: 0.5,
    // Anneaux ambre foncé en blending normal → visibles et nets sur ciel clair.
    ring: '#b45309', ringOpacity: 0.72,
    wire: '#1e3a8a', wireOpacity: 0.07,
    stars: 0, starColor: '#ffffff',
    bloom: 0, useBloom: false,
    blending: THREE.NormalBlending,
    lineOpacity: 0.5, nodeRadius: 0.14,
    fogNear: 30, fogFar: 95,
  },
}

// Texture de halo radial doux (couronne solaire + sprites d'étoiles).
function useGlowTexture() {
  return useMemo(() => {
    const size = 128
    const c = document.createElement('canvas')
    c.width = c.height = size
    const ctx = c.getContext('2d')!
    const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2)
    g.addColorStop(0, 'rgba(255,255,255,1)')
    g.addColorStop(0.18, 'rgba(255,255,255,0.7)')
    g.addColorStop(0.45, 'rgba(255,255,255,0.25)')
    g.addColorStop(1, 'rgba(255,255,255,0)')
    ctx.fillStyle = g
    ctx.fillRect(0, 0, size, size)
    return new THREE.CanvasTexture(c)
  }, [])
}

const SUN_POS: [number, number, number] = [17, 6, -14]

// ─── Le Soleil — astre ambre + couronne + anneaux orbitaux ────────────────────
function Sun({ pal }: { pal: Pal }) {
  const glow = useGlowTexture()
  const coronaRef = useRef<THREE.Group>(null)
  const ringsRef = useRef<THREE.Group>(null)

  useFrame((_, dt) => {
    if (coronaRef.current) coronaRef.current.rotation.z += dt * 0.02
    if (ringsRef.current) ringsRef.current.rotation.z += dt * 0.06
  })

  return (
    <group position={SUN_POS}>
      {/* Cœur lumineux */}
      <mesh>
        <sphereGeometry args={[3.4, 48, 48]} />
        <meshBasicMaterial color={pal.sun} toneMapped={false} />
      </mesh>

      {/* Couronne — deux couches */}
      <group ref={coronaRef}>
        <sprite scale={[20, 20, 1]}>
          <spriteMaterial map={glow} color={pal.corona} transparent opacity={pal.sunGlow}
            blending={pal.blending} depthWrite={false} toneMapped={false} />
        </sprite>
        <sprite scale={[42, 42, 1]}>
          <spriteMaterial map={glow} color={pal.corona} transparent opacity={pal.sunGlow * 0.45}
            blending={pal.blending} depthWrite={false} toneMapped={false} />
        </sprite>
      </group>

      {/* Anneaux orbitaux — système incliné cohérent (type Saturne) */}
      <group ref={ringsRef} rotation={[Math.PI / 2.45, 0.18, 0]}>
        {[5.2, 6.0, 6.9, 8.1, 9.4].map((r, i) => (
          <mesh key={i}>
            <torusGeometry args={[r, 0.03, 12, 200]} />
            <meshBasicMaterial color={pal.ring} transparent
              opacity={pal.ringOpacity * (1 - i * 0.13)}
              blending={pal.blending} depthWrite={false} toneMapped={false} />
          </mesh>
        ))}
      </group>
    </group>
  )
}

// ─── Dôme géodésique filaire englobant — « champ de confinement » ─────────────
function WireDome({ pal }: { pal: Pal }) {
  const ref = useRef<THREE.Mesh>(null)
  useFrame((_, dt) => {
    if (ref.current) {
      ref.current.rotation.y += dt * 0.012
      ref.current.rotation.x += dt * 0.005
    }
  })
  return (
    <mesh ref={ref}>
      <icosahedronGeometry args={[17, 2]} />
      <meshBasicMaterial color={pal.wire} wireframe transparent opacity={pal.wireOpacity}
        blending={pal.blending} depthWrite={false} toneMapped={false} />
    </mesh>
  )
}

// ─── Champ d'étoiles maison (fog désactivé → pas d'artefacts de blobs) ────────
function Starfield({ pal }: { pal: Pal }) {
  const glow = useGlowTexture()
  const positions = useMemo(() => {
    const a = new Float32Array(pal.stars * 3)
    for (let i = 0; i < pal.stars; i++) {
      const r = 55 + Math.random() * 45
      const t = Math.random() * Math.PI * 2
      const p = Math.acos(2 * Math.random() - 1)
      a[i * 3] = r * Math.sin(p) * Math.cos(t)
      a[i * 3 + 1] = r * Math.sin(p) * Math.sin(t)
      a[i * 3 + 2] = r * Math.cos(p)
    }
    return a
  }, [pal.stars])

  if (pal.stars === 0) return null
  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} count={pal.stars} />
      </bufferGeometry>
      <pointsMaterial size={0.7} map={glow} color={pal.starColor} transparent opacity={0.9}
        sizeAttenuation depthWrite={false} blending={THREE.AdditiveBlending} fog={false} toneMapped={false} />
    </points>
  )
}

// ─── Le réseau — nœuds instanciés (cyan/magenta) + liens entre voisins ────────
const NODE_COUNT = 250

function Network({ pal }: { pal: Pal }) {
  const meshRef = useRef<THREE.InstancedMesh>(null)
  const groupRef = useRef<THREE.Group>(null)

  const { positions, colors, linePositions } = useMemo(() => {
    const pts: THREE.Vector3[] = []
    for (let i = 0; i < NODE_COUNT; i++) {
      pts.push(new THREE.Vector3(
        (Math.random() - 0.5) * 52,
        (Math.random() - 0.5) * 34,
        (Math.random() - 0.5) * 24,
      ))
    }

    const cNode = new THREE.Color(pal.node)
    const cFlux = new THREE.Color(pal.flux)
    const colors = new Float32Array(NODE_COUNT * 3)
    pts.forEach((_, i) => {
      const c = Math.random() < 0.22 ? cFlux : cNode
      colors[i * 3] = c.r; colors[i * 3 + 1] = c.g; colors[i * 3 + 2] = c.b
    })

    const segs: number[] = []
    const MAX_DIST = 9
    const MAX_LINKS = 3
    for (let i = 0; i < pts.length; i++) {
      let links = 0
      for (let j = i + 1; j < pts.length && links < MAX_LINKS; j++) {
        if (pts[i].distanceTo(pts[j]) < MAX_DIST) {
          segs.push(pts[i].x, pts[i].y, pts[i].z, pts[j].x, pts[j].y, pts[j].z)
          links++
        }
      }
    }
    return { positions: pts, colors, linePositions: new Float32Array(segs) }
  }, [pal.node, pal.flux])

  const dummy = useMemo(() => new THREE.Object3D(), [])

  useFrame((state) => {
    const t = state.clock.elapsedTime
    if (groupRef.current) {
      groupRef.current.rotation.y = t * 0.018
      groupRef.current.position.y = Math.sin(t * 0.25) * 0.6
    }
    const mesh = meshRef.current
    if (mesh) {
      positions.forEach((p, i) => {
        dummy.position.set(p.x, p.y + Math.sin(t * 0.6 + i) * 0.18, p.z)
        const s = 0.85 + Math.sin(t * 1.4 + i * 2.1) * 0.15
        dummy.scale.setScalar(s)
        dummy.updateMatrix()
        mesh.setMatrixAt(i, dummy.matrix)
      })
      mesh.instanceMatrix.needsUpdate = true
    }
  })

  return (
    <group ref={groupRef}>
      <lineSegments>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position"
            args={[linePositions, 3]} count={linePositions.length / 3} />
        </bufferGeometry>
        <lineBasicMaterial color={pal.line} transparent opacity={pal.lineOpacity}
          toneMapped={false} blending={pal.blending} depthWrite={false} />
      </lineSegments>

      <instancedMesh ref={meshRef} args={[undefined, undefined, NODE_COUNT]}>
        <icosahedronGeometry args={[pal.nodeRadius, 1]} />
        <meshBasicMaterial toneMapped={false} blending={pal.blending} transparent
          opacity={pal.useBloom ? 1 : 0.95} />
        <instancedBufferAttribute attach="instanceColor" args={[colors, 3]} />
      </instancedMesh>
    </group>
  )
}

// Léger flottement de caméra pour donner vie à la scène.
function CameraDrift() {
  const { camera } = useThree()
  useFrame((state) => {
    const t = state.clock.elapsedTime
    camera.position.x = Math.sin(t * 0.08) * 1.4
    camera.position.y = Math.cos(t * 0.06) * 0.9
    camera.lookAt(0, 0, 0)
  })
  return null
}

function Scene({ dark }: { dark: boolean }) {
  const pal = dark ? PALETTE.dark : PALETTE.light
  return (
    <>
      <color attach="background" args={[pal.bg]} />
      <fog attach="fog" args={[pal.bg, pal.fogNear, pal.fogFar]} />
      <Starfield pal={pal} />
      <WireDome pal={pal} />
      <Sun pal={pal} />
      <Network pal={pal} />
      <CameraDrift />
      {pal.useBloom && (
        <EffectComposer>
          <Bloom luminanceThreshold={0.15} mipmapBlur intensity={pal.bloom} radius={0.72} />
        </EffectComposer>
      )}
    </>
  )
}

// Module lourd (three.js) — chargé en lazy par Background.tsx.
export default function BackgroundScene({ dark }: { dark: boolean }) {
  return (
    <div className="fixed inset-0" style={{ zIndex: 0 }}>
      <Canvas
        dpr={[1, 1.6]}
        camera={{ position: [0, 0, 26], fov: 60 }}
        gl={{ antialias: false, powerPreference: 'high-performance' }}
        style={{ width: '100%', height: '100%' }}
      >
        <Scene dark={dark} />
      </Canvas>
    </div>
  )
}

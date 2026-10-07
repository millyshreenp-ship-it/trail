import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';

export type Led = 'blue' | 'amber' | 'green' | 'red';
export interface DeviceVisual { lines: string[]; progress: number; led: Led }
export interface SceneProps {
  visual: DeviceVisual;
  phoneLines: string[];
  internals: boolean;
  transit: boolean;
  pressed: boolean;
  resetSignal: number;
  onButton: (down: boolean) => void;
  onUnavailable: () => void;
}

const LED: Record<Led, number> = { blue: 0x4aa8ff, amber: 0xffb02e, green: 0x2fe08a, red: 0xff4d4d };
const FRONT = 0.22;
const BUTTON_X = 1.02;

function canvasOf(width: number, height: number) {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  return { canvas, ctx: canvas.getContext('2d')! };
}

function texture(canvas: HTMLCanvasElement) {
  const map = new THREE.CanvasTexture(canvas);
  map.colorSpace = THREE.SRGBColorSpace;
  map.anisotropy = 8;
  return map;
}

function roundedRect(width: number, height: number, radius: number) {
  const shape = new THREE.Shape();
  const x = -width / 2;
  const y = -height / 2;
  shape.moveTo(x + radius, y);
  shape.lineTo(x + width - radius, y);
  shape.quadraticCurveTo(x + width, y, x + width, y + radius);
  shape.lineTo(x + width, y + height - radius);
  shape.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
  shape.lineTo(x + radius, y + height);
  shape.quadraticCurveTo(x, y + height, x, y + height - radius);
  shape.lineTo(x, y + radius);
  shape.quadraticCurveTo(x, y, x + radius, y);
  return shape;
}

function slab(width: number, height: number, radius: number, depth: number, bevel: number) {
  const geometry = new THREE.ExtrudeGeometry(roundedRect(width, height, radius), { depth, bevelEnabled: true, bevelThickness: bevel, bevelSize: bevel, bevelSegments: 5, curveSegments: 18 });
  geometry.translate(0, 0, -depth / 2);
  return geometry;
}

// Mirrors show() on the board: 21 columns by 4 lines on a 128x64 panel.
function drawOled(ctx: CanvasRenderingContext2D, lines: string[], progress: number) {
  ctx.fillStyle = '#020709';
  ctx.fillRect(0, 0, 256, 128);
  ctx.fillStyle = '#c9ecff';
  ctx.font = '18px "Courier New", monospace';
  lines.slice(0, 4).forEach((line, index) => ctx.fillText(line.slice(0, 21), 6, 22 + index * 26));
  if (progress > 0) {
    ctx.strokeStyle = '#c9ecff';
    ctx.strokeRect(6.5, 108.5, 243, 12);
    ctx.fillRect(9, 111, Math.round(238 * progress), 7);
  }
  ctx.fillStyle = 'rgba(120,190,255,0.07)';
  for (let y = 0; y < 128; y += 4) ctx.fillRect(0, y, 256, 1);
}

function drawPhone(ctx: CanvasRenderingContext2D, lines: string[]) {
  ctx.fillStyle = '#f4f6f2';
  ctx.fillRect(0, 0, 276, 560);
  ctx.fillStyle = '#14795c';
  ctx.fillRect(0, 0, 276, 64);
  ctx.fillStyle = '#ffffff';
  ctx.font = '600 22px sans-serif';
  ctx.fillText('Banking app', 18, 40);
  ctx.fillStyle = '#202b27';
  lines.slice(0, 3).forEach((line, index) => {
    ctx.font = index === 0 ? '600 21px sans-serif' : '19px sans-serif';
    ctx.fillText(line, 18, 130 + index * 44);
  });
  ctx.fillStyle = '#14795c';
  ctx.fillRect(18, 300, 240, 56);
  ctx.fillStyle = '#ffffff';
  ctx.font = '600 20px sans-serif';
  ctx.fillText('Confirm', 98, 336);
  ctx.fillStyle = '#a73c3c';
  ctx.fillRect(0, 496, 276, 64);
  ctx.fillStyle = '#ffffff';
  ctx.font = '600 16px sans-serif';
  ctx.fillText('Remote screen session active', 14, 534);
}

function label(text: string) {
  const { canvas, ctx } = canvasOf(256, 64);
  ctx.fillStyle = 'rgba(255,255,255,0.94)';
  ctx.strokeStyle = '#14795c';
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.roundRect(3, 3, 250, 58, 12);
  ctx.fill();
  ctx.stroke();
  ctx.fillStyle = '#202b27';
  ctx.font = '600 25px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, 128, 34);
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture(canvas), depthTest: false, transparent: true }));
  sprite.scale.set(1.05, 0.26, 1);
  sprite.renderOrder = 20;
  return sprite;
}

type Disposable = { geometry?: THREE.BufferGeometry; material?: THREE.Material | THREE.Material[] };

export default function HardwareScene(props: SceneProps) {
  const host = useRef<HTMLDivElement>(null);
  const latest = useRef(props);
  latest.current = props;
  const handles = useRef<{ drawDevice: () => void; drawPhoneScreen: () => void; reset: () => void } | null>(null);

  useEffect(() => {
    const container = host.current!;
    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      latest.current.onUnavailable();
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    renderer.domElement.setAttribute('aria-hidden', 'true');
    container.appendChild(renderer.domElement);
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(35, 1.6, 0.1, 60);
    const target = new THREE.Vector3(-1.1, 0, 0);
    const home = new THREE.Vector3(-0.9, 0.8, 8.1);
    camera.position.copy(home);

    scene.add(new THREE.HemisphereLight(0xffffff, 0x9fb3a8, 1.1));
    const key = new THREE.DirectionalLight(0xffffff, 2.2);
    key.position.set(3, 5, 6);
    key.castShadow = true;
    key.shadow.mapSize.set(1024, 1024);
    key.shadow.camera.left = -6;
    key.shadow.camera.right = 6;
    key.shadow.camera.top = 6;
    key.shadow.camera.bottom = -6;
    scene.add(key);
    const rim = new THREE.DirectionalLight(0x9fe3c4, 1.1);
    rim.position.set(-4, 2, -3);
    scene.add(rim);

    const ground = new THREE.Mesh(new THREE.PlaneGeometry(14, 8), new THREE.ShadowMaterial({ opacity: 0.16 }));
    ground.rotation.x = -Math.PI / 2;
    ground.position.set(-1.1, -1.75, 0);
    ground.receiveShadow = true;
    scene.add(ground);

    // EarlyTrace Key
    const device = new THREE.Group();
    device.rotation.set(-0.22, 0.38, 0.03);
    scene.add(device);
    const shellMaterial = new THREE.MeshPhysicalMaterial({ color: 0x1f2b27, roughness: 0.42, metalness: 0.12, clearcoat: 0.35, transparent: true });
    const shell = new THREE.Mesh(slab(3.1, 1.7, 0.3, 0.34, 0.05), shellMaterial);
    shell.castShadow = true;
    device.add(shell);

    const oled = canvasOf(256, 128);
    const oledMap = texture(oled.canvas);
    const glass = new THREE.Mesh(new THREE.PlaneGeometry(1.42, 0.76), new THREE.MeshStandardMaterial({ color: 0x050808, roughness: 0.15, metalness: 0.4 }));
    glass.position.set(-0.4, 0.02, FRONT + 0.004);
    const screen = new THREE.Mesh(new THREE.PlaneGeometry(1.14, 0.57), new THREE.MeshBasicMaterial({ map: oledMap, toneMapped: false }));
    screen.position.set(-0.4, 0.02, FRONT + 0.008);
    device.add(glass, screen);

    const buttonBase = new THREE.Mesh(new THREE.TorusGeometry(0.235, 0.04, 14, 40), new THREE.MeshStandardMaterial({ color: 0x3b4b44, roughness: 0.4, metalness: 0.5 }));
    buttonBase.position.set(BUTTON_X, -0.12, FRONT + 0.01);
    const buttonMaterial = new THREE.MeshStandardMaterial({ color: 0xe9eee8, roughness: 0.35, metalness: 0.1, emissive: 0x0e5a3f, emissiveIntensity: 0 });
    const button = new THREE.Mesh(new THREE.CylinderGeometry(0.19, 0.2, 0.12, 40), buttonMaterial);
    button.rotation.x = Math.PI / 2;
    button.position.set(BUTTON_X, -0.12, FRONT + 0.07);
    button.castShadow = true;
    const hit = new THREE.Mesh(new THREE.CylinderGeometry(0.34, 0.34, 0.3, 24), new THREE.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false }));
    hit.rotation.x = Math.PI / 2;
    hit.position.set(BUTTON_X, -0.12, FRONT + 0.1);
    device.add(buttonBase, button, hit);
    let ring = new THREE.Mesh(new THREE.RingGeometry(0.27, 0.32, 8), new THREE.MeshBasicMaterial({ color: 0x2fe08a, side: THREE.DoubleSide }));
    ring.position.set(BUTTON_X, -0.12, FRONT + 0.03);
    ring.visible = false;
    device.add(ring);

    const ledMaterial = new THREE.MeshStandardMaterial({ color: LED.blue, emissive: LED.blue, emissiveIntensity: 1.2 });
    const led = new THREE.Mesh(new THREE.SphereGeometry(0.055, 16, 12), ledMaterial);
    led.position.set(BUTTON_X, 0.5, FRONT + 0.02);
    device.add(led);

    const port = new THREE.Mesh(new THREE.BoxGeometry(0.14, 0.4, 0.17), new THREE.MeshStandardMaterial({ color: 0xc9d1cc, roughness: 0.25, metalness: 0.9 }));
    port.position.set(-1.58, 0, 0);
    const portCore = new THREE.Mesh(new THREE.BoxGeometry(0.15, 0.3, 0.07), new THREE.MeshStandardMaterial({ color: 0x050707 }));
    portCore.position.set(-1.585, 0, 0);
    device.add(port, portCore);

    const loop = new THREE.Mesh(new THREE.TorusGeometry(0.2, 0.035, 12, 36), new THREE.MeshStandardMaterial({ color: 0xcfd6d2, roughness: 0.2, metalness: 0.95 }));
    loop.position.set(1.62, 0.72, 0);
    loop.rotation.set(0.5, 0.9, 0);
    device.add(loop);

    // Internals revealed when the shell fades.
    const internals = new THREE.Group();
    internals.visible = false;
    const pcb = new THREE.Mesh(new THREE.BoxGeometry(2.8, 1.38, 0.05), new THREE.MeshStandardMaterial({ color: 0x1f6a4e, roughness: 0.6 }));
    const module = new THREE.Mesh(new THREE.BoxGeometry(0.8, 0.52, 0.07), new THREE.MeshStandardMaterial({ color: 0xbfc7c2, metalness: 0.8, roughness: 0.3 }));
    module.position.set(0.5, -0.3, 0.06);
    const antenna = new THREE.Mesh(new THREE.BoxGeometry(0.8, 0.16, 0.05), new THREE.MeshStandardMaterial({ color: 0x141b18 }));
    antenna.position.set(0.5, 0.06, 0.05);
    const oledBoard = new THREE.Mesh(new THREE.BoxGeometry(1.5, 0.8, 0.06), new THREE.MeshStandardMaterial({ color: 0x143b4a, roughness: 0.5 }));
    oledBoard.position.set(-0.4, 0.02, 0.1);
    const tact = new THREE.Mesh(new THREE.BoxGeometry(0.26, 0.26, 0.1), new THREE.MeshStandardMaterial({ color: 0x232a27 }));
    tact.position.set(BUTTON_X, -0.12, 0.08);
    internals.add(pcb, module, antenna, oledBoard, tact);
    const labels: [string, number, number, number][] = [['ESP32-C3 module', 0.5, -0.75, 0.2], ['128x64 OLED', -0.4, 0.62, 0.3], ['Tactile switch', BUTTON_X, -0.62, 0.3], ['USB-C', -1.55, -0.45, 0.2]];
    labels.forEach(([text, x, y, z]) => { const sprite = label(text); sprite.position.set(x, y, z); internals.add(sprite); });
    device.add(internals);

    // Phone with a compromised session, for contrast.
    const phone = new THREE.Group();
    phone.position.set(-3.5, -0.1, -0.5);
    phone.rotation.set(-0.1, 0.55, 0.02);
    const phoneBody = new THREE.Mesh(slab(1.55, 3.0, 0.26, 0.12, 0.03), new THREE.MeshPhysicalMaterial({ color: 0x151c1a, roughness: 0.35, metalness: 0.3, clearcoat: 0.4 }));
    phoneBody.castShadow = true;
    const phoneCanvas = canvasOf(276, 560);
    const phoneMap = texture(phoneCanvas.canvas);
    const phoneScreen = new THREE.Mesh(new THREE.PlaneGeometry(1.4, 2.84), new THREE.MeshBasicMaterial({ map: phoneMap, toneMapped: false }));
    phoneScreen.position.z = 0.092;
    phone.add(phoneBody, phoneScreen);
    scene.add(phone);

    // BLE / USB path between the bridge and the key.
    const linkPoints = [new THREE.Vector3(-2.8, 0.35, -0.2), new THREE.Vector3(-1.9, 0.9, 0.3), new THREE.Vector3(-1.2, 0.2, 0.3)];
    const linkGeometry = new THREE.BufferGeometry().setFromPoints(new THREE.CatmullRomCurve3(linkPoints).getPoints(40));
    const link = new THREE.Line(linkGeometry, new THREE.LineDashedMaterial({ color: 0x14795c, dashSize: 0.12, gapSize: 0.08 }));
    link.computeLineDistances();
    link.visible = false;
    scene.add(link);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.target.copy(target);
    controls.enablePan = false;
    controls.enableDamping = true;
    controls.minDistance = 4.5;
    controls.maxDistance = 14;
    controls.minPolarAngle = 0.6;
    controls.maxPolarAngle = 1.75;

    // Capture phase, so a press on the button pre-empts OrbitControls' own drag handling.
    const raycaster = new THREE.Raycaster();
    const pointer = new THREE.Vector2();
    let holding = false;
    const overButton = (event: PointerEvent) => {
      const rect = renderer.domElement.getBoundingClientRect();
      pointer.set(((event.clientX - rect.left) / rect.width) * 2 - 1, -((event.clientY - rect.top) / rect.height) * 2 + 1);
      raycaster.setFromCamera(pointer, camera);
      return raycaster.intersectObject(hit, false).length > 0;
    };
    const down = (event: PointerEvent) => {
      if (!overButton(event)) return;
      event.stopImmediatePropagation();
      try { renderer.domElement.setPointerCapture(event.pointerId); } catch { /* released pointer */ }
      holding = true;
      latest.current.onButton(true);
    };
    const up = () => { if (holding) { holding = false; latest.current.onButton(false); } };
    const hover = (event: PointerEvent) => { renderer.domElement.style.cursor = holding || overButton(event) ? 'pointer' : 'grab'; };
    renderer.domElement.addEventListener('pointerdown', down, { capture: true });
    renderer.domElement.addEventListener('pointerup', up);
    renderer.domElement.addEventListener('pointercancel', up);
    renderer.domElement.addEventListener('lostpointercapture', up);
    renderer.domElement.addEventListener('pointermove', hover);

    const resize = () => {
      const { clientWidth: width, clientHeight: height } = container;
      if (!width || !height) return;
      renderer.setSize(width, height, false);
      renderer.domElement.style.width = '100%';
      renderer.domElement.style.height = '100%';
      camera.aspect = width / height;
      camera.zoom = Math.min(1, camera.aspect / 1.45);
      camera.updateProjectionMatrix();
    };
    const observer = new ResizeObserver(resize);
    observer.observe(container);
    resize();

    handles.current = {
      drawDevice: () => {
        drawOled(oled.ctx, latest.current.visual.lines, latest.current.visual.progress);
        oledMap.needsUpdate = true;
        const progress = latest.current.visual.progress;
        ring.visible = progress > 0;
        if (progress > 0) {
          ring.geometry.dispose();
          ring.geometry = new THREE.RingGeometry(0.27, 0.32, 64, 1, Math.PI / 2, -progress * Math.PI * 2);
        }
      },
      drawPhoneScreen: () => { drawPhone(phoneCanvas.ctx, latest.current.phoneLines); phoneMap.needsUpdate = true; },
      reset: () => { camera.position.copy(home); controls.target.copy(target); controls.update(); },
    };
    handles.current.drawDevice();
    handles.current.drawPhoneScreen();

    const started = performance.now();
    renderer.setAnimationLoop(() => {
      const t = (performance.now() - started) / 1000;
      const state = latest.current;
      if (!reducedMotion) device.position.y = Math.sin(t * 0.9) * 0.05;
      const shellTarget = state.internals ? 0.14 : 1;
      shellMaterial.opacity += (shellTarget - shellMaterial.opacity) * 0.12;
      shellMaterial.depthWrite = shellMaterial.opacity > 0.9;
      internals.visible = shellMaterial.opacity < 0.7;
      const pressDepth = state.pressed ? FRONT + 0.03 : FRONT + 0.07;
      button.position.z += (pressDepth - button.position.z) * 0.35;
      buttonMaterial.emissiveIntensity = state.visual.progress > 0 ? 0.6 + state.visual.progress : 0;
      const color = LED[state.visual.led];
      ledMaterial.color.setHex(color);
      ledMaterial.emissive.setHex(color);
      ledMaterial.emissiveIntensity = state.visual.led === 'amber' && !reducedMotion ? 0.8 + Math.sin(t * 6) * 0.5 : 1.2;
      link.visible = state.transit;
      if (state.transit) (link.material as THREE.LineDashedMaterial).dashSize = 0.12 + (reducedMotion ? 0 : 0.05 * Math.sin(t * 10));
      controls.update();
      renderer.render(scene, camera);
    });

    return () => {
      renderer.setAnimationLoop(null);
      observer.disconnect();
      controls.dispose();
      renderer.domElement.removeEventListener('pointerdown', down, { capture: true });
      renderer.domElement.removeEventListener('pointerup', up);
      renderer.domElement.removeEventListener('pointercancel', up);
      renderer.domElement.removeEventListener('lostpointercapture', up);
      renderer.domElement.removeEventListener('pointermove', hover);
      scene.traverse(object => {
        const item = object as Disposable;
        item.geometry?.dispose();
        (Array.isArray(item.material) ? item.material : item.material ? [item.material] : []).forEach(material => {
          (material as THREE.MeshBasicMaterial).map?.dispose();
          material.dispose();
        });
      });
      renderer.dispose();
      renderer.domElement.remove();
      handles.current = null;
    };
  }, []);

  useEffect(() => { handles.current?.drawDevice(); }, [props.visual.lines, props.visual.progress]);
  useEffect(() => { handles.current?.drawPhoneScreen(); }, [props.phoneLines]);
  useEffect(() => { if (props.resetSignal) handles.current?.reset(); }, [props.resetSignal]);

  return <div className="hardware-canvas" ref={host} role="img" aria-label="Interactive 3D simulation of the EarlyTrace Key beside a phone with a remote screen session"/>;
}

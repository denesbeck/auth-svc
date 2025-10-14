import { useEffect, useRef } from "react";
import * as THREE from "three";

const Layout = ({ children }: { children: React.ReactNode }) => {
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const mouseX = useRef(0); // Track mouse position
  const mouseY = useRef(0);

  useEffect(() => {
    // Set up scene, camera, and renderer
    const scene = new THREE.Scene();

    // Create a perspective camera
    const camera = new THREE.PerspectiveCamera(
      75,
      window.innerWidth / window.innerHeight,
      0.1,
      1000,
    );

    // Create the WebGLRenderer with transparent background
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0); // Set the background to transparent
    if (canvasRef.current) {
      canvasRef.current.appendChild(renderer.domElement);
    }

    // Fixed positions for cubes
    const fixedPositions = [
      // bottom left
      [-80, -50, -19, 25],
      [-40, -30, -19, 12],
      [-50, -20, -9, 8],
      [-10, -35, -9, 18],
      // top right
      [80, 40, -19, 25],
      [35, 30, -19, 12],
      [40, 8, -9, 14],
      [20, 40, -9, 12],
      // bottom right
      [60, -20, -9, 8],
      [60, -40, -9, 14],
      [35, -40, -9, 12],
      // top left
      [-50, 30, -19, 12],
      [-50, 5, -9, 9],
      [-70, 20, -9, 14],
    ];

    // Function to generate fixed cubes
    const generateFixedCube = (
      x: number,
      y: number,
      z: number,
      size: number,
    ) => {
      const geometry = new THREE.BoxGeometry(size, size, size);
      const material = new THREE.MeshBasicMaterial({
        color: 0xd3d3d3, // Light gray color
        wireframe: true,
      });

      const cube = new THREE.Mesh(geometry, material);
      cube.position.set(x, y, z);
      cube.rotation.set(
        Math.random() * Math.PI,
        Math.random() * Math.PI,
        Math.random() * Math.PI,
      );
      scene.add(cube);

      return cube;
    };

    // Create the cubes at fixed positions
    const cubes: THREE.Mesh[] = fixedPositions.map(([x, y, z, s]) =>
      generateFixedCube(x, y, z, s),
    );

    // Position the camera
    camera.position.z = 50;

    // Mouse movement listener to rotate the cubes
    const onMouseMove = (event: MouseEvent) => {
      mouseX.current = (event.clientX / window.innerWidth) * 2 - 1; // Normalize mouseX to range [-1, 1]
      mouseY.current = -(event.clientY / window.innerHeight) * 2 + 1; // Normalize mouseY to range [-1, 1]
    };
    window.addEventListener("mousemove", onMouseMove);

    // Animation loop
    const animate = () => {
      requestAnimationFrame(animate);

      // Default rotation (even without mouse interaction)
      const rotationSpeed = 0.001;
      cubes.forEach((cube) => {
        cube.rotation.x += rotationSpeed + 0.006 * mouseY.current; // Rotate based on mouse Y and default speed
        cube.rotation.y += rotationSpeed + 0.006 * mouseX.current; // Rotate based on mouse X and default speed
      });

      // Render the scene
      renderer.render(scene, camera);
    };

    animate();

    // Resize the renderer when the window size changes
    const onWindowResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };
    window.addEventListener("resize", onWindowResize);

    // Clean up event listeners on component unmount
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("resize", onWindowResize);
      renderer.dispose();
    };
  }, []);

  return (
    <div className="flex flex-col items-center w-screen h-full min-h-screen bg-gradient-to-tr from-cyan-300 via-indigo-500 to-blue-400 sm:justify-center">
      {/* Three.js Canvas */}
      <div
        ref={canvasRef}
        className="overflow-hidden absolute top-0 left-0 z-0 w-screen h-screen"
      />

      {/* Content Layout */}
      <div className="relative top-0 z-10 py-12 px-8 sm:block sm:fixed sm:py-4 sm:px-12 w-[100vw] sm:h-[30vh]">
        <h1 className="flex items-center text-5xl font-extrabold font-[DepartureMono] text-sky-300">
          Auth Service
        </h1>
        <p className="text-lg text-white">
          An authentication platform for software developers.
        </p>
      </div>

      {/* Main Content */}
      <div className="relative z-10">{children}</div>
    </div>
  );
};

export default Layout;

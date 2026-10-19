/**
 * AETHER SHIELD // SUPER GOD MODE
 * Interactive HTML5 Canvas Network Topology Radar
 * Real-time particle flows, glowing orbital rings, and dynamic node interactions.
 */

class NetworkTopologyRadar {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.particles = [];
    this.nodes = [];
    this.animId = null;
    this.hoveredNode = null;
    this.selectedNode = null;

    this.resize();
    window.addEventListener('resize', () => this.resize());

    // Mouse and touch interaction
    this.canvas.addEventListener('mousemove', (e) => this.onMouseMove(e));
    this.canvas.addEventListener('click', (e) => this.onClick(e));

    this.start();
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.width = rect.width || 800;
    this.height = Math.max(380, rect.height || 420);
    this.canvas.width = this.width * window.devicePixelRatio;
    this.canvas.height = this.height * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
  }

  updateNodes(devices, gatewayIp) {
    const centerX = this.width / 2;
    const centerY = this.height / 2;
    const radius = Math.min(centerX, centerY) * 0.72;

    this.nodes = [];

    // Central Gateway Router Node
    this.nodes.push({
      id: 'gateway',
      name: 'Fiber ONT Gateway (SWAR00P)',
      ip: gatewayIp || '192.168.1.1',
      type: 'router',
      x: centerX,
      y: centerY,
      radius: 34,
      isGateway: true,
      isBlocked: false,
      color: '#06b6d4',
      icon: '🌐'
    });

    // Client Nodes in Orbit
    const clientDevices = devices.filter(d => !d.is_gateway && d.ip !== gatewayIp);
    const count = clientDevices.length;
    const angleStep = (Math.PI * 2) / Math.max(1, count);

    clientDevices.forEach((dev, idx) => {
      const angle = idx * angleStep - Math.PI / 2;
      const x = centerX + Math.cos(angle) * radius;
      const y = centerY + Math.sin(angle) * radius;

      const isBlocked = !!dev.is_blocked;
      const isPaused = !!dev.is_paused;
      const isGuest = dev.network_type === 'guest';

      let color = '#38bdf8';
      if (isBlocked) color = '#ef4444';
      else if (isPaused) color = '#f59e0b';
      else if (isGuest) color = '#8b5cf6';

      this.nodes.push({
        id: dev.mac,
        mac: dev.mac,
        name: dev.custom_name || dev.hostname,
        ip: dev.ip,
        type: dev.device_type,
        x: x,
        y: y,
        radius: 24,
        isGateway: false,
        isBlocked: isBlocked,
        isPaused: isPaused,
        isGuest: isGuest,
        color: color,
        icon: this.getIcon(dev.device_type),
        dlKbps: dev.current_dl_kbps || 0,
        ulKbps: dev.current_ul_kbps || 0,
        band: dev.wifi_band || '5 GHz'
      });
    });

    // Spawn packets proportional to traffic
    if (Math.random() < 0.6) {
      this.spawnPackets();
    }
  }

  spawnPackets() {
    const centerNode = this.nodes[0];
    if (!centerNode) return;

    for (let i = 1; i < this.nodes.length; i++) {
      const target = this.nodes[i];
      if (target.isBlocked || target.isPaused) continue;

      // Inbound download packet (Router -> Client)
      this.particles.push({
        fromX: centerNode.x,
        fromY: centerNode.y,
        toX: target.x,
        toY: target.y,
        progress: 0,
        speed: 0.015 + Math.random() * 0.02,
        color: '#06b6d4',
        size: 3.5
      });

      // Outbound upload packet (Client -> Router)
      if (Math.random() < 0.5) {
        this.particles.push({
          fromX: target.x,
          fromY: target.y,
          toX: centerNode.x,
          toY: centerNode.y,
          progress: 0,
          speed: 0.012 + Math.random() * 0.015,
          color: '#8b5cf6',
          size: 2.8
        });
      }
    }
  }

  getIcon(type) {
    switch (type) {
      case 'phone': return '📱';
      case 'laptop':
      case 'pc': return '💻';
      case 'tablet': return '📟';
      case 'smart_tv': return '📺';
      case 'console': return '🎮';
      case 'router': return '🌐';
      case 'iot': return '💡';
      default: return '📱';
    }
  }

  onMouseMove(e) {
    const rect = this.canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    this.hoveredNode = null;
    for (const node of this.nodes) {
      const dist = Math.hypot(node.x - mouseX, node.y - mouseY);
      if (dist <= node.radius + 6) {
        this.hoveredNode = node;
        this.canvas.style.cursor = 'pointer';
        return;
      }
    }
    this.canvas.style.cursor = 'default';
  }

  onClick(e) {
    if (this.hoveredNode && !this.hoveredNode.isGateway) {
      if (window.openDeviceModal) {
        window.openDeviceModal(this.hoveredNode.mac);
      }
    }
  }

  draw() {
    this.ctx.clearRect(0, 0, this.width, this.height);
    const time = Date.now() * 0.002;
    const centerNode = this.nodes[0];

    // 1. Draw Radar Background Grid & Orbital Rings
    if (centerNode) {
      this.ctx.save();
      for (let r = 80; r <= 240; r += 70) {
        this.ctx.beginPath();
        this.ctx.arc(centerNode.x, centerNode.y, r, 0, Math.PI * 2);
        this.ctx.strokeStyle = 'rgba(6, 182, 212, 0.08)';
        this.ctx.lineWidth = 1;
        this.ctx.setLineDash([4, 6]);
        this.ctx.stroke();
      }

      // Rotating Radar Sweeper Line
      this.ctx.beginPath();
      this.ctx.moveTo(centerNode.x, centerNode.y);
      const sweepX = centerNode.x + Math.cos(time * 0.8) * 250;
      const sweepY = centerNode.y + Math.sin(time * 0.8) * 250;
      this.ctx.lineTo(sweepX, sweepY);
      this.ctx.strokeStyle = 'rgba(6, 182, 212, 0.18)';
      this.ctx.lineWidth = 1.5;
      this.ctx.setLineDash([]);
      this.ctx.stroke();
      this.ctx.restore();
    }

    // 2. Draw Connection Links between Gateway and Clients
    if (centerNode) {
      for (let i = 1; i < this.nodes.length; i++) {
        const node = this.nodes[i];
        this.ctx.beginPath();
        this.ctx.moveTo(centerNode.x, centerNode.y);
        this.ctx.lineTo(node.x, node.y);

        if (node.isBlocked) {
          this.ctx.strokeStyle = 'rgba(239, 68, 68, 0.35)';
          this.ctx.lineWidth = 2;
          this.ctx.setLineDash([6, 6]);
        } else if (node.isGuest) {
          this.ctx.strokeStyle = 'rgba(139, 92, 246, 0.3)';
          this.ctx.lineWidth = 1.8;
          this.ctx.setLineDash([]);
        } else {
          this.ctx.strokeStyle = 'rgba(6, 182, 212, 0.25)';
          this.ctx.lineWidth = 1.8;
          this.ctx.setLineDash([]);
        }
        this.ctx.stroke();
      }
    }

    // 3. Update & Draw Live Flying Packet Particles
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.progress += p.speed;
      if (p.progress >= 1) {
        this.particles.splice(i, 1);
        continue;
      }
      const curX = p.fromX + (p.toX - p.fromX) * p.progress;
      const curY = p.fromY + (p.toY - p.fromY) * p.progress;

      this.ctx.beginPath();
      this.ctx.arc(curX, curY, p.size, 0, Math.PI * 2);
      this.ctx.fillStyle = p.color;
      this.ctx.shadowColor = p.color;
      this.ctx.shadowBlur = 10;
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
    }

    // 4. Draw Nodes
    for (const node of this.nodes) {
      const isHovered = this.hoveredNode === node;
      const pulse = Math.sin(time * 3) * 2;

      // Glow backdrop
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius + (isHovered ? 6 : 0) + pulse, 0, Math.PI * 2);
      this.ctx.fillStyle = node.isBlocked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(6, 182, 212, 0.1)';
      this.ctx.fill();

      // Node Body Circle
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius + (isHovered ? 4 : 0), 0, Math.PI * 2);
      this.ctx.fillStyle = node.isGateway ? '#0f172a' : '#090d16';
      this.ctx.strokeStyle = node.color;
      this.ctx.lineWidth = node.isGateway ? 3 : 2;
      this.ctx.shadowColor = node.color;
      this.ctx.shadowBlur = isHovered ? 20 : 10;
      this.ctx.stroke();
      this.ctx.fill();
      this.ctx.shadowBlur = 0;

      // Icon
      this.ctx.font = `${node.isGateway ? '20px' : '15px'} Arial`;
      this.ctx.textAlign = 'center';
      this.ctx.textBaseline = 'middle';
      this.ctx.fillText(node.icon, node.x, node.y);

      // Label below node
      this.ctx.font = '600 11px Inter';
      this.ctx.fillStyle = node.isBlocked ? '#f87171' : '#f1f5f9';
      this.ctx.fillText(node.name, node.x, node.y + node.radius + 14);

      this.ctx.font = '500 10px "JetBrains Mono"';
      this.ctx.fillStyle = '#64748b';
      this.ctx.fillText(node.ip, node.x, node.y + node.radius + 26);
    }
  }

  start() {
    const loop = () => {
      this.draw();
      this.animId = requestAnimationFrame(loop);
    };
    loop();
  }

  stop() {
    if (this.animId) cancelAnimationFrame(this.animId);
  }
}

window.NetworkTopologyRadar = NetworkTopologyRadar;

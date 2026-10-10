/* CIMI 3D globe. A dependency-free orthographic globe drawn on <canvas>:
   dotted continents, a graticule, country markers and great-circle arcs that
   run from each source country to India. Drag to spin. Colours come from
   the theme's CSS variables, so it follows light and dark mode.

   Performance: the loop pauses when the globe is off screen, when the tab is
   hidden, and stops for good once the canvas leaves the page. With "reduce
   motion" switched on it draws still frames and only moves when dragged. */
(function (global) {
  'use strict';

  // Rough continent outlines as [lon, lat] rings. Only used to decide which
  // dots are land, so a few dozen vertices per continent is plenty.
  var LAND = [
    [[-168,66],[-162,70],[-140,70],[-120,72],[-95,72],[-80,73],[-65,62],[-56,52],[-66,45],[-70,42],[-76,35],[-81,31],[-80,25],[-83,29],[-90,29],[-97,26],[-97,21],[-92,18],[-87,21],[-83,15],[-77,8],[-80,7],[-86,12],[-92,14],[-105,20],[-110,24],[-114,31],[-118,34],[-124,40],[-124,48],[-132,55],[-140,60],[-152,58],[-165,60]],
    [[-55,60],[-45,60],[-20,70],[-18,80],[-35,83],[-60,82],[-70,77],[-58,70]],
    [[-80,8],[-72,12],[-60,10],[-50,0],[-35,-5],[-35,-10],[-40,-22],[-48,-28],[-58,-38],[-65,-42],[-68,-52],[-74,-52],[-73,-40],[-71,-30],[-70,-18],[-76,-14],[-81,-5],[-80,0]],
    [[-10,36],[-9,43],[-2,44],[-5,48],[-1,50],[5,53],[8,57],[5,62],[12,66],[20,70],[30,71],[40,68],[45,60],[40,48],[30,45],[28,41],[22,37],[15,40],[12,44],[8,44],[3,42],[-5,36]],
    [[-6,50],[2,51],[0,54],[-3,58],[-6,57]],
    [[-17,15],[-17,21],[-10,30],[-6,36],[10,37],[20,32],[32,31],[35,28],[43,12],[51,12],[42,-2],[40,-10],[35,-22],[32,-28],[20,-35],[17,-30],[12,-17],[9,-1],[5,5],[-8,5],[-14,10]],
    [[35,28],[36,34],[48,30],[56,26],[59,22],[52,16],[43,12]],
    [[28,41],[40,42],[48,42],[52,37],[58,26],[62,25],[67,24],[70,21],[73,18],[77,8],[80,13],[80,16],[87,22],[92,22],[94,17],[98,10],[100,4],[104,1],[103,10],[106,10],[109,13],[108,20],[110,21],[117,24],[121,30],[122,37],[119,40],[126,38],[129,35],[130,42],[135,44],[141,52],[137,55],[143,60],[160,62],[170,65],[180,66],[180,72],[150,72],[130,73],[110,77],[90,76],[70,73],[60,70],[45,68],[40,68],[45,60],[40,48],[30,45]],
    [[130,31],[136,34],[140,36],[142,41],[141,45],[145,44],[140,40],[135,35]],
    [[95,5],[105,-6],[115,-8],[120,-9],[125,-8],[119,-4],[118,1],[116,7],[110,2],[104,-2],[98,2]],
    [[114,-22],[122,-18],[130,-12],[137,-12],[142,-11],[146,-19],[153,-28],[150,-37],[141,-38],[135,-35],[129,-32],[115,-34]],
  ];

  // Approximate locations used for markers (capital or population centre).
  var PLACES = {
    IN: [21.15, 79.09], CN: [35, 104], RU: [55.75, 37.6], US: [39, -98], NL: [52.3, 5.3],
    BR: [-14, -51], VN: [16, 107], PK: [30, 70], DE: [51, 10], SG: [1.35, 103.8],
    GB: [54, -2], FR: [46.6, 2.4], JP: [36, 138], KR: [36, 128], TR: [39, 35],
    IR: [32, 53], UA: [49, 32], ID: [-2, 118], BD: [23.7, 90.4], LK: [7.9, 80.8],
  };
  var HOME = PLACES.IN; // Nagpur: every arc ends here.
  var RAD = Math.PI / 180;

  function insideRing(lon, lat, ring) {
    var inside = false;
    for (var i = 0, j = ring.length - 1; i < ring.length; j = i++) {
      var xi = ring[i][0], yi = ring[i][1], xj = ring[j][0], yj = ring[j][1];
      if (((yi > lat) !== (yj > lat)) && (lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi)) inside = !inside;
    }
    return inside;
  }

  // Fibonacci-sphere sample, kept only where it falls on land. Built once.
  var landDots = null;
  function getLandDots() {
    if (landDots) return landDots;
    landDots = [];
    var n = 5200, golden = Math.PI * (3 - Math.sqrt(5));
    for (var i = 0; i < n; i += 1) {
      var y = 1 - (i / (n - 1)) * 2;
      var lat = Math.asin(y) / RAD;
      var lon = ((((i * golden) / RAD) % 360) + 360) % 360 - 180;
      for (var r = 0; r < LAND.length; r += 1) {
        if (insideRing(lon, lat, LAND[r])) { landDots.push(toVec(lat, lon)); break; }
      }
    }
    return landDots;
  }

  function toVec(lat, lon) {
    var la = lat * RAD, lo = lon * RAD;
    return [Math.cos(la) * Math.sin(lo), Math.sin(la), Math.cos(la) * Math.cos(lo)];
  }

  function slerp(a, b, t) {
    var dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    var omega = Math.acos(dot);
    if (omega < 1e-6) return a.slice();
    var s = Math.sin(omega), k1 = Math.sin((1 - t) * omega) / s, k2 = Math.sin(t * omega) / s;
    return [a[0] * k1 + b[0] * k2, a[1] * k1 + b[1] * k2, a[2] * k1 + b[2] * k2];
  }

  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function readColors() {
    return {
      dot: cssVar('--globe-dot', 'rgba(255,255,255,.22)'),
      grid: cssVar('--globe-grid', 'rgba(255,255,255,.07)'),
      rim: cssVar('--globe-rim', 'rgba(255,255,255,.18)'),
      red: cssVar('--chart-malicious', '#ff4552'),
      amber: cssVar('--chart-suspicious', '#f5a623'),
      neutral: cssVar('--chart-clean', '#d9d9d9'),
    };
  }

  var reduceMotion = global.matchMedia && global.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /**
   * mount(container, { points: [{ code, value, malicious, suspicious }], label })
   * Returns { update(points), destroy() }.
   */
  function mount(container, options) {
    options = options || {};
    var canvas = document.createElement('canvas');
    canvas.className = 'globe';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', options.label || 'Rotating globe');
    container.appendChild(canvas);
    var ctx = canvas.getContext('2d');

    var state = {
      lon0: HOME[1] - 25, // start with India just right of centre
      lat0: 18,
      points: [],
      colors: readColors(),
      dragging: false,
      lastInteraction: 0,
      visible: true,
      raf: 0,
      start: performance.now(),
      size: 0,
      dpr: 1,
    };

    function setPoints(points) {
      state.points = (points || []).filter(function (p) { return PLACES[p.code] && p.code !== 'IN'; }).map(function (p, i) {
        var max = Math.max.apply(null, points.map(function (q) { return q.value || 1; }));
        return {
          vec: toVec(PLACES[p.code][0], PLACES[p.code][1]),
          weight: Math.max(0.25, (p.value || 1) / (max || 1)),
          color: p.malicious ? 'red' : p.suspicious ? 'amber' : 'neutral',
          phase: (i * 0.137) % 1,
        };
      });
      draw(performance.now());
    }

    function resize() {
      var rect = container.getBoundingClientRect();
      var size = Math.max(80, Math.min(rect.width, rect.height || rect.width));
      state.dpr = Math.min(global.devicePixelRatio || 1, 2);
      state.size = size;
      canvas.width = Math.round(size * state.dpr);
      canvas.height = Math.round(size * state.dpr);
      canvas.style.width = size + 'px';
      canvas.style.height = size + 'px';
      draw(performance.now());
    }

    // Rotate a unit vector into view space: spin around the polar axis, then tilt.
    function project(v, cosA, sinA, cosT, sinT) {
      var x = v[0] * cosA + v[2] * sinA;
      var z1 = -v[0] * sinA + v[2] * cosA;
      var y = v[1] * cosT - z1 * sinT;
      var z = v[1] * sinT + z1 * cosT;
      return [x, y, z];
    }

    function draw(now) {
      if (!state.size) return;
      var c = state.colors;
      var s = state.size * state.dpr;
      var R = s * 0.44, cx = s / 2, cy = s / 2;
      var a = -state.lon0 * RAD, t = state.lat0 * RAD;
      var cosA = Math.cos(a), sinA = Math.sin(a), cosT = Math.cos(t), sinT = Math.sin(t);
      var time = (now - state.start) / 1000;
      ctx.clearRect(0, 0, s, s);

      // rim
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.strokeStyle = c.rim;
      ctx.lineWidth = 1 * state.dpr;
      ctx.stroke();

      // graticule every 30 degrees, front side only
      ctx.strokeStyle = c.grid;
      ctx.lineWidth = 1 * state.dpr;
      var lat, lon, k, p, started;
      for (lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath(); started = false;
        for (lon = -180; lon <= 180; lon += 4) {
          p = project(toVec(lat, lon), cosA, sinA, cosT, sinT);
          if (p[2] > 0) { if (started) ctx.lineTo(cx + p[0] * R, cy - p[1] * R); else { ctx.moveTo(cx + p[0] * R, cy - p[1] * R); started = true; } } else started = false;
        }
        ctx.stroke();
      }
      for (lon = -180; lon < 180; lon += 30) {
        ctx.beginPath(); started = false;
        for (lat = -88; lat <= 88; lat += 4) {
          p = project(toVec(lat, lon), cosA, sinA, cosT, sinT);
          if (p[2] > 0) { if (started) ctx.lineTo(cx + p[0] * R, cy - p[1] * R); else { ctx.moveTo(cx + p[0] * R, cy - p[1] * R); started = true; } } else started = false;
        }
        ctx.stroke();
      }

      // land dots, fading toward the limb for depth
      var dots = getLandDots();
      ctx.fillStyle = c.dot;
      var d = Math.max(1, 1.6 * state.dpr);
      for (k = 0; k < dots.length; k += 1) {
        p = project(dots[k], cosA, sinA, cosT, sinT);
        if (p[2] <= 0) continue;
        ctx.globalAlpha = 0.35 + 0.65 * p[2];
        ctx.fillRect(cx + p[0] * R - d / 2, cy - p[1] * R - d / 2, d, d);
      }
      ctx.globalAlpha = 1;

      // arcs from each source country to India, lifted off the surface
      var home = toVec(HOME[0], HOME[1]);
      state.points.forEach(function (pt) {
        var col = c[pt.color];
        var steps = 48, prev = null, travel = reduceMotion ? 0.5 : (time * 0.35 + pt.phase) % 1;
        ctx.strokeStyle = col;
        ctx.lineWidth = (0.8 + pt.weight * 1.4) * state.dpr;
        for (var i = 0; i <= steps; i += 1) {
          var f = i / steps;
          var v = slerp(pt.vec, home, f);
          var lift = 1 + 0.22 * Math.sin(Math.PI * f);
          var q = project([v[0] * lift, v[1] * lift, v[2] * lift], cosA, sinA, cosT, sinT);
          var shown = q[2] > 0 || (q[0] * q[0] + q[1] * q[1]) > 1;
          var xy = [cx + q[0] * R, cy - q[1] * R];
          if (prev && shown && prev.shown) {
            ctx.globalAlpha = 0.25 + 0.55 * Math.max(0, 1 - Math.abs(f - travel) * 3);
            ctx.beginPath(); ctx.moveTo(prev.xy[0], prev.xy[1]); ctx.lineTo(xy[0], xy[1]); ctx.stroke();
          }
          prev = { xy: xy, shown: shown };
        }
        ctx.globalAlpha = 1;

        // source marker with a slow pulse
        var m = project(pt.vec, cosA, sinA, cosT, sinT);
        if (m[2] > 0) {
          var mx = cx + m[0] * R, my = cy - m[1] * R, r0 = (2 + pt.weight * 2.5) * state.dpr;
          ctx.fillStyle = col;
          ctx.beginPath(); ctx.arc(mx, my, r0, 0, Math.PI * 2); ctx.fill();
          if (!reduceMotion) {
            var pulse = (time * 0.6 + pt.phase) % 1;
            ctx.globalAlpha = 1 - pulse;
            ctx.strokeStyle = col;
            ctx.lineWidth = 1 * state.dpr;
            ctx.beginPath(); ctx.arc(mx, my, r0 + pulse * 10 * state.dpr, 0, Math.PI * 2); ctx.stroke();
            ctx.globalAlpha = 1;
          }
        }
      });

      // India marker
      var h = project(home, cosA, sinA, cosT, sinT);
      if (h[2] > 0) {
        var hx = cx + h[0] * R, hy = cy - h[1] * R;
        ctx.strokeStyle = c.red;
        ctx.lineWidth = 1.5 * state.dpr;
        ctx.beginPath(); ctx.arc(hx, hy, 5 * state.dpr, 0, Math.PI * 2); ctx.stroke();
        ctx.fillStyle = c.red;
        ctx.beginPath(); ctx.arc(hx, hy, 2 * state.dpr, 0, Math.PI * 2); ctx.fill();
      }
    }

    function loop(now) {
      state.raf = 0;
      if (!canvas.isConnected) return destroy();
      if (!state.dragging && now - state.lastInteraction > 2500) state.lon0 += 0.06; // gentle spin
      draw(now);
      schedule();
    }

    function schedule() {
      if (reduceMotion || state.raf || !state.visible || document.hidden) return;
      state.raf = requestAnimationFrame(loop);
    }

    // drag to spin
    var last = null;
    function onDown(e) {
      state.dragging = true;
      last = [e.clientX, e.clientY];
      canvas.setPointerCapture && canvas.setPointerCapture(e.pointerId);
    }
    function onMove(e) {
      if (!state.dragging || !last) return;
      state.lon0 -= (e.clientX - last[0]) * 0.4;
      state.lat0 = Math.max(-60, Math.min(70, state.lat0 + (e.clientY - last[1]) * 0.3));
      last = [e.clientX, e.clientY];
      state.lastInteraction = performance.now();
      if (reduceMotion) draw(performance.now());
    }
    function onUp() { state.dragging = false; last = null; state.lastInteraction = performance.now(); }
    canvas.addEventListener('pointerdown', onDown);
    canvas.addEventListener('pointermove', onMove);
    canvas.addEventListener('pointerup', onUp);
    canvas.addEventListener('pointercancel', onUp);

    var ro = global.ResizeObserver ? new ResizeObserver(resize) : null;
    if (ro) ro.observe(container); else global.addEventListener('resize', resize);
    var io = global.IntersectionObserver ? new IntersectionObserver(function (entries) {
      state.visible = entries[0].isIntersecting;
      schedule();
    }) : null;
    if (io) io.observe(canvas);
    function onVisibility() { schedule(); }
    function onTheme() { state.colors = readColors(); draw(performance.now()); }
    document.addEventListener('visibilitychange', onVisibility);
    global.addEventListener('cimi:theme', onTheme);

    function destroy() {
      if (state.raf) cancelAnimationFrame(state.raf);
      state.raf = 0;
      if (ro) ro.disconnect();
      if (io) io.disconnect();
      document.removeEventListener('visibilitychange', onVisibility);
      global.removeEventListener('cimi:theme', onTheme);
    }

    setPoints(options.points);
    resize();
    schedule();
    return { update: setPoints, destroy: destroy };
  }

  global.CimiGlobe = { mount: mount, places: PLACES };
})(window);

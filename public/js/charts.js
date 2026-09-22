/* CIMI — dependency-free SVG chart primitives.
   Every chart is plain SVG built in the browser: no chart library, no CDN,
   works offline, and scales with the container. */
(function (global) {
  'use strict';

  var PALETTE = {
    malicious: '#f87171',
    suspicious: '#fbbf24',
    clean: '#34d399',
    unknown: '#94a3b8',
    accent: '#5eead4',
    grid: 'rgba(255,255,255,0.07)',
    axis: '#64748b',
  };

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function svgWrap(width, height, inner, label) {
    return '<svg viewBox="0 0 ' + width + ' ' + height + '" class="w-full h-full" ' +
      'preserveAspectRatio="none" role="img" aria-label="' + esc(label || 'chart') + '">' + inner + '</svg>';
  }

  /** Stacked area / line trend chart for daily verdict counts. */
  function trendChart(series, options) {
    options = options || {};
    var width = 720, height = 220, padL = 34, padR = 12, padT = 14, padB = 26;
    if (!series || !series.length) return emptyState('No lookup activity yet');

    var keys = options.keys || ['malicious', 'suspicious', 'clean'];
    var max = 1;
    series.forEach(function (d) {
      var sum = keys.reduce(function (acc, k) { return acc + (d[k] || 0); }, 0);
      if (sum > max) max = sum;
    });
    max = Math.ceil(max * 1.15);

    var innerW = width - padL - padR;
    var innerH = height - padT - padB;
    var stepX = series.length > 1 ? innerW / (series.length - 1) : innerW;

    function x(i) { return padL + i * stepX; }
    function y(v) { return padT + innerH - (v / max) * innerH; }

    var parts = [];

    // grid + y labels
    for (var g = 0; g <= 4; g += 1) {
      var value = Math.round((max / 4) * g);
      var yy = y(value);
      parts.push('<line x1="' + padL + '" y1="' + yy + '" x2="' + (width - padR) + '" y2="' + yy +
        '" stroke="' + PALETTE.grid + '" stroke-width="1"/>');
      parts.push('<text x="' + (padL - 7) + '" y="' + (yy + 3.5) + '" text-anchor="end" font-size="9" fill="' +
        PALETTE.axis + '">' + value + '</text>');
    }

    // stacked areas (bottom-up)
    var baseline = series.map(function () { return 0; });
    keys.slice().reverse().forEach(function (key) {
      var top = series.map(function (d, i) { return baseline[i] + (d[key] || 0); });
      var up = top.map(function (v, i) { return x(i) + ',' + y(v); }).join(' ');
      var down = baseline.map(function (v, i) { return x(i) + ',' + y(v); }).reverse().join(' ');
      parts.push('<polygon points="' + up + ' ' + down + '" fill="' + PALETTE[key] + '" fill-opacity="0.22"/>');
      parts.push('<polyline points="' + up + '" fill="none" stroke="' + PALETTE[key] +
        '" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"/>');
      baseline = top;
    });

    // x labels (first, middle, last)
    [0, Math.floor(series.length / 2), series.length - 1].forEach(function (i, n, arr) {
      if (arr.indexOf(i) !== n) return;
      var d = series[i];
      if (!d) return;
      parts.push('<text x="' + x(i) + '" y="' + (height - 8) + '" text-anchor="' +
        (i === 0 ? 'start' : i === series.length - 1 ? 'end' : 'middle') +
        '" font-size="9" fill="' + PALETTE.axis + '">' + esc(String(d.date).slice(5)) + '</text>');
    });

    return svgWrap(width, height, parts.join(''), 'Daily verdict trend');
  }

  /** Donut chart for the verdict split. */
  function donutChart(segments, options) {
    options = options || {};
    var size = 180, cx = size / 2, cy = size / 2, r = 66, thickness = 22;
    var total = segments.reduce(function (acc, s) { return acc + s.value; }, 0);
    if (!total) return emptyState('No data yet');

    var parts = [];
    var angle = -Math.PI / 2;

    segments.forEach(function (seg) {
      if (!seg.value) return;
      var slice = (seg.value / total) * Math.PI * 2;
      var end = angle + slice;
      var large = slice > Math.PI ? 1 : 0;
      var x1 = cx + r * Math.cos(angle), y1 = cy + r * Math.sin(angle);
      var x2 = cx + r * Math.cos(end), y2 = cy + r * Math.sin(end);
      parts.push('<path d="M ' + x1 + ' ' + y1 + ' A ' + r + ' ' + r + ' 0 ' + large + ' 1 ' + x2 + ' ' + y2 +
        '" fill="none" stroke="' + (seg.color || PALETTE.unknown) + '" stroke-width="' + thickness +
        '" stroke-linecap="butt"><title>' + esc(seg.label + ': ' + seg.value) + '</title></path>');
      angle = end;
    });

    parts.push('<text x="' + cx + '" y="' + (cy - 2) + '" text-anchor="middle" font-size="26" font-weight="600" fill="#f1f5f9">' + total + '</text>');
    parts.push('<text x="' + cx + '" y="' + (cy + 16) + '" text-anchor="middle" font-size="10" fill="' + PALETTE.axis + '">' +
      esc(options.caption || 'lookups') + '</text>');

    return '<svg viewBox="0 0 ' + size + ' ' + size + '" class="h-44 w-44" role="img" aria-label="Verdict distribution">' +
      parts.join('') + '</svg>';
  }

  /** Horizontal bar list (geography, techniques, tags). */
  function barList(items, options) {
    options = options || {};
    if (!items || !items.length) return emptyState(options.empty || 'No data yet');
    var max = Math.max.apply(null, items.map(function (i) { return i.value; })) || 1;

    return '<div class="space-y-2.5">' + items.map(function (item) {
      var pct = Math.max(3, Math.round((item.value / max) * 100));
      return '<div>' +
        '<div class="flex items-baseline justify-between gap-2 mb-1">' +
          '<span class="text-[11px] text-slate-300 truncate">' + esc(item.label) + '</span>' +
          '<span class="text-[11px] font-medium text-slate-400 tabular-nums">' + esc(item.value) +
            (item.suffix ? '<span class="text-slate-600"> ' + esc(item.suffix) + '</span>' : '') + '</span>' +
        '</div>' +
        '<div class="scorebar"><span style="width:' + pct + '%;background:' + (item.color || PALETTE.accent) + '"></span></div>' +
      '</div>';
    }).join('') + '</div>';
  }

  /** Sparkline for the reputation timeline. */
  function sparkline(points, options) {
    options = options || {};
    if (!points || points.length < 2) return emptyState('No timeline');
    var width = 420, height = 90, pad = 8;
    var values = points.map(function (p) { return p.score; });
    var max = Math.max.apply(null, values.concat([10]));
    var stepX = (width - pad * 2) / (points.length - 1);

    var coords = points.map(function (p, i) {
      var x = pad + i * stepX;
      var y = pad + (height - pad * 2) * (1 - p.score / max);
      return x + ',' + y;
    });

    var color = options.color || PALETTE.accent;
    var area = coords.join(' ') + ' ' + (width - pad) + ',' + (height - pad) + ' ' + pad + ',' + (height - pad);

    return svgWrap(width, height,
      '<polygon points="' + area + '" fill="' + color + '" fill-opacity="0.16"/>' +
      '<polyline points="' + coords.join(' ') + '" fill="none" stroke="' + color +
        '" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>' +
      '<circle cx="' + (pad + (points.length - 1) * stepX) + '" cy="' +
        (pad + (height - pad * 2) * (1 - points[points.length - 1].score / max)) +
        '" r="3.5" fill="' + color + '"/>',
      'Reputation timeline');
  }

  /**
   * Relationship network — deterministic radial layout, clusters placed on
   * concentric arcs so the picture is stable between renders.
   */
  function networkGraph(nodes, edges, options) {
    options = options || {};
    if (!nodes || !nodes.length) return emptyState('Run a correlation to see the network');

    var width = 720, height = 420, cx = width / 2, cy = height / 2;
    var positions = {};

    // Group nodes by cluster membership if provided, else a single ring.
    var groups = options.clusters && options.clusters.length
      ? options.clusters.map(function (c) { return c.members; })
      : [nodes.map(function (n) { return n.id; })];

    // One cluster fills the canvas; several clusters sit on concentric rings.
    var maxRadius = (height / 2) - 46;
    var ringStep = groups.length > 1 ? maxRadius / groups.length : maxRadius;

    groups.forEach(function (members, gi) {
      var radius = groups.length === 1 ? maxRadius * 0.86 : ringStep * (gi + 1) * 0.9;
      members.forEach(function (id, i) {
        // Offset each ring so labels on adjacent rings do not stack up.
        var angle = (i / Math.max(members.length, 1)) * Math.PI * 2 + gi * 0.7 - Math.PI / 2;
        positions[id] = {
          x: cx + radius * Math.cos(angle) * 1.55,
          y: cy + radius * Math.sin(angle),
        };
      });
    });

    var parts = [];

    edges.forEach(function (e) {
      var a = positions[e.source], b = positions[e.target];
      if (!a || !b) return;
      parts.push('<line x1="' + a.x.toFixed(1) + '" y1="' + a.y.toFixed(1) + '" x2="' + b.x.toFixed(1) +
        '" y2="' + b.y.toFixed(1) + '" stroke="' + PALETTE.accent + '" stroke-opacity="' +
        Math.min(0.75, 0.2 + e.weight).toFixed(2) + '" stroke-width="' +
        (1 + e.weight * 3).toFixed(2) + '"><title>' + esc(e.shared.join(', ')) + '</title></line>');
    });

    nodes.forEach(function (n) {
      var p = positions[n.id];
      if (!p) return;
      var color = PALETTE[n.verdict] || PALETTE.unknown;
      var r = 7 + (n.score || 0) / 14;
      parts.push('<g><circle cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="' + r.toFixed(1) +
        '" fill="' + color + '" fill-opacity="0.85" stroke="#0c111b" stroke-width="2"><title>' +
        esc(n.id + ' — ' + n.verdict + ' (' + n.score + '/100)') + '</title></circle>' +
        '<text x="' + p.x.toFixed(1) + '" y="' + (p.y + r + 11).toFixed(1) + '" text-anchor="middle" font-size="9" fill="#94a3b8">' +
        esc(n.id.length > 22 ? n.id.slice(0, 20) + '…' : n.id) + '</text></g>');
    });

    return '<svg viewBox="0 0 ' + width + ' ' + height + '" class="w-full" style="max-height:460px" role="img" aria-label="Indicator relationship network">' +
      parts.join('') + '</svg>';
  }

  function emptyState(message) {
    return '<div class="flex-center h-full min-h-[120px] text-xs text-slate-600 text-center px-4">' + esc(message) + '</div>';
  }

  global.CimiCharts = {
    PALETTE: PALETTE,
    trendChart: trendChart,
    donutChart: donutChart,
    barList: barList,
    sparkline: sparkline,
    networkGraph: networkGraph,
    emptyState: emptyState,
    esc: esc,
  };
})(window);

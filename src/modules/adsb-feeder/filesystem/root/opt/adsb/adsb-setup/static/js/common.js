"use strict";

function formatPosition(lat, lon) {
  if (!typeof lat == "number" || !typeof lon == "number") return "unknown"
  const latCardinal = lat > 0 ? "N" : "S";
  const lonCardinal = lon > 0 ? "E" : "W";
  return `${lat.toFixed(3)}° ${latCardinal} ${lon.toFixed(3)}° ${lonCardinal}`;
}

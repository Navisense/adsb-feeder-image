"use strict";

function formatPosition(lat, lon) {
  if (!typeof lat == "number" || !typeof lon == "number") return "unknown"
  const latCardinal = lat > 0 ? "N" : "S";
  const lonCardinal = lon > 0 ? "E" : "W";
  return `${lat.toFixed(3)}° ${latCardinal} ${lon.toFixed(3)}° ${lonCardinal}`;
}

function makeNotificationCardHtml(kind, title, message) {
  let kindClass = "text-bg-info";
  if (kind == "error") {
    kindClass = "text-bg-danger";
  }
  return `
    <div class="col-12">
      <div class="card ${kindClass} m-3">
        <div class="card-body">
          <h5 class="card-title">${title}</h5>
          <p class="card-text">${message}</p>
        </div>
      </div>
    </div>`;
}

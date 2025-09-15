"use strict";

/**
 * Utility to check whether the feeder is reachable.
 */
class FeederConnectivityChecker {
  constructor(
    domains,
    onStatusUpdate,
    checkTimeout = 300 * 1000,
    recheckIntervals = [[1000, 200], [3000, 500], [Infinity, 3000]],
  ) {
    this.stati = new Map(domains.map((d) => [d, null]));
    this.onStatusUpdate = onStatusUpdate;
    this.checkTimeout = checkTimeout;
    this.recheckIntervals = recheckIntervals;
    this.checkStart = Date.now();
    this.hasTimedOut = false;
  }

  start() {
    this.checkStart = Date.now();
    this.sendCheckRequests();
  }

  sendCheckRequests() {
    let checkAgain = false;
    for (const [domain, previousStatus] of this.stati.entries()) {
      if (previousStatus == "success") {
        continue;
      }
      checkAgain = true;
      let req = new XMLHttpRequest();
      req.timeout = 1000;
      req.onload = this.maybeUpdateStatus(domain, previousStatus, "success");
      req.onerror = this.maybeUpdateStatus(domain, previousStatus, "error");
      req.ontimeout = this.maybeUpdateStatus(domain, previousStatus, "timeout");
      req.open("GET", `http://${domain}/healthz`);
      req.send();
    }
    let recheckInterval = 1000;
    const timeSinceStart = Date.now() - this.checkStart;
    for (const [threshold, interval] of this.recheckIntervals) {
      if (timeSinceStart <= threshold) {
        recheckInterval = interval;
        break;
      }
    }
    if (!this.hasTimedOut && checkAgain) {
      setTimeout(this.sendCheckRequests.bind(this), recheckInterval);
    }
  }

  maybeUpdateStatus(domain, previousStatus, status) {
    return (_) => {
      this.stati.set(domain, status);
      this.hasTimedOut = Date.now() > this.checkStart + this.checkTimeout;
      if (this.hasTimedOut || status != previousStatus) {
        this.onStatusUpdate(this.stati, this.hasTimedOut);
      }
    };
  }
}

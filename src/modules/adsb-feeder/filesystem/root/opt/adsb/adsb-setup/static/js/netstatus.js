"use strict";

/**
 * Utility to check whether the feeder is reachable.
 */
class FeederConnectivityChecker {
  constructor(
    domains,
    onStatusUpdate,
    checkTimeout = 300 * 1000,
    recheckInterval = 3000
  ) {
    this.stati = new Map(domains.map((d) => [d, null]));
    this.onStatusUpdate = onStatusUpdate;
    this.checkTimeout = checkTimeout;
    this.recheckInterval = recheckInterval;
    this.checkUntil = Date.now();
    this.hasTimedOut = false;
  }

  start() {
    this.checkUntil = Date.now() + this.checkTimeout;
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
    if (!this.hasTimedOut && checkAgain) {
      setTimeout(this.sendCheckRequests.bind(this), this.recheckInterval);
    }
  }

  maybeUpdateStatus(domain, previousStatus, status) {
    return (_) => {
      this.stati[domain] = status;
      this.hasTimedOut = Date.now() > this.checkUntil;
      if (this.hasTimedOut || status != previousStatus) {
        this.onStatusUpdate(this.stati, this.hasTimedOut);
      }
    };
  }
}
